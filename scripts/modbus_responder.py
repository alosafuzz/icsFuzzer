#!/usr/bin/env python3
"""Modbus TCP software responder for testing icsFuzzer without hardware.

Writes a structured sidecar JSONL alongside the fuzzer's own JSONL so that
every responder decision (why a connection was closed, what exception was
returned) can be correlated against the fuzzer's crash indicators. This is
the baseline calibration step: know what "expected" behaviour looks like
before calling a finding on real hardware.

Response logic:
  - Assigned public FCs (01-06, 0F, 10, 16, 17, 2B, etc.) → exception 0x02
  - Unrecognised / user-defined / reserved FCs → exception 0x01
  - FC05 write single coil to address 0x0001 with 0xFF00 or 0x0000 → success echo
  - Bad protocol ID in MBAP → close (action: close_bad_proto_id)
  - PDU length > 260 → close (action: close_oversized_pdu)
  - Truncated header (<7 bytes received) → close (action: close_truncated_header)
  - Truncated PDU (fewer bytes than declared) → close (action: close_truncated_pdu)
  - Empty PDU (pdu_len=0) → close (action: close_empty_pdu)
  - 5 s idle timeout → close (action: close_timeout)

Sidecar format (one JSON line per ADU processed):
  session_id  — unique ID per accepted TCP connection
  seq         — monotonically increasing request counter within the session
  timestamp   — ISO-8601 UTC
  client      — "host:port" of the fuzzer
  tid         — MBAP transaction ID (hex string, null if header unreadable)
  unit_id     — MBAP unit identifier (hex string, null if header unreadable)
  fc          — function code (hex string, null if PDU empty or header unreadable)
  action      — controlled vocabulary (see ACTION_* constants below)
  reason      — human-readable explanation
  rx_hex      — raw bytes received for this ADU (hex)
  tx_hex      — raw bytes sent in response (hex, null if connection closed)

Correlation with fuzzer JSONL:
  For single-ADU cases: one fuzzer record ↔ one sidecar record (join on session seq order).
  For multi-ADU payloads (pipelined, coil-aliasing pairs): one fuzzer record ↔ N sidecar
  records. Any fuzzer crash_indicator whose corresponding sidecar action is an expected
  close or exception is a false positive. Any crash_indicator with no matching sidecar
  entry — or with a sidecar action of close_timeout after a valid-looking ADU — is a
  genuine finding candidate.

Usage:
  python3 scripts/modbus_responder.py [--host 127.0.0.1] [--port 5020] [--output output/]

  Then run the fuzzer against it:
  python3 icsFuzzer.py --protocol modbus --target 127.0.0.1:5020 --yes
"""

import argparse
import collections
import json
import socket
import struct
import threading
from datetime import datetime, timezone
from pathlib import Path

# ── Action vocabulary ─────────────────────────────────────────────────────────
# Keep these stable — they are the join key for analysis scripts.

ACTION_RESP_EXCEPTION_ILLEGAL_FUNCTION      = "response_exception_illegal_function"
ACTION_RESP_EXCEPTION_ILLEGAL_DATA_ADDRESS  = "response_exception_illegal_data_address"
ACTION_RESP_WRITE_SUCCESS                   = "response_write_success"
ACTION_CLOSE_BAD_PROTO_ID                   = "close_bad_proto_id"
ACTION_CLOSE_OVERSIZED_PDU                  = "close_oversized_pdu"
ACTION_CLOSE_TRUNCATED_HEADER               = "close_truncated_header"
ACTION_CLOSE_TRUNCATED_PDU                  = "close_truncated_pdu"
ACTION_CLOSE_EMPTY_PDU                      = "close_empty_pdu"
ACTION_CLOSE_TIMEOUT                        = "close_timeout"
ACTION_CLOSE_CLIENT_RESET                   = "close_client_reset"

# ── Modbus constants ──────────────────────────────────────────────────────────

_ASSIGNED_PUBLIC = frozenset([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x2B,
])


# ── Sidecar logger ────────────────────────────────────────────────────────────

class SidecarLogger:
    """Thread-safe JSONL writer for responder decisions."""

    def __init__(self, output_dir: str):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = out / f"modbus-responder-{ts}.jsonl"
        self._file = open(self.path, "w", encoding="utf-8")
        self._lock = threading.Lock()
        self._counts: collections.Counter = collections.Counter()
        print(f"[responder] sidecar  → {self.path}")

    def log(
        self,
        session_id: str,
        seq: int,
        client: tuple,
        tid,         # int or None
        unit_id,     # int or None
        fc,          # int or None
        action: str,
        reason: str,
        rx_hex: str,
        tx_hex,      # str or None
    ) -> None:
        record = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "seq":        seq,
            "client":     f"{client[0]}:{client[1]}",
            "tid":        f"0x{tid:04X}" if tid is not None else None,
            "unit_id":    f"0x{unit_id:02X}" if unit_id is not None else None,
            "fc":         f"0x{fc:02X}" if fc is not None else None,
            "action":     action,
            "reason":     reason,
            "rx_hex":     rx_hex,
            "tx_hex":     tx_hex,
        }
        with self._lock:
            self._file.write(json.dumps(record) + "\n")
            self._file.flush()
            self._counts[action] += 1

    def summary(self) -> None:
        total = sum(self._counts.values())
        print(f"\n[responder] sidecar summary — {total} ADUs processed")
        for action, count in sorted(self._counts.items(), key=lambda x: -x[1]):
            print(f"  {action:<48} {count}")
        print(f"[responder] sidecar  → {self.path}")

    def close(self) -> None:
        with self._lock:
            if not self._file.closed:
                self._file.close()


# ── Wire helpers ──────────────────────────────────────────────────────────────

def _build_exception(tid: int, unit_id: int, fc: int, exc_code: int) -> bytes:
    pdu = bytes([fc | 0x80, exc_code])
    return struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), unit_id) + pdu


def _build_echo(tid: int, unit_id: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), unit_id) + pdu


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


# ── Per-connection handler ────────────────────────────────────────────────────

_session_counter = 0
_session_lock = threading.Lock()


def _next_session_id() -> str:
    global _session_counter
    with _session_lock:
        _session_counter += 1
        return f"S{_session_counter:04d}"


def handle_client(
    conn: socket.socket,
    addr: tuple,
    sidecar: SidecarLogger,
    verbose: bool = True,
) -> None:
    session_id = _next_session_id()
    seq = 0
    if verbose:
        print(f"[responder] + {addr[0]}:{addr[1]}  ({session_id})")
    conn.settimeout(5.0)

    try:
        while True:
            seq += 1

            # ── Read MBAP header (7 bytes) ──────────────────────────────────
            header = _recv_exact(conn, 7)
            if len(header) == 0:
                # Clean client close — don't log (no ADU was started)
                return
            if len(header) < 7:
                sidecar.log(
                    session_id, seq, addr,
                    tid=None, unit_id=None, fc=None,
                    action=ACTION_CLOSE_TRUNCATED_HEADER,
                    reason=f"received {len(header)}/7 header bytes — client closed mid-header",
                    rx_hex=header.hex(),
                    tx_hex=None,
                )
                return

            tid, proto_id, length, unit_id = struct.unpack(">HHHB", header)

            # ── Validate protocol ID ────────────────────────────────────────
            if proto_id != 0x0000:
                sidecar.log(
                    session_id, seq, addr,
                    tid=tid, unit_id=unit_id, fc=None,
                    action=ACTION_CLOSE_BAD_PROTO_ID,
                    reason=f"MBAP protocol_id=0x{proto_id:04X} (must be 0x0000)",
                    rx_hex=header.hex(),
                    tx_hex=None,
                )
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  bad proto_id=0x{proto_id:04X} — closing")
                return

            # ── Validate PDU length ─────────────────────────────────────────
            pdu_len = length - 1  # length field includes unit_id byte
            if pdu_len < 0 or pdu_len > 260:
                sidecar.log(
                    session_id, seq, addr,
                    tid=tid, unit_id=unit_id, fc=None,
                    action=ACTION_CLOSE_OVERSIZED_PDU,
                    reason=f"MBAP length field implies pdu_len={pdu_len} (max 260)",
                    rx_hex=header.hex(),
                    tx_hex=None,
                )
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  bad pdu_len={pdu_len} — closing")
                return

            # Empty PDU (length=1 means only unit_id, no FC byte)
            if pdu_len == 0:
                sidecar.log(
                    session_id, seq, addr,
                    tid=tid, unit_id=unit_id, fc=None,
                    action=ACTION_CLOSE_EMPTY_PDU,
                    reason="MBAP length=1 — unit_id only, no function code",
                    rx_hex=header.hex(),
                    tx_hex=None,
                )
                return

            # ── Read PDU ────────────────────────────────────────────────────
            pdu = _recv_exact(conn, pdu_len)
            rx_hex = (header + pdu).hex()

            if len(pdu) < pdu_len:
                sidecar.log(
                    session_id, seq, addr,
                    tid=tid, unit_id=unit_id, fc=None,
                    action=ACTION_CLOSE_TRUNCATED_PDU,
                    reason=f"received {len(pdu)}/{pdu_len} PDU bytes — client closed mid-PDU",
                    rx_hex=rx_hex,
                    tx_hex=None,
                )
                return

            fc = pdu[0]
            if verbose:
                print(f"[responder]   {session_id}/{seq}  tid=0x{tid:04X} uid=0x{unit_id:02X} fc=0x{fc:02X}")

            # ── Build and send response ─────────────────────────────────────
            if fc in _ASSIGNED_PUBLIC:
                # Simulate one writable coil at address 0x0001 for FC05
                if fc == 0x05 and len(pdu) >= 5:
                    addr_val = struct.unpack(">H", pdu[1:3])[0]
                    coil_val = struct.unpack(">H", pdu[3:5])[0]
                    if addr_val == 0x0001 and coil_val in (0xFF00, 0x0000):
                        resp = _build_echo(tid, unit_id, pdu)
                        conn.sendall(resp)
                        sidecar.log(
                            session_id, seq, addr,
                            tid=tid, unit_id=unit_id, fc=fc,
                            action=ACTION_RESP_WRITE_SUCCESS,
                            reason="FC05 write single coil at addr 0x0001 — echoed as write success",
                            rx_hex=rx_hex,
                            tx_hex=resp.hex(),
                        )
                        continue

                resp = _build_exception(tid, unit_id, fc, 0x02)
                conn.sendall(resp)
                sidecar.log(
                    session_id, seq, addr,
                    tid=tid, unit_id=unit_id, fc=fc,
                    action=ACTION_RESP_EXCEPTION_ILLEGAL_DATA_ADDRESS,
                    reason=f"assigned FC 0x{fc:02X} — refused with exception 0x02 (Illegal Data Address)",
                    rx_hex=rx_hex,
                    tx_hex=resp.hex(),
                )
            else:
                resp = _build_exception(tid, unit_id, fc, 0x01)
                conn.sendall(resp)
                sidecar.log(
                    session_id, seq, addr,
                    tid=tid, unit_id=unit_id, fc=fc,
                    action=ACTION_RESP_EXCEPTION_ILLEGAL_FUNCTION,
                    reason=f"unassigned FC 0x{fc:02X} — refused with exception 0x01 (Illegal Function)",
                    rx_hex=rx_hex,
                    tx_hex=resp.hex(),
                )

    except socket.timeout:
        sidecar.log(
            session_id, seq, addr,
            tid=None, unit_id=None, fc=None,
            action=ACTION_CLOSE_TIMEOUT,
            reason="5 s idle timeout — no data received",
            rx_hex="",
            tx_hex=None,
        )
    except (ConnectionResetError, BrokenPipeError, OSError):
        sidecar.log(
            session_id, seq, addr,
            tid=None, unit_id=None, fc=None,
            action=ACTION_CLOSE_CLIENT_RESET,
            reason="client reset or closed connection unexpectedly",
            rx_hex="",
            tx_hex=None,
        )
    finally:
        conn.close()
        if verbose:
            print(f"[responder] - {addr[0]}:{addr[1]}  ({session_id})")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Modbus TCP software responder — icsFuzzer calibration target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--host",   default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port",   type=int, default=5020, help="Bind port (default: 5020)")
    parser.add_argument("--output", default="output", metavar="DIR",
                        help="Directory for sidecar JSONL (default: output/)")
    parser.add_argument("--quiet",  action="store_true", help="Suppress per-ADU console output")
    args = parser.parse_args()

    sidecar = SidecarLogger(args.output)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(10)
    print(f"[responder] listening on {args.host}:{args.port}  (Ctrl-C to stop)")

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, sidecar, not args.quiet),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[responder] stopping ...")
    finally:
        srv.close()
        sidecar.summary()
        sidecar.close()


if __name__ == "__main__":
    main()
