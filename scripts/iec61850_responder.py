#!/usr/bin/env python3
"""IEC 61850 MMS software responder for icsFuzzer calibration.

TCP server on port 10200 (non-privileged stand-in for 102).
Handles the TPKT/COTP/ACSE/MMS handshake and a minimal set of MMS services.

Sidecar action vocabulary:
  cotp_cr_ok        COTP CR received; CC sent
  cotp_cr_bad       COTP CR malformed; closed
  acse_aarq_ok      ACSE AARQ received; AARE (accepted) sent
  acse_aarq_bad     ACSE AARQ malformed or wrong tag; AARE (rejected) sent
  mms_getnamelist   GetNameList responded with one domain (ICS_FUZZER_TARGET)
  mms_identify      Identify responded (icsFuzzer-sw / MMS / 1.0)
  mms_read_ok       Read responded with a synthetic data value
  mms_write_reject  Write responded with ServiceError (access violation)
  mms_unknown       Unknown MMS service; confirmedErrorPDU sent
  mms_bad_pdu       MMS PDU structurally unparseable; closed
  tpkt_bad          Malformed TPKT header; closed
  disconnect        Client disconnected normally
"""

import argparse
import json
import socket
import struct
import sys
import threading
from typing import Optional


# ── BER helpers ───────────────────────────────────────────────────────────────

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def _skip_ber_len(buf: bytes, pos: int) -> int:
    """Advance pos past one BER length field; return new pos."""
    if pos >= len(buf):
        return pos
    b = buf[pos]
    pos += 1
    if b & 0x80:
        pos += b & 0x7F
    return pos


def _mms_offset(raw: bytes) -> int:
    """Return byte index of MMS PDU in TPKT frame.

    Old format: TPKT[4]+COTP_DT[3]+MMS  → offset 7
    New format: TPKT[4]+COTP_DT[3]+Session_DT[4]+Pres_FCD+MMS  → offset > 7
    Returns -1 if the frame is too short or unparseable.
    """
    if len(raw) < 8:
        return -1
    if raw[7] != 0x01:
        return 7   # old bare format
    # Session DATA SPDU: 01 00 01 00 (4 bytes)
    pos = 11
    if pos >= len(raw) or raw[pos] != 0x61:
        return -1
    pos += 1
    pos = _skip_ber_len(raw, pos)
    if pos >= len(raw) or raw[pos] != 0x30:
        return -1
    pos += 1
    pos = _skip_ber_len(raw, pos)
    # context-id: 02 01 03
    if pos + 3 > len(raw) or raw[pos:pos + 3] != b'\x02\x01\x03':
        return -1
    pos += 3
    # single-ASN1-type [0]: A0 [len]
    if pos >= len(raw) or raw[pos] != 0xA0:
        return -1
    pos += 1
    pos = _skip_ber_len(raw, pos)
    return pos if pos < len(raw) else -1


def _ber(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(body)) + body


def _vis(s: str) -> bytes:
    b = s.encode()
    return _ber(0x1A, b)


def _tpkt(payload: bytes) -> bytes:
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    total   = 4 + len(cotp_dt) + len(payload)
    return struct.pack('!BBH', 0x03, 0x00, total) + cotp_dt + payload


# ── Pre-built responses ───────────────────────────────────────────────────────

# COTP CC (22 bytes, mirrors CR with CC PDU type 0xD0)
_COTP_CC = struct.pack('!BBH', 0x03, 0x00, 22) + bytes([
    0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
    0xC0, 0x01, 0x0A,
    0xC1, 0x02, 0x00, 0x01,
    0xC2, 0x02, 0x00, 0x01,
])


def _build_acse_aare() -> bytes:
    """ACSE AARE (accepted), wrapping MMS initiate-ResponsePDU [9]."""
    mms_resp_body = (
        _ber(0x80, bytes([0x01])) +    # local-detail-called = 1
        _ber(0x81, bytes([0x64])) +    # max-outstanding-calling = 100
        _ber(0x82, bytes([0x64])) +    # max-outstanding-called  = 100
        _ber(0x83, bytes([0x04]))      # nesting-level = 4
    )
    mms_resp  = _ber(0xA9, mms_resp_body)                   # initiate-ResponsePDU [9]
    external  = _ber(0x28, bytes([0x02, 0x01, 0x01]) + _ber(0xA0, mms_resp))
    user_info = _ber(0xBE, external)
    app_ctx   = _ber(0xA1, _ber(0x06, bytes([0x28, 0xCA, 0x22, 0x02, 0x01])))
    result    = _ber(0xA2, bytes([0x02, 0x01, 0x00]))        # result = accepted (0)
    result_d  = _ber(0xA3, _ber(0xA1, bytes([0x02, 0x01, 0x00])))  # acse-service-user null
    aare      = _ber(0x61, app_ctx + result + result_d + user_info)
    return _tpkt(aare)


_ACSE_AARE = _build_acse_aare()


def _mms_getnamelist_resp(invoke_id: int) -> bytes:
    """GetNameList response listing one domain: ICS_FUZZER_TARGET."""
    domain    = _ber(0x1A, b"ICS_FUZZER_TARGET")   # VisibleString
    list_id   = _ber(0xA0, domain)
    more_fol  = bytes([0x01, 0x01, 0x00])           # moreFollows = FALSE
    svc       = _ber(0xA1, list_id + more_fol)      # getNameList [1]
    resp      = _ber(0xA1, bytes([0x02, 0x01, invoke_id & 0xFF]) + svc)
    return _tpkt(resp)


def _mms_identify_resp(invoke_id: int) -> bytes:
    """Identify response."""
    id_body = _vis("icsFuzzer-sw") + _vis("MMS") + _vis("1.0")
    svc     = _ber(0xA2, id_body)   # identify [2]
    resp    = _ber(0xA1, bytes([0x02, 0x01, invoke_id & 0xFF]) + svc)
    return _tpkt(resp)


def _mms_read_resp(invoke_id: int) -> bytes:
    """Read response with a synthetic BOOLEAN value."""
    # accessResult [0] = data [0] = boolean [3]
    bool_val    = _ber(0x83, bytes([0x01]))            # boolean TRUE, tag [3] PRIM
    access_res  = _ber(0xA0, bool_val)
    list_result = _ber(0xA0, access_res)
    svc         = _ber(0xA4, list_result)              # read [4]
    resp        = _ber(0xA1, bytes([0x02, 0x01, invoke_id & 0xFF]) + svc)
    return _tpkt(resp)


def _mms_write_reject_resp(invoke_id: int) -> bytes:
    """Write response = ServiceError (access violation = 3)."""
    error_body = bytes([0x02, 0x01, invoke_id & 0xFF,
                        0x02, 0x01, 0x03])             # serviceError = 3 (access)
    err        = _ber(0xA2, error_body)                # confirmedErrorPDU [2]
    return _tpkt(err)


def _mms_error_resp(invoke_id: int, code: int = 1) -> bytes:
    """Generic confirmedErrorPDU."""
    error_body = bytes([0x02, 0x01, invoke_id & 0xFF, 0x02, 0x01, code & 0xFF])
    err        = _ber(0xA2, error_body)
    return _tpkt(err)


# ── TPKT reader ───────────────────────────────────────────────────────────────

def _recv_tpkt(conn: socket.socket, timeout: float = 10.0) -> Optional[bytes]:
    """Read one TPKT frame. Returns None on timeout, b'' on close."""
    conn.settimeout(timeout)
    try:
        hdr = b''
        while len(hdr) < 4:
            chunk = conn.recv(4 - len(hdr))
            if not chunk:
                return b''
            hdr += chunk
        if hdr[0] != 0x03:
            return hdr    # pass non-TPKT data to caller
        claimed = struct.unpack('!H', hdr[2:4])[0]
        rest    = claimed - 4
        if rest <= 0:
            return hdr
        body = b''
        while len(body) < rest:
            chunk = conn.recv(min(rest - len(body), 65536))
            if not chunk:
                break
            body += chunk
        return hdr + body
    except socket.timeout:
        return None
    except (ConnectionResetError, OSError):
        return b''


# ── Connection handler ────────────────────────────────────────────────────────

def _sidecar(action: str, data: dict = None, fh=None) -> None:
    msg = {"action": action}
    if data:
        msg.update(data)
    line = json.dumps(msg)
    fh   = fh or sys.stdout
    print(line, file=fh, flush=True)


def _parse_mms_outer(tpkt: bytes):
    """Extract (mms_tag, invoke_id, svc_tag) from a TPKT frame.

    Handles both bare MMS (old format, offset 7) and Session DT +
    Presentation FCD wrapped MMS (new format, offset > 7).
    Raises ValueError if the frame is too short or malformed.
    """
    off = _mms_offset(tpkt)
    if off < 0 or off >= len(tpkt):
        raise ValueError("too short or unparseable wrapper")
    mms_tag      = tpkt[off]
    mms_len_byte = tpkt[off + 1] if off + 1 < len(tpkt) else 0
    if mms_len_byte & 0x80:
        extra  = mms_len_byte & 0x7F
        offset = off + 2 + extra
    else:
        offset = off + 2
    if len(tpkt) < offset + 3:
        raise ValueError("truncated invoke id")
    invoke_id = tpkt[offset + 2]  # 02 01 XX
    svc_tag   = tpkt[offset + 3] if len(tpkt) > offset + 3 else 0x00
    return mms_tag, invoke_id, svc_tag


# State machine
_ST_INIT      = "init"
_ST_COTP      = "cotp_done"
_ST_ACSE      = "acse_done"
_ST_MMS       = "mms_ready"


def handle_client(conn: socket.socket, addr, verbose: bool, sc_fh) -> None:
    state = _ST_INIT

    def sc(action, **kw):
        _sidecar(action, {"peer": f"{addr[0]}:{addr[1]}", **kw}, sc_fh)

    def send(data: bytes):
        try:
            conn.sendall(data)
        except OSError:
            pass

    try:
        while True:
            raw = _recv_tpkt(conn, timeout=30.0)

            if raw is None:
                # timeout — keep waiting unless stuck in init
                if state == _ST_INIT:
                    break
                continue

            if raw == b'':
                sc("disconnect")
                break

            if len(raw) < 4 or raw[0] != 0x03:
                sc("tpkt_bad", got=raw[:8].hex())
                break

            # ── COTP phase ───────────────────────────────────────────────────
            if len(raw) >= 6 and raw[5] == 0xE0:   # COTP CR
                if state != _ST_INIT:
                    sc("cotp_cr_bad", reason="unexpected CR in state " + state)
                    break
                send(_COTP_CC)
                state = _ST_COTP
                sc("cotp_cr_ok")
                continue

            # ── ACSE phase ───────────────────────────────────────────────────
            if state == _ST_COTP:
                if len(raw) < 8:
                    first = "none"
                    aarq_found = False
                else:
                    first = f"0x{raw[7]:02X}"
                    if raw[7] == 0x60:
                        # Old bare AARQ format
                        aarq_found = True
                    elif raw[7] == 0x0D:
                        # New: Session CN SPDU — AARQ (0x60) is embedded inside
                        aarq_found = 0x60 in raw[8:]
                    else:
                        aarq_found = False
                if not aarq_found:
                    sc("acse_aarq_bad", got=first)
                    reject_body = (
                        _ber(0xA1, _ber(0x06, bytes([0x28, 0xCA, 0x22, 0x02, 0x01]))) +
                        _ber(0xA2, bytes([0x02, 0x01, 0x02])) +   # result=rejected
                        _ber(0xA3, _ber(0xA1, bytes([0x02, 0x01, 0x02])))
                    )
                    send(_tpkt(_ber(0x61, reject_body)))
                    break
                send(_ACSE_AARE)
                state = _ST_MMS
                sc("acse_aarq_ok")
                continue

            # ── MMS phase ────────────────────────────────────────────────────
            if state in (_ST_ACSE, _ST_MMS):
                if len(raw) < 8:
                    sc("mms_bad_pdu", reason="frame too short")
                    break

                # Non-MMS PDU types in this state
                if raw[5] == 0xE0:        # another CR
                    sc("cotp_cr_bad", reason="CR mid-session")
                    send(_COTP_CC)        # lenient: re-confirm
                    continue

                mms_off = _mms_offset(raw)
                mms_tag = raw[mms_off] if mms_off >= 0 and mms_off < len(raw) else 0x00

                if mms_off < 0 or mms_tag not in (0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
                                                   0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
                                                   0xAC, 0xAD, 0xAE, 0xAF):
                    sc("mms_bad_pdu", tag=f"0x{mms_tag:02X}")
                    # send generic error and keep connection
                    send(_tpkt(bytes([0xA2, 0x04, 0x02, 0x01, 0x01, 0x02])))
                    continue

                if mms_tag != 0xA0:      # confirmed request only
                    sc("mms_unknown", tag=f"0x{mms_tag:02X}")
                    send(_mms_error_resp(0x01, code=2))
                    continue

                try:
                    _, invoke_id, svc_tag = _parse_mms_outer(raw)
                except ValueError as e:
                    sc("mms_bad_pdu", reason=str(e))
                    break

                if svc_tag == 0xA1:      # getNameList
                    send(_mms_getnamelist_resp(invoke_id))
                    sc("mms_getnamelist", invoke_id=invoke_id)
                elif svc_tag == 0xA2:    # identify
                    send(_mms_identify_resp(invoke_id))
                    sc("mms_identify", invoke_id=invoke_id)
                elif svc_tag == 0xA4:    # read
                    send(_mms_read_resp(invoke_id))
                    sc("mms_read_ok", invoke_id=invoke_id)
                elif svc_tag == 0xA5:    # write
                    send(_mms_write_reject_resp(invoke_id))
                    sc("mms_write_reject", invoke_id=invoke_id)
                else:
                    send(_mms_error_resp(invoke_id, code=1))
                    sc("mms_unknown", invoke_id=invoke_id,
                       svc=f"0x{svc_tag:02X}")

                state = _ST_MMS
                continue

            # Unrecognised state / frame
            sc("tpkt_bad", state=state, frame=raw[:8].hex())
            break

    except Exception as exc:
        sc("error", exc=str(exc))
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="IEC 61850 MMS software responder (non-privileged port)")
    ap.add_argument("--port", type=int, default=10200,
                    help="TCP port to listen on (default 10200)")
    ap.add_argument("--host", default="0.0.0.0",
                    help="Bind address (default 0.0.0.0)")
    ap.add_argument("--verbose", action="store_true",
                    help="Print sidecar JSON to stderr too")
    ap.add_argument("--sidecar", metavar="FILE",
                    help="Write sidecar JSON lines to FILE instead of stdout")
    args = ap.parse_args()

    sc_fh = open(args.sidecar, "w") if args.sidecar else sys.stdout

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(5)
    _sidecar("listening", {"host": args.host, "port": args.port}, sc_fh)

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, args.verbose, sc_fh),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        if sc_fh is not sys.stdout:
            sc_fh.close()


if __name__ == "__main__":
    main()
