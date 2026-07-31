# Adding a Protocol Module to icsFuzzer

This guide walks through the complete workflow for adding a new ICS protocol to
icsFuzzer — from the blank file to calibrated baseline. It targets security
researchers and ICS engineers who are comfortable with Python but have not
touched the fuzzer internals before.

The guide is organized chronologically: the order below is the order you should
actually do the work. Skip-ahead is tempting and consistently produces bugs that
only surface during the first live run.

---

## Architecture overview

icsFuzzer is a structured generator-based fuzzer, not a mutation fuzzer.  Every
protocol module produces a deterministic list of test cases in pure Python,
without a live target.  Sending those cases to a device is a separate phase that
requires either a software responder or real hardware.

```
core/base_module.py          ← Device, FuzzResult, FuzzModule, constants
core/fingerprint.py          ← FingerprintResult, OUI lookup, protocol parsers
core/logger.py               ← FuzzLogger (writes JSONL)
protocols/<name>/fuzzer.py   ← your new module
scripts/<name>_responder.py  ← software testbed (write this first)
tests/test_<name>_fuzzer.py  ← generator + unit tests
tests/test_<name>_integration.py  ← integration tests against the responder
lab-notes/<name>-research.md ← protocol notes
```

### `Device`

Carries connection metadata.  Your module receives one in `__init__` and must
never mutate it during a fuzz run.

```python
@dataclass
class Device:
    ip: str
    port: int
    protocol: str
    device_type: str = "unknown"
    firmware: str    = "unknown"
    vendor: str      = "unknown"
    model: str       = "unknown"
    mac: Optional[str] = None       # L2 address, for GOOSE / raw-Ethernet protocols
    metadata: dict   = field(default_factory=dict)
```

### `FuzzResult`

One per test case sent.  Your `_send_case()` builds and returns one.

```python
@dataclass
class FuzzResult:
    case_id:          str
    protocol:         str
    target:           str
    category:         str
    description:      str
    payload:          Optional[bytes] = None
    response:         Optional[bytes] = None
    anomaly:          Optional[str]   = None   # one of the ANOMALY_* constants
    crash_indicator:  bool            = False
    response_decoded: Optional[dict]  = None   # parsed fields if applicable
    duration_ms:      Optional[float] = None
```

### Anomaly constants

Import these from `core.base_module` — never use raw strings.

| Constant | Meaning |
|---|---|
| `ANOMALY_TIMEOUT` | No response within the timeout window |
| `ANOMALY_CONNECTION_RESET` | TCP RST / BrokenPipe / ConnectionAbortedError |
| `ANOMALY_NO_RESPONSE` | Zero-length recv (clean EOF) |
| `ANOMALY_MALFORMED_RESPONSE` | Response violates the protocol framing spec |
| `ANOMALY_EXCEPTION` | Protocol-level error reply (spec-compliant, not a crash) |
| `ANOMALY_UNEXPECTED_DATA` | Valid framing but unexpected PDU type for this state |

`crash_indicator=True` means "needs human review — device may have crashed."
`ANOMALY_EXCEPTION` with `crash_indicator=False` is the normal path for valid
but refused requests (Modbus FC | 0x80, BACnet Error, MMS confirmedErrorPDU).

### `FuzzModule` base class

Your class inherits from this.  The three class-level attributes are mandatory:

```python
class YourProtocolFuzzer(FuzzModule):
    PROTOCOL_NAME   = "yourprotocol"   # used as case_id prefix and log key
    DEFAULT_PORT    = 12345
    FUZZ_CATEGORIES = [...]            # all categories this module supports
```

The base class provides:

- `_next_id()` — returns `"yourprotocol-0001"`, `"yourprotocol-0002"`, etc.
- `_resolve_categories(categories)` — filters requested categories against
  `FUZZ_CATEGORIES`, warns on unknowns, returns valid subset.
- `fingerprint(active)` — default returns OUI-only result; override per protocol.
- `replay_payload(payload)` — default raises `NotImplementedError`; override
  once the send phase is implemented.

---

## Step 1 — Create `protocols/<name>/fuzzer.py`

```
protocols/
  <name>/
    __init__.py     ← empty
    fuzzer.py
```

Start with the skeleton below, then fill in the sections one at a time.

```python
"""<ProtocolName> fuzzer module.

Spec: <RFC / standard citation with date>
TCP/UDP port: <N>
"""

import socket
import struct
import time
from typing import Optional

from core.base_module import (
    ANOMALY_CONNECTION_RESET,
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
    ANOMALY_NO_RESPONSE,
    ANOMALY_TIMEOUT,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
    FuzzModule,
    FuzzResult,
)

# ── protocol-specific category names ─────────────────────────────────────────
CATEGORY_SERVICE_SWEEP = "<name>_service_sweep"
# add more as needed

# ── constants ─────────────────────────────────────────────────────────────────
# function codes, PDU types, magic bytes — put them here, not inline

# ── module-level wire builders ────────────────────────────────────────────────
# Pure functions, no class state. _tpkt(), _read_req(), _hel(), etc.


class YourProtocolFuzzer(FuzzModule):
    PROTOCOL_NAME   = "<name>"
    DEFAULT_PORT    = <N>
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_SEQUENCE,
        CATEGORY_STATE_MACHINE,
        CATEGORY_SERVICE_SWEEP,
    ]

    def __init__(self, target: Device, logger=None, delay: float = 0.1, seeds=None):
        super().__init__(target=target, logger=logger, delay=delay, seeds=seeds)
        self._sock = None
        # protocol-specific session state goes here

    # ── wire builders (instance methods that need self, e.g. for session handle)

    # ── generator methods ─────────────────────────────────────────────────────

    def _generate_boundary(self) -> list:
        cases = []
        # (description: str, payload: bytes) tuples
        return cases

    # ... one method per category ...

    # ── public API ────────────────────────────────────────────────────────────

    def generate_cases(self, categories=None) -> list:
        ...

    def connect(self, target=None) -> None:
        ...

    def close(self) -> None:
        ...

    def fuzz(self, categories=None) -> list:
        ...

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError("<Protocol> discovery requires scapy + CAP_NET_RAW.")
```

---

## Step 2 — Implement `generate_cases()`

This is the most important method. It runs completely without a network
connection, which is what makes generator-based fuzzing auditable, exportable,
and testable.

```python
def generate_cases(self, categories=None) -> list:
    """Return all fuzz cases without sending. Hardware-independent.

    Returns list of (case_id, category, description, payload_bytes).
    """
    active = self._resolve_categories(categories)
    generator_map = {
        CATEGORY_BOUNDARY:          self._generate_boundary,
        CATEGORY_BINARY_CORRUPTION: self._generate_binary_corruption,
        CATEGORY_SEQUENCE:          self._generate_sequence,
        CATEGORY_STATE_MACHINE:     self._generate_state_machine,
        CATEGORY_SERVICE_SWEEP:     self._generate_service_sweep,
    }
    cases = []
    for category in active:
        gen = generator_map.get(category)
        if gen is None:
            continue
        for description, payload in gen():
            cases.append((self._next_id(), category, description, payload))
    return cases
```

**What each category should contain:**

| Category | What to put in it |
|---|---|
| `boundary` | Spec-defined limits (min/max field values, address ceiling). Correct implementations handle these; crashes here are pure findings. |
| `binary_corruption` | Bit-flips, byte substitutions (0x00/0xFF/0xAA), length mutations, truncations. |
| `sequence` | Out-of-order PDUs, duplicate sends, interleaved sessions, pipelined requests. |
| `state_machine` | Send authenticated commands before auth, tear-down commands before setup, replay a closed session. |
| `<protocol>_service_sweep` | Exhaustive sweep of service/function codes including reserved, vendor-specific, and exception spaces. |

For protocol-specific categories beyond the standard set, define string
constants at module level (see IEC 61850's `CATEGORY_SERVICE_SWEEP`,
`CATEGORY_ASN1`, `CATEGORY_FRAG`, `CATEGORY_ADDR`).

### Category density guidelines

From calibrating all 8 existing modules, a healthy module looks like:

- 150–600 total cases
- No single category dominates more than 50% of the total
- `binary_corruption` sweeps (per-byte flip × 3 values) inflate quickly — cap
  the input payloads you corrupt, not the operation count
- `service_sweep` / function-code exhaustion is O(256) by design; that is fine

---

## Step 3 — Implement the required send methods

### `connect(target=None)`

Establish the TCP (or UDP) session.  For protocols with a mandatory handshake
(COTP, STARTDT, Register Session), complete the full exchange before returning.
The caller expects the connection to be ready for `fuzz()` on return.

```python
def connect(self, target=None) -> None:
    if target is not None:
        self.target = target
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((self.target.ip, self.target.port))
    self._sock = s

    # Example: send protocol handshake
    s.sendall(HANDSHAKE_REQUEST)
    resp = self._recv_response()
    if not resp or resp[0] != EXPECTED_MAGIC:
        s.close()
        raise ConnectionError(f"Handshake failed: {resp!r}")
```

### `close()`

Always safe to call on an already-closed socket.

```python
def close(self) -> None:
    if self._sock:
        try:
            self._sock.close()
        except OSError:
            pass
        self._sock = None
```

### `_send_case()`

Not abstract, but you must implement it.  This is where the send/recv/classify
loop lives.

```python
def _send_case(self, case_id, category, description, payload) -> FuzzResult:
    if self._sock is None:
        raise RuntimeError("call connect() before fuzz()")
    t0 = time.monotonic()
    result = FuzzResult(
        case_id=case_id, protocol=self.PROTOCOL_NAME,
        target=f"{self.target.ip}:{self.target.port}",
        category=category, description=description, payload=payload,
    )
    try:
        self._sock.sendall(payload)
        response = self._recv_response()
        result.response = response
        if not response:
            result.anomaly = ANOMALY_NO_RESPONSE
            result.crash_indicator = True
            self._reconnect()
        elif len(response) < MINIMUM_VALID_RESPONSE:
            result.anomaly = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            self._reconnect()
        else:
            self._classify_response(payload, response, result)
    except socket.timeout:
        result.anomaly = ANOMALY_TIMEOUT
        result.crash_indicator = True
        self._reconnect()
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
        result.anomaly = ANOMALY_CONNECTION_RESET
        result.crash_indicator = True
        self._reconnect()
    finally:
        result.duration_ms = (time.monotonic() - t0) * 1000
    if self.logger:
        self.logger.log(result)
    if self.delay:
        time.sleep(self.delay)
    return result
```

**Reconnect after all broken-socket anomalies** — not just timeout and reset.
If `recv()` returns empty bytes (EOF) and you do not reconnect, every subsequent
case sends into a dead socket and produces a cascade of false positives.  Call
`self._reconnect()` after `ANOMALY_NO_RESPONSE` and `ANOMALY_MALFORMED_RESPONSE`
as well.

### `_classify_response()`

Examines the raw response bytes and sets `result.anomaly` and
`result.crash_indicator`.  Keep the logic here; do not mix it into `_send_case`.

Key decisions you need to encode:
- What does a protocol-compliant error response look like? That is
  `ANOMALY_EXCEPTION, crash_indicator=False` — not a crash.
- What framing violations indicate a broken implementation?  Those are
  `ANOMALY_MALFORMED_RESPONSE, crash_indicator=True`.
- Are there responses so unexpected they might indicate state confusion?
  Use `ANOMALY_UNEXPECTED_DATA` with judgment.

### `fuzz()`

Delegates to `generate_cases()` and `_send_case()`.  Add progress output so a
long run does not look stalled.

```python
def fuzz(self, categories=None) -> list:
    if self._sock is None:
        raise RuntimeError("call connect() before fuzz()")
    cats  = self._resolve_categories(categories)
    cases = self.generate_cases(cats)
    total = len(cases)
    print(f"[{self.PROTOCOL_NAME}] {total} cases  {len(cats)} categories")
    results = []
    for i, (case_id, cat, desc, payload) in enumerate(cases, 1):
        r = self._send_case(case_id, cat, desc, payload)
        results.append(r)
        if self.logger:
            self.logger.log(r)
        if r.crash_indicator and self._sock is None:
            try:
                self.connect()
            except Exception:
                pass
        if i % 50 == 0:
            print(f"[{self.PROTOCOL_NAME}] {case_id}  {i}/{total} ({i/total:.0%})")
    return results
```

### `discover()`

For the generator phase, stub this out:

```python
def discover(self, interface: str, timeout: int = 30) -> list:
    raise NotImplementedError(
        "<Protocol> discovery requires scapy + CAP_NET_RAW."
    )
```

Full implementation — passive sniff on the wire, parse broadcast/announce
frames, return `Device` list — is a hardware-phase task.

---

## Step 4 — Optional methods

### `fingerprint(active=True)`

The base class default reads the OS ARP cache and returns an OUI vendor lookup
with `confidence="low"`.  Override this to send a single benign identity probe.

```python
def fingerprint(self, active: bool = True) -> "FingerprintResult":
    from core.fingerprint import FingerprintResult, fingerprint_from_oui

    oui_result = fingerprint_from_oui(self.target.ip)
    if not active:
        return oui_result

    vendor = model = firmware = "unknown"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(4.0)
        s.connect((self.target.ip, self.target.port))
        s.sendall(IDENTITY_REQUEST_BYTES)
        resp = s.recv(512)
        # parse resp → vendor, model, firmware
    except OSError:
        return oui_result
    finally:
        s.close()     # always close — no exception swallowing needed

    return FingerprintResult(
        vendor=vendor, model=model, firmware=firmware,
        confidence="high" if vendor != "unknown" else "low",
        method="<name>_identity_probe",
    )
```

**Always use `try/finally: s.close()`** on the ephemeral socket.  An OSError
raised after `connect()` but before `close()` leaks the file descriptor
otherwise.

The two CLI flags wire to this method:

- `--fingerprint-passive` → `fingerprint(active=False)` — zero packets, OUI only
- `--fingerprint` → `fingerprint(active=True)` — one benign probe per device

### `replay_payload(payload)`

Re-sends a raw payload from the JSONL log and returns the response.  Used by
`--replay` and `--replay-all-crashes`.

```python
def replay_payload(self, payload: bytes) -> Optional[bytes]:
    if self._sock is None:
        raise RuntimeError("call connect() before replay_payload()")
    self._sock.sendall(payload)
    return self._recv_response()
```

### `establish_presence()`

For protocols that require a registration step before sending service requests
— MQTT CONNECT, S7 Setup Communication, IEC 104 STARTDT — override this method
to send that initial handshake.  The CLI calls it automatically after `connect()`
and before `fuzz()`.  The default is a no-op.

---

## Step 5 — Write the software responder first

**Do not implement the send phase without a software responder.**  This is the
single most impactful rule from building the eight existing modules.

The responder eliminates hardware from the development loop.  More importantly,
it produces a *sidecar JSONL* — one structured record per PDU received — that
makes the difference between "62 crash indicators" and "62 crash indicators,
of which 60 are expected protocol-close behaviors and 2 are genuine findings."

### Structure

```
scripts/<name>_responder.py
scripts/__init__.py        ← creates importable package for integration tests
```

Model the responder on `scripts/modbus_responder.py`.  The key elements:

```python
# Module-level session counter (never per-connection local — see pitfall #10)
import threading
_session_lock    = threading.Lock()
_session_counter = 0

def _next_session_handle() -> int:
    global _session_counter
    with _session_lock:
        _session_counter += 1
        return 0x00010000 + _session_counter


class SidecarLogger:
    def __init__(self, path: str):
        self._f = open(path, "w")

    def log(self, action: str, peer: str, **extra):
        import json, time
        self._f.write(json.dumps({"ts": time.time(), "action": action,
                                   "peer": peer, **extra}) + "\n")
        self._f.flush()


def handle_client(conn, addr, sidecar, verbose=False):
    """Importable handler — used by both __main__ and integration tests."""
    peer = f"{addr[0]}:{addr[1]}"
    try:
        while True:
            data = _recv_frame(conn)
            if not data:
                sidecar.log("disconnect", peer)
                return
            response = _dispatch(data, sidecar, peer)
            if response:
                conn.sendall(response)
    except (ConnectionResetError, BrokenPipeError):
        sidecar.log("client_reset", peer)
    finally:
        conn.close()
```

### Sidecar action vocabulary

Agree on a stable set of action strings before you write the first integration
test.  These strings become join keys in analysis — renaming them later is
painful.  Typical vocabulary:

```
response_ok             # normal successful response
response_exception      # spec-compliant error response
close_bad_frame         # frame violated protocol, responder closed
close_truncated         # incomplete frame received
close_empty             # zero-length receive (client disconnected cleanly)
close_unknown_command   # unknown service/function code, responder closed
client_reset            # TCP RST before close
disconnect              # clean close by client
```

### Port offset convention

Standard ICS ports require root privileges.  Offset by 10× or use an even
number above 1024:

| Protocol | Standard port | Responder port |
|---|---|---|
| Modbus | 502 | 5020 |
| IEC 104 | 2404 | 2405 |
| DNP3 | 20000 | 20001 |
| EtherNet/IP | 44818 | 44819 |
| BACnet | 47808 | 47809 |
| GE SRTP | 18245 | 18246 |
| OPC-UA | 4840 | 4841 |
| IEC 61850 | 102 | 1102 |

---

## Step 6 — Test suite

Two test files, one shared fixture, no live network.

### `tests/test_<name>_fuzzer.py` — generator and unit tests

These must pass without any socket or responder.  They cover:

1. **Wire builder correctness** — test every `_build_xyz()` function for header
   bytes, length fields, and framing.

2. **Category coverage** — `generate_cases()` must include all declared
   `FUZZ_CATEGORIES`.

3. **Case ID uniqueness** — every case ID in the generated list is unique.

4. **Payload types** — every payload is `bytes`, never `str`.

5. **Minimum case count** — assert `len(cases) >= N` so regressions in
   generator logic are immediately visible.

6. **Classification logic** — unit-test `_classify_response()` with synthetic
   responses: clean, exception, malformed, empty, truncated.

```python
import pytest
from protocols.<name>.fuzzer import YourProtocolFuzzer, _build_request
from core.base_module import Device, ANOMALY_TIMEOUT, ANOMALY_EXCEPTION

@pytest.fixture
def device():
    return Device(ip="127.0.0.1", port=12345, protocol="<name>")

@pytest.fixture
def fuzzer(device):
    return YourProtocolFuzzer(target=device, logger=None, delay=0)

class TestWireBuilders:
    def test_request_start_bytes(self):
        pkt = _build_request(service=0x01)
        assert pkt[:2] == b'\xAB\xCD'   # example magic

class TestGenerateCases:
    def test_all_categories_present(self, fuzzer):
        cases = fuzzer.generate_cases()
        cats  = {c[1] for c in cases}
        for cat in YourProtocolFuzzer.FUZZ_CATEGORIES:
            assert cat in cats

    def test_unique_case_ids(self, fuzzer):
        cases = fuzzer.generate_cases()
        ids   = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_payloads_are_bytes(self, fuzzer):
        for _, _, _, payload in fuzzer.generate_cases():
            assert isinstance(payload, bytes)
```

### `tests/test_<name>_integration.py` — send-phase tests against the responder

These tests actually send packets but use an in-process responder rather than
a live device.  The pattern that works across all 8 existing modules:

```python
import socket
import threading
import pytest

from scripts.<name>_responder import handle_client
from protocols.<name>.fuzzer import YourProtocolFuzzer
from core.base_module import Device, ANOMALY_EXCEPTION

class _NoopSidecar:
    def log(self, *args, **kwargs):
        pass

def _start_responder(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    srv.settimeout(2.0)

    def _serve():
        while True:
            try:
                conn, addr = srv.accept()
                t = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, _NoopSidecar(), False),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                break
        srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return srv, t

PORT = 12399

@pytest.fixture(scope="module")
def responder():
    srv, t = _start_responder(PORT)
    yield
    # srv.close() already called in _serve when timeout fires

@pytest.fixture
def fuzzer(responder):
    device  = Device(ip="127.0.0.1", port=PORT, protocol="<name>")
    f       = YourProtocolFuzzer(target=device, logger=None, delay=0)
    f.connect()
    yield f
    f.close()

class TestIntegration:
    def test_connect_succeeds(self, responder):
        device = Device(ip="127.0.0.1", port=PORT, protocol="<name>")
        f = YourProtocolFuzzer(target=device, logger=None)
        f.connect()
        f.close()

    def test_valid_request_returns_response(self, fuzzer):
        payload  = _build_valid_request()
        response = fuzzer.replay_payload(payload)
        assert response is not None and len(response) >= MINIMUM_VALID_RESPONSE

    def test_exception_response_not_crash(self, fuzzer):
        # Send a service request the responder will decline
        from core.logger import FuzzLogger
        import io
        results = fuzzer.fuzz(categories=["<name>_service_sweep"])
        exceptions = [r for r in results if r.anomaly == ANOMALY_EXCEPTION]
        crashes    = [r for r in results if r.crash_indicator]
        # All sweep responses should be exceptions, none should crash
        assert len(exceptions) > 0
        assert len(crashes) == 0
```

---

## Step 7 — Calibration baseline

The calibration baseline is a full fuzz run against the software responder, with
the sidecar enabled.  Record the output and commit it to
`lab-notes/<name>-research.md` as the module's reference point.

```bash
# Terminal 1: start the responder with sidecar output
python3 scripts/<name>_responder.py --output output/

# Terminal 2: fuzz it
python3 icsfuzzer.py \
    --protocol <name> \
    --target 127.0.0.1:<responder_port> \
    --yes
```

After the run, examine the JSONL log:

```bash
# Count crash indicators by anomaly type
jq 'select(.crash_indicator==true) | .anomaly' output/<name>-*.jsonl | sort | uniq -c

# Check for unexpected malformed_response outside corruption categories
jq 'select(.anomaly=="malformed_response" and
           (.category != "binary_corruption") and
           (.category != "link_layer"))' output/<name>-*.jsonl
```

**What a clean baseline looks like:**

- Zero `malformed_response` from `boundary`, `sequence`, or `state_machine`
  categories. Those are false positives — fix them before proceeding.
- All `malformed_response` and `timeout` in `binary_corruption` are expected
  (you sent garbage, the responder closed — that is correct behavior).
- Every `crash_indicator` maps 1:1 to a sidecar `close_*` action for the same
  timestamp. Any fuzzer crash without a matching sidecar record is a genuine
  finding candidate.

Punch the final counts into `lab-notes/<name>-research.md`:

```
Calibration baseline (software responder, YYYY-MM-DD):
  N cases → M crash indicators (X timeout, Y connection_reset, Z no_response)
  K exception_responses (all expected: <reason>)
  J malformed_response (all from binary_corruption — expected)
  0 ANOMALY_MALFORMED_RESPONSE from non-corruption categories
```

---

## Step 8 — Research notes

Create `lab-notes/<name>-research.md` before you write a single line of
generator code.  It is the primary artifact that turns implementation knowledge
into shareable research.

**Suggested sections:**

```markdown
# <Protocol> Research Notes

## Protocol overview
- Purpose, deployed context, typical hardware (PLCs, RTUs, gateways)
- Transport: TCP or UDP, port(s)
- Authentication model (none / username-password / certificate / MAC list)

## Spec references
- Full citation with date and section numbers you rely on

## Wire format
- Frame structure diagram with byte offsets
- Header field table (name, offset, length, encoding, valid range)

## Connection lifecycle
- Step-by-step session establishment with example hex bytes
- Session teardown sequence

## Fuzz surface analysis
- What fields vary? Which are fixed by spec?
- What are the valid ranges for each fuzzy field?
- Which service codes are assigned vs. reserved vs. vendor-specific?
- What does a compliant exception response look like?

## Known vulnerabilities
- CVEs in this protocol stack (cite number, CVSS, affected products)
- Papers or advisories that motivated specific test cases

## Calibration baseline
(filled in after first software-responder run)

## Hardware findings
(filled in after hardware phase)

## Open questions
- Fields still unclear after spec reading
- Behaviors observed on hardware that differ from spec
```

---

## Common pitfalls

These come from building all eight modules.  Each was invisible to unit tests
and only surfaced during the first JSONL analysis of a live run.

### 1. Multi-ADU buffer contamination

If the protocol allows pipelining or your generator produces multi-PDU cases
(Modbus coil-aliasing sends two ADUs in one payload), the device sends one
response per ADU.  Reading only one response leaves the second in the TCP
buffer.  The *next* case then reads that stale response and immediately flags
a TID/sequence mismatch.

Fix: count ADUs per payload, drain N-1 before reading the final response:

```python
for _ in range(self._count_adus(payload) - 1):
    self._recv_response()
response = self._recv_response()
```

### 2. Sequence number comparison against the wrong ADU

After draining N-1 responses in a multi-ADU payload, the Nth response echoes
the Nth ADU's sequence number — not the first.  Comparing against the first
makes every multi-ADU case fail classification.

Fix: pass the *last* ADU's sequence number to `_classify_response()`.

### 3. Reconnect after ALL broken-socket anomalies

Reconnect after `ANOMALY_TIMEOUT` and `ANOMALY_CONNECTION_RESET` is obvious.
What is not obvious: also reconnect after `ANOMALY_NO_RESPONSE` (clean EOF)
and `ANOMALY_MALFORMED_RESPONSE`.  A peer that closes the connection cleanly
causes an empty recv.  Without reconnect, all subsequent cases fail with
connection errors and every case from that point on becomes a false positive.

### 4. Build the software responder before the send phase

It is tempting to write the send phase and test on real hardware immediately.
The problem is that hardware gives you one signal per crash: "something went
wrong."  The software responder sidecar gives you both signals: "something
went wrong" (fuzzer side) plus "this is what I closed on" (responder side).
The sidecar is what separates a finding from a false positive.

### 5. Exception responses are not crashes

Every protocol has a spec-compliant error response.  Modbus: `FC | 0x80`.
BACnet: Error APDU.  DNP3: IIN FUNC_NOT_SUPP.  MMS: confirmedErrorPDU.
These must be `ANOMALY_EXCEPTION, crash_indicator=False`.  Marking them as
crashes inflates the finding count and trains your attention away from the real
signals.

### 6. Integration tests import the responder — no duplicated logic

Write `handle_client()` in the responder as a standalone importable function.
Integration tests import it directly and pass `_NoopSidecar()` to avoid file
I/O.  Never duplicate responder logic in test fixtures.  Also create
`scripts/__init__.py` so the import works without `sys.path` gymnastics.

### 7. First-run JSONL analysis is not optional

Run the full suite against the software responder and analyze the JSONL before
declaring the module done.  Check for: TID/sequence mismatches in non-corruption
categories (buffer contamination), `malformed_response` outside corruption
categories (false positives), and crash indicators without corresponding sidecar
closes (genuine findings on the software responder — likely a responder bug
worth fixing).

### 8. Module-level session counter in the responder

If the protocol assigns session handles, the responder must allocate them from a
module-level counter protected by a lock — never a per-call local variable.
A per-call counter restarts at 1 for every connection.  Integration tests that
open N sequential connections will all get the same handle, causing
uniqueness-assertion failures.

### 9. Session handle patching must exclude binary\_corruption and state\_machine

`_prepare_payload()` patches the current session handle into outgoing frames
so they appear legitimate to the device.  But `binary_corruption` cases
intentionally send wrong handles — patching defeats their purpose.
`state_machine` tests explicitly probe wrong-session behaviors.  Keep both in a
skip-set.

### 10. No-response commands need explicit skip-recv handling

Some protocol commands have no defined response (EtherNet/IP NOP, UDP
broadcast announces).  If `_send_case()` calls `recv()` after these, it blocks
until timeout and marks every such case `ANOMALY_TIMEOUT, crash_indicator=True`.
That is a 100% false positive rate for those cases.  Detect no-response
commands by service code before `recv()` and skip the receive entirely.

### 11. Malformed-by-design cases belong in the right category

Cases that are so broken the responder has no choice but to close (e.g., DNP3
LEN=5 with no user data) do not belong in `boundary`.  `boundary` implies
"extreme-but-valid; a correct implementation responds."  Intentional
connection-closers belong in `binary_corruption` or a protocol-specific
`link_layer` / `frame_corruption` category.

---

## Completion checklist

Before marking a module complete in `lab-notes/punch-list.md`:

- [ ] `generate_cases()` returns all declared categories
- [ ] Case IDs are unique and prefixed with `PROTOCOL_NAME`
- [ ] All payloads are `bytes`
- [ ] `connect()` completes the full protocol handshake
- [ ] `close()` is safe to call when not connected
- [ ] `fuzz()` reconnects after every broken-socket anomaly
- [ ] `_classify_response()` separates exception from crash
- [ ] `replay_payload()` is implemented
- [ ] `fingerprint(active=True/False)` is implemented with `try/finally` socket close
- [ ] Software responder written with sidecar JSONL
- [ ] `scripts/__init__.py` exists
- [ ] Generator tests: wire builders, category coverage, ID uniqueness
- [ ] Integration tests: connect, valid request, exception-not-crash
- [ ] Calibration baseline run complete; zero non-corruption `malformed_response`
- [ ] `lab-notes/<name>-research.md` has spec citations and baseline results
- [ ] Punch list updated
