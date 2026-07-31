# icsFuzzer

A modular fuzzer for industrial control system (ICS/OT) network protocols. icsFuzzer
generates malformed and out-of-specification traffic for ten protocols, classifies the
responses, and ships a spec-faithful software responder for each protocol so you can
calibrate expected behavior before ever touching real hardware.

> **Authorized use only.** icsFuzzer sends deliberately malformed traffic that can crash or
> hang control-system devices. Only run it against systems you own or have explicit written
> permission to test. See [SECURITY.md](SECURITY.md).

A writeup of what this tool found against real hardware (an ESP32 and OpenPLC v3/v4) — and how
five maintainers responded — is on the blog:
[**Fuzzing ten ICS protocols on real hardware**](https://alosafuzz.github.io/2026/07/30/fuzzing-ten-ics-protocols-on-real-hardware.html).

## Supported protocols

| Protocol | Default port | Transport |
|---|---|---|
| Modbus | 502 | TCP |
| DNP3 | 20000 | TCP |
| OPC-UA | 4840 | TCP |
| EtherNet/IP | 44818 | TCP |
| IEC 61850 / MMS | 102 | TCP |
| BACnet | 47808 | UDP |
| IEC 104 | 2404 | TCP |
| PROFINET | 34964 | UDP |
| S7comm | 102 | TCP |
| FINS | 9600 | UDP |

## Why the software responders matter

On a live device, a dropped connection is ambiguous — the device may have crashed, or it may
have correctly rejected a bad frame. Each protocol ships with a software responder that logs
every request it handles to a sidecar file, recording whether it closed a connection
deliberately (for example, because the protocol ID was wrong). Calibrate against the
responder first, and every crash indicator resolves to either an expected close or a genuine
gap. You then trust the differences you see on real hardware.

## Install

Requires Python 3.10+. Most modules are standard-library only.

```bash
git clone https://github.com/alosafuzz/icsFuzzer
cd icsFuzzer
pip install -r requirements.txt
```

## Quick start

Calibrate against a software responder before any live target:

```bash
# terminal 1 — start the Modbus responder (no root needed; port 5020)
python3 scripts/modbus_responder.py --output output/

# terminal 2 — fuzz the responder
python3 icsfuzzer.py --protocol modbus --target 127.0.0.1:5020 --yes
```

Then point it at an authorized target:

```bash
python3 icsfuzzer.py --protocol s7comm --target 192.168.1.10:102 --yes
python3 icsfuzzer.py --protocol modbus  --target 192.168.1.10:502 --delay 0.1
```

Useful flags: `--categories a,b,c` (run a subset), `--dry-run` (generate cases without
sending), `--rate-limit PPS`, `--replay <ID>` / `--replay-all-crashes` (re-send from a prior
run's log).

## Output

Runs are logged as JSONL under `output/`, one record per case, with the anomaly
classification and the raw request/response bytes. Re-run the reporter to summarize or replay
a previous session.

## Testing

```bash
pip install pytest
pytest
```

The suite covers per-protocol case generation plus integration tests that drive each
software responder directly.

## Proof-of-concept scripts

The [`poc/`](poc/) directory contains a small set of standalone reproductions for issues
found with icsFuzzer. **Only PoCs for fixed or already-public issues are included here.**
Reproductions for unpatched or undisclosed issues are withheld pending coordinated
disclosure — see [poc/README.md](poc/README.md).

## Extending it

Adding a protocol module is documented end to end in
[docs/adding-a-protocol-module.md](docs/adding-a-protocol-module.md), including the pitfalls
that only surface on the first real run (multi-ADU draining, sequence-number handling,
exception-vs-crash classification, reconnect-after-anomaly).

## Security & responsible use

Read [SECURITY.md](SECURITY.md) before use. If you find a vulnerability in a vendor's product
with this tool, coordinate disclosure with the vendor before publishing.

## License

[MIT](LICENSE) © 2026 Shad Malloy (alosafuzz).

## Author

Built by Shad Malloy (**alosafuzz**), independent ICS/OT security research.
Contact: alosafuzz@proton.me
