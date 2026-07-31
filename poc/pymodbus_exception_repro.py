#!/usr/bin/env python3
"""
Repro: pymodbus async Modbus/TCP server returns a fixed exception response
(function code 0x28, transaction_id 0) for ANY undecodable function code,
instead of echoing the request's transaction_id and reflecting the real FC.

Bug lives in pymodbus itself — ServerRequestHandler.callback_data()'s
`except ModbusIOException:` branch (pymodbus/server/requesthandler.py):
  - `ExceptionResponse(40, ...)`  -> 40 (0x28) is a hardcoded literal
  - never sets `response.transaction_id` (the sibling exception paths do)

Confirmed on pymodbus 3.14.0 (latest release) and 3.11.2 (bundled by OpenPLC v4).
Standard library + pymodbus only. Exit 0 = bug reproduced.

    pip install pymodbus
    python3 pymodbus_exception_repro.py
"""
import asyncio, struct, socket, threading, time, sys
import pymodbus
from pymodbus.datastore import (ModbusSequentialDataBlock, ModbusDeviceContext,
                                ModbusServerContext)
from pymodbus.server import StartAsyncTcpServer

PORT = 15021


def make_context():
    dev = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(1, [0] * 100),
        co=ModbusSequentialDataBlock(1, [0] * 100),
        hr=ModbusSequentialDataBlock(1, [17] * 100),
        ir=ModbusSequentialDataBlock(1, [0] * 100),
    )
    return ModbusServerContext(devices=dev, single=True)


def server_thread():
    asyncio.run(StartAsyncTcpServer(context=make_context(),
                                    address=("127.0.0.1", PORT)))


def mbap(tid, pdu, unit=1):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def send(tid, fc, data=b"\x00\x00\x00\x01"):
    s = socket.socket(); s.settimeout(3); s.connect(("127.0.0.1", PORT))
    s.sendall(mbap(tid, bytes([fc]) + data))
    try:
        r = s.recv(256)
    except Exception as e:
        r = f"<{type(e).__name__}>".encode()
    s.close()
    return r


def main():
    print("pymodbus", pymodbus.__version__)
    threading.Thread(target=server_thread, daemon=True).start()
    time.sleep(2.5)  # let the server bind

    valid = send(0x1234, 0x03)  # valid read: proves TID echo works normally
    print("valid FC03 read  -> ", valid.hex(),
          "(TID 0x%04X echoed correctly)" % struct.unpack(">H", valid[0:2])[0])

    print("\nUndecodable function codes, each with a DISTINCT transaction id:")
    resps = []
    for tid, fc in [(0x0009, 0x09), (0x000A, 0x0A), (0x000D, 0x0D)]:
        r = send(tid, fc)
        resps.append(r.hex())
        print(f"  req TID=0x{tid:04X} FC=0x{fc:02X}  ->  {r.hex()}")

    uniq = set(resps)
    print(f"\nunique responses across 3 distinct requests: {len(uniq)} -> {uniq}")
    ok = len(uniq) == 1 and next(iter(uniq))
    if ok:
        b = bytes.fromhex(next(iter(uniq)))
        print(f"  response TID = 0x{struct.unpack('>H', b[0:2])[0]:04X}  (expected: echo the request TID)")
        print(f"  response FC  = 0x{b[7]:02X}  (= 0x28|0x80; exception for FC 0x28, which was never sent)")
        print("\nBUG REPRODUCED on pymodbus", pymodbus.__version__)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
