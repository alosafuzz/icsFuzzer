"""Device fingerprinting utilities shared across ICS protocol modules.

Two risk tiers:
  passive (active=False) — reads ARP cache only, sends zero packets.
  active  (active=True)  — sends one benign identity probe per protocol.
"""

from __future__ import annotations

import re
import struct
import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FingerprintResult:
    vendor:     str = "unknown"
    model:      str = "unknown"
    firmware:   str = "unknown"
    serial:     str = "unknown"
    confidence: str = "none"      # "high" / "medium" / "low" / "none"
    method:     str = ""          # technique that produced this result
    extra:      dict = field(default_factory=dict)

    def is_known(self) -> bool:
        return self.confidence != "none" and self.vendor != "unknown"

    def as_dict(self) -> dict:
        return {
            "vendor":     self.vendor,
            "model":      self.model,
            "firmware":   self.firmware,
            "serial":     self.serial,
            "confidence": self.confidence,
            "method":     self.method,
        }


# ── OUI lookup table (curated for ICS/OT vendors) ────────────────────────────
# Key: uppercase colon-separated 3-octet prefix (e.g. "00:0E:8C")
# Source: IEEE OUI database, filtered to known ICS/OT manufacturers

_OUI_TABLE: dict[str, str] = {
    # Siemens
    "00:0E:8C": "Siemens AG",
    "00:1B:1B": "Siemens AG",
    "20:87:56": "Siemens AG",
    "28:63:36": "Siemens AG",
    "34:7C:25": "Siemens AG",
    "AC:64:17": "Siemens AG",
    # Rockwell Automation / Allen-Bradley
    "00:00:BC": "Rockwell Automation",
    "00:09:B0": "Rockwell Automation",
    "00:1D:9C": "Rockwell Automation",
    "00:60:35": "Rockwell Automation",
    "5C:88:16": "Rockwell Automation",
    # Schneider Electric / Modicon
    "00:30:64": "Schneider Electric",
    "00:50:F0": "Schneider Electric",
    "08:00:F4": "Schneider Electric",
    "D0:C7:C0": "Schneider Electric",
    # GE Automation / GE Digital
    "00:1B:22": "GE Automation",
    "00:80:2F": "GE Automation",
    "38:60:77": "GE Digital",
    # ABB
    "00:0A:DC": "ABB AB",
    "00:E0:85": "ABB AB",
    # Honeywell
    "00:00:32": "Honeywell International",
    "00:40:C7": "Honeywell International",
    "10:5E:60": "Honeywell International",
    # Emerson Electric
    "00:13:06": "Emerson Electric",
    "00:E0:6A": "Emerson Electric",
    # Mitsubishi Electric
    "00:00:21": "Mitsubishi Electric",
    "00:14:C0": "Mitsubishi Electric",
    # Omron
    "00:00:66": "Omron Corporation",
    "00:20:D2": "Omron Corporation",
    # Phoenix Contact
    "00:A0:45": "Phoenix Contact",
    "A8:F9:4B": "Phoenix Contact",
    # WAGO
    "00:30:DE": "WAGO GmbH",
    # Beckhoff
    "00:01:05": "Beckhoff Automation",
    "00:12:87": "Beckhoff Automation",
    # Advantech
    "00:D0:C9": "Advantech Co. Ltd.",
    "00:60:64": "Advantech Co. Ltd.",
    # Moxa Technologies (ICS networking)
    "00:10:85": "Moxa Technologies",
    "00:90:E8": "Moxa Technologies",
    # Hirschmann / Belden
    "00:08:0F": "Hirschmann Automation",
    # Red Lion Controls
    "00:60:52": "Red Lion Controls",
    # HMS Networks (Anybus)
    "00:30:11": "HMS Networks",
    # Weidmüller
    "00:0D:F0": "Weidmuller Interface",
    # ProSoft Technology
    "00:20:4A": "ProSoft Technology",
}

# ── ODVA EtherNet/IP Vendor ID table ─────────────────────────────────────────
# Source: ODVA EtherNet/IP Vendor ID registry (partial — top ~40 ICS vendors)

_ODVA_VENDOR_TABLE: dict[int, str] = {
    1:    "Rockwell Automation / Allen-Bradley",
    2:    "Namco Controls Corp.",
    6:    "General Signal Corp.",
    7:    "SMC Corp.",
    10:   "Sumitomo Electric Industries",
    11:   "Digital Electronics Corp.",
    14:   "Belden Inc.",
    34:   "Eaton Corp.",
    40:   "Numatics Inc.",
    49:   "Turck Inc.",
    50:   "Pepperl+Fuchs GmbH",
    74:   "Siemens Energy & Automation",
    96:   "Hirschmann Automation",
    105:  "WAGO Corp.",
    108:  "Molex Inc.",
    134:  "Schneider Electric",
    137:  "Honeywell Inc.",
    152:  "Omron Corp.",
    161:  "Beckhoff Automation GmbH",
    168:  "Murr Elektronik GmbH",
    198:  "Phoenix Contact GmbH",
    218:  "Sick AG",
    242:  "Banner Engineering",
    286:  "Cognex Corp.",
    302:  "Emerson Network Power",
    312:  "ABB Stotz-Kontakt GmbH",
    343:  "Weidmuller Interface GmbH",
    432:  "Endress+Hauser Flowtec AG",
    492:  "HMS Industrial Networks AB",
    529:  "GE Fanuc Automation",
    596:  "Advantech Co. Ltd.",
    752:  "ProSoft Technology Inc.",
    826:  "Yaskawa Electric Corp.",
    998:  "Mitsubishi Electric Corp.",
    1093: "Red Lion Controls",
}

# ── BACnet Vendor ID table ────────────────────────────────────────────────────
# Source: ASHRAE BACnet Vendor ID registry (partial — top ~30 vendors)

_BACNET_VENDOR_TABLE: dict[int, str] = {
    0:    "ASHRAE",
    5:    "Johnson Controls Inc.",
    7:    "Siemens Building Technologies",
    8:    "Trane",
    10:   "Alerton / Honeywell",
    11:   "Delta Controls",
    13:   "Automated Logic Corp.",
    23:   "Carrier Corporation",
    36:   "Reliable Controls Corp.",
    42:   "Temco Controls Ltd.",
    55:   "Cimetrics Inc.",
    86:   "FieldServer Technologies",
    116:  "TAC (Schneider Electric)",
    118:  "Distech Controls",
    154:  "Echelon Corp.",
    186:  "KMC Controls",
    260:  "Bosch Security Systems",
    303:  "Computrols Inc.",
    328:  "Tridium Inc.",
    374:  "Alerton",
    390:  "Honeywell Building Solutions",
    406:  "Siemens Industry Inc.",
}


# ── Lookup helpers ────────────────────────────────────────────────────────────

def lookup_oui(mac: str) -> str:
    """Return ICS vendor name for a MAC address, or 'unknown'.

    Accepts AA:BB:CC:DD:EE:FF, AA-BB-CC, or AABBCC formats.
    """
    if not mac:
        return "unknown"
    mac = mac.upper().replace("-", ":").replace(".", ":")
    if ":" not in mac:
        mac = ":".join(mac[i:i+2] for i in range(0, min(len(mac), 12), 2))
    parts = mac.split(":")
    if len(parts) < 3:
        return "unknown"
    prefix = ":".join(parts[:3])
    return _OUI_TABLE.get(prefix, "unknown")


def lookup_odva_vendor(vendor_id: int) -> str:
    return _ODVA_VENDOR_TABLE.get(vendor_id, f"vendor_{vendor_id}")


def lookup_bacnet_vendor(vendor_id: int) -> str:
    return _BACNET_VENDOR_TABLE.get(vendor_id, f"bacnet_vendor_{vendor_id}")


# ── Passive: ARP cache reader ─────────────────────────────────────────────────

def get_mac_from_arp(ip: str) -> Optional[str]:
    """Read the MAC address for ip from the OS ARP cache. Sends zero packets.

    Returns None if the entry is missing or the cache is inaccessible.
    """
    # Linux fast path: parse kernel ARP table
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00":
                        return mac
    except OSError:
        pass
    # Fallback: run arp -n
    try:
        out = subprocess.check_output(
            ["arp", "-n", ip], stderr=subprocess.DEVNULL, timeout=3
        ).decode()
        m = re.search(
            r"([\dA-Fa-f]{2}[:\-][\dA-Fa-f]{2}[:\-][\dA-Fa-f]{2}"
            r"[:\-][\dA-Fa-f]{2}[:\-][\dA-Fa-f]{2}[:\-][\dA-Fa-f]{2})",
            out,
        )
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def fingerprint_from_oui(ip: str) -> FingerprintResult:
    """Passive OUI lookup — reads ARP cache, zero packets sent."""
    mac = get_mac_from_arp(ip)
    if mac is None:
        return FingerprintResult(confidence="none", method="oui_no_mac")
    vendor = lookup_oui(mac)
    if vendor == "unknown":
        return FingerprintResult(
            confidence="none", method="oui_unrecognized", extra={"mac": mac}
        )
    return FingerprintResult(
        vendor=vendor, confidence="low", method="oui", extra={"mac": mac}
    )


# ── EtherNet/IP List Identity parser ─────────────────────────────────────────

def parse_enip_list_identity(data: bytes) -> Optional[FingerprintResult]:
    """Parse an EtherNet/IP List Identity response (command 0x0063).

    data: full ENIP frame (24-byte header + CPF payload).
    Returns FingerprintResult(confidence='high') on success, None on parse error.
    """
    if len(data) < 26:
        return None
    cmd = struct.unpack_from('<H', data, 0)[0]
    if cmd != 0x0063:
        return None
    payload_len = struct.unpack_from('<H', data, 2)[0]
    if len(data) < 24 + payload_len or payload_len < 2:
        return None
    payload = data[24:24 + payload_len]
    item_count = struct.unpack_from('<H', payload, 0)[0]
    pos = 2
    for _ in range(item_count):
        if pos + 4 > len(payload):
            break
        item_type = struct.unpack_from('<H', payload, pos)[0]
        item_len  = struct.unpack_from('<H', payload, pos + 2)[0]
        item_data = payload[pos + 4: pos + 4 + item_len]
        pos += 4 + item_len
        if item_type != 0x000C:   # not Identity Item
            continue
        # Identity Item layout (all LE, starting at offset 0):
        # ProtocolVersion(2) SocketAddr(16) VendorID(2) DeviceType(2)
        # ProductCode(2) Revision(2) Status(2) SerialNumber(4)
        # ProductNameLen(1) ProductName(n) State(1)
        if len(item_data) < 33:
            continue
        try:
            vendor_id  = struct.unpack_from('<H', item_data, 18)[0]
            dev_type   = struct.unpack_from('<H', item_data, 20)[0]
            prod_code  = struct.unpack_from('<H', item_data, 22)[0]
            rev_major  = item_data[24]
            rev_minor  = item_data[25]
            serial_num = struct.unpack_from('<I', item_data, 28)[0]
            name_len   = item_data[32]
            name_raw   = item_data[33: 33 + name_len]
            product_name = name_raw.decode("ascii", errors="replace").strip()
        except (struct.error, IndexError):
            continue
        return FingerprintResult(
            vendor=lookup_odva_vendor(vendor_id),
            model=product_name or f"code_{prod_code}",
            firmware=f"{rev_major}.{rev_minor}",
            serial=f"{serial_num:08X}",
            confidence="high",
            method="enip_list_identity",
            extra={"vendor_id": vendor_id, "device_type": dev_type, "product_code": prod_code},
        )
    return None


# ── Modbus FC43 MEI Read Device Identification parser ─────────────────────────

def parse_modbus_fc43_mei(pdu: bytes) -> Optional[FingerprintResult]:
    """Parse a Modbus FC43 MEI Read Device Identification PDU (everything after MBAP).

    Returns FingerprintResult on success, None if the PDU is invalid or an exception.
    """
    if len(pdu) < 8:
        return None
    if pdu[0] & 0x80:   # exception response bit set
        return None
    if pdu[0] != 0x2B or pdu[1] != 0x0E:
        return None
    num_objs = pdu[6]
    pos = 7
    objects: dict[int, str] = {}
    for _ in range(num_objs):
        if pos + 2 > len(pdu):
            break
        obj_id  = pdu[pos]
        obj_len = pdu[pos + 1]
        if pos + 2 + obj_len > len(pdu):
            break
        obj_val = pdu[pos + 2: pos + 2 + obj_len].decode("ascii", errors="replace")
        objects[obj_id] = obj_val
        pos += 2 + obj_len
    if not objects:
        return None
    vendor   = objects.get(0x00, "unknown")
    model    = objects.get(0x01, "unknown")
    firmware = objects.get(0x02, "unknown")
    confidence = "high" if vendor != "unknown" and model != "unknown" else "medium"
    return FingerprintResult(
        vendor=vendor,
        model=model,
        firmware=firmware,
        confidence=confidence,
        method="modbus_fc43_mei",
        extra={k: v for k, v in objects.items() if k > 2},
    )


# ── BACnet I-Am APDU parser ───────────────────────────────────────────────────

def parse_bacnet_iam(apdu: bytes) -> Optional[dict]:
    """Parse a BACnet I-Am APDU. Returns {'device_id': int, 'vendor_id': int} or None.

    I-Am: PDU-type=0x10, Service=0x00
    Tags (in order): Object-Identifier, Max-APDU-Length, Segmentation, VendorID
    """
    if len(apdu) < 4 or apdu[0] != 0x10 or apdu[1] != 0x00:
        return None
    pos = 2
    device_id: Optional[int] = None
    vendor_id:  Optional[int] = None
    try:
        # Object Identifier (app tag 12 = 0xC4, 4 bytes)
        if pos + 5 <= len(apdu) and apdu[pos] == 0xC4:
            raw = struct.unpack_from('>I', apdu, pos + 1)[0]
            if (raw >> 22) & 0x3FF == 8:   # device object type
                device_id = raw & 0x3FFFFF
            pos += 5
        # Max-APDU-Length (app tag 2 = UINT, variable length)
        if pos < len(apdu) and (apdu[pos] & 0xF0) == 0x20:
            tag_len = apdu[pos] & 0x07
            pos += 1 + tag_len
        # Segmentation (app tag 9 = ENUMERATED, 1 byte)
        if pos < len(apdu) and (apdu[pos] & 0xF8) == 0x90:
            pos += 2
        # VendorID (app tag 2 = UINT)
        if pos < len(apdu):
            if apdu[pos] == 0x21 and pos + 2 <= len(apdu):
                vendor_id = apdu[pos + 1]
            elif apdu[pos] == 0x22 and pos + 3 <= len(apdu):
                vendor_id = struct.unpack_from('>H', apdu, pos + 1)[0]
    except (IndexError, struct.error):
        pass
    return {"device_id": device_id, "vendor_id": vendor_id}
