"""Unit tests for core/fingerprint.py — all offline, no network I/O."""

import struct
from unittest.mock import patch, MagicMock

import pytest

from core.fingerprint import (
    FingerprintResult,
    lookup_oui,
    lookup_odva_vendor,
    lookup_bacnet_vendor,
    get_mac_from_arp,
    fingerprint_from_oui,
    parse_enip_list_identity,
    parse_modbus_fc43_mei,
    parse_bacnet_iam,
)
from core.base_module import Device


# ── FingerprintResult ─────────────────────────────────────────────────────────

class TestFingerprintResult:
    def test_defaults(self):
        r = FingerprintResult()
        assert r.vendor == "unknown"
        assert r.model == "unknown"
        assert r.firmware == "unknown"
        assert r.serial == "unknown"
        assert r.confidence == "none"
        assert r.method == ""
        assert r.extra == {}

    def test_is_known_false_when_none(self):
        assert not FingerprintResult().is_known()

    def test_is_known_false_vendor_unknown(self):
        r = FingerprintResult(confidence="high")
        assert not r.is_known()

    def test_is_known_true(self):
        r = FingerprintResult(vendor="Siemens AG", confidence="high")
        assert r.is_known()

    def test_as_dict_keys(self):
        r = FingerprintResult(vendor="X", confidence="low")
        d = r.as_dict()
        for key in ("vendor", "model", "firmware", "serial", "confidence", "method"):
            assert key in d

    def test_extra_preserved(self):
        r = FingerprintResult(extra={"mac": "00:0E:8C:11:22:33"})
        assert r.extra["mac"] == "00:0E:8C:11:22:33"


# ── OUI lookup ────────────────────────────────────────────────────────────────

class TestLookupOui:
    def test_siemens_colon(self):
        assert lookup_oui("00:0E:8C:AA:BB:CC") == "Siemens AG"

    def test_rockwell_hyphen(self):
        # Normalize hyphen separators
        assert lookup_oui("00-00-BC-11-22-33") == "Rockwell Automation"

    def test_schneider(self):
        assert lookup_oui("00:30:64:00:00:00") == "Schneider Electric"

    def test_unknown_oui(self):
        assert lookup_oui("FF:FF:FF:00:00:00") == "unknown"

    def test_empty_string(self):
        assert lookup_oui("") == "unknown"

    def test_hms_networks_oui(self):
        # 00:30:11 belongs to HMS Networks (Anybus); a stale duplicate ABB entry
        # at this prefix was removed — verify the surviving mapping is HMS.
        assert lookup_oui("00:30:11:AA:BB:CC") == "HMS Networks"

    def test_no_duplicate_keys_in_table(self):
        from core.fingerprint import _OUI_TABLE
        keys = list(_OUI_TABLE.keys())
        assert len(keys) == len(set(keys)), "Duplicate OUI prefixes in _OUI_TABLE"

    def test_case_insensitive(self):
        assert lookup_oui("00:0e:8c:aa:bb:cc") == "Siemens AG"

    def test_no_separator(self):
        # 12 hex chars without separators
        assert lookup_oui("000E8CAABBCC") == "Siemens AG"

    def test_partial_mac_3_octets(self):
        # Only OUI part (3 octets)
        assert lookup_oui("00:0E:8C") == "Siemens AG"


# ── ODVA Vendor table ─────────────────────────────────────────────────────────

class TestLookupOdvaVendor:
    def test_rockwell(self):
        assert lookup_odva_vendor(1) == "Rockwell Automation / Allen-Bradley"

    def test_siemens(self):
        assert lookup_odva_vendor(74) == "Siemens Energy & Automation"

    def test_unknown_returns_placeholder(self):
        result = lookup_odva_vendor(99999)
        assert "99999" in result

    def test_beckhoff(self):
        assert "Beckhoff" in lookup_odva_vendor(161)


# ── BACnet Vendor table ───────────────────────────────────────────────────────

class TestLookupBacnetVendor:
    def test_johnson_controls(self):
        assert "Johnson" in lookup_bacnet_vendor(5)

    def test_siemens(self):
        assert "Siemens" in lookup_bacnet_vendor(7)

    def test_unknown(self):
        result = lookup_bacnet_vendor(9999)
        assert "9999" in result


# ── ARP cache reader ──────────────────────────────────────────────────────────

class TestGetMacFromArp:
    def test_reads_proc_net_arp(self, tmp_path):
        arp_file = tmp_path / "arp"
        arp_file.write_text(
            "IP address       HW type  Flags  HW address            Mask  Device\n"
            "192.168.1.10     0x1      0x2    00:0E:8C:AA:BB:CC     *     eth0\n"
            "192.168.1.20     0x1      0x2    00:00:00:00:00:00     *     eth0\n"
        )
        with patch("builtins.open", return_value=open(str(arp_file))):
            result = get_mac_from_arp("192.168.1.10")
        assert result == "00:0E:8C:AA:BB:CC"

    def test_skips_zero_mac(self, tmp_path):
        arp_file = tmp_path / "arp"
        arp_file.write_text(
            "IP address  HW type  Flags  HW address           Mask  Device\n"
            "10.0.0.1    0x1      0x2    00:00:00:00:00:00    *     eth0\n"
        )
        with patch("builtins.open", return_value=open(str(arp_file))):
            result = get_mac_from_arp("10.0.0.1")
        assert result is None

    def test_missing_ip_returns_none(self, tmp_path):
        arp_file = tmp_path / "arp"
        arp_file.write_text("IP address  HW type  Flags  HW address  Mask  Device\n")
        with patch("builtins.open", return_value=open(str(arp_file))):
            result = get_mac_from_arp("10.99.99.99")
        assert result is None

    def test_proc_unavailable_falls_back_to_arp_cmd(self):
        with patch("builtins.open", side_effect=OSError("no /proc")):
            with patch("subprocess.check_output", return_value=b"? (192.168.1.1) at 00:0E:8C:11:22:33 [ether]"):
                result = get_mac_from_arp("192.168.1.1")
        assert result == "00:0E:8C:11:22:33"

    def test_all_fail_returns_none(self):
        with patch("builtins.open", side_effect=OSError):
            with patch("subprocess.check_output", side_effect=Exception):
                assert get_mac_from_arp("1.2.3.4") is None


# ── fingerprint_from_oui ──────────────────────────────────────────────────────

class TestFingerprintFromOui:
    def test_known_vendor(self):
        with patch("core.fingerprint.get_mac_from_arp", return_value="00:0E:8C:AA:BB:CC"):
            r = fingerprint_from_oui("192.168.1.1")
        assert r.vendor == "Siemens AG"
        assert r.confidence == "low"
        assert r.method == "oui"
        assert r.extra["mac"] == "00:0E:8C:AA:BB:CC"

    def test_no_mac_returns_none_confidence(self):
        with patch("core.fingerprint.get_mac_from_arp", return_value=None):
            r = fingerprint_from_oui("1.2.3.4")
        assert r.confidence == "none"

    def test_unrecognized_oui(self):
        with patch("core.fingerprint.get_mac_from_arp", return_value="FF:FF:FF:AA:BB:CC"):
            r = fingerprint_from_oui("1.2.3.4")
        assert r.confidence == "none"
        assert r.extra.get("mac") == "FF:FF:FF:AA:BB:CC"


# ── parse_enip_list_identity ──────────────────────────────────────────────────

def _build_enip_list_identity(vendor_id=1, device_type=12, product_code=99,
                               rev_major=2, rev_minor=5, serial=0xDEADBEEF,
                               product_name=b"Allen-Bradley ControlLogix") -> bytes:
    """Build a minimal EtherNet/IP List Identity response."""
    name_len = len(product_name)
    # Identity Item (type=0x000C)
    identity_item = (
        struct.pack('<H', 1)          # ProtocolVersion
        + b'\x00' * 16               # SocketAddr (filler)
        + struct.pack('<H', vendor_id)
        + struct.pack('<H', device_type)
        + struct.pack('<H', product_code)
        + bytes([rev_major, rev_minor])  # Revision
        + struct.pack('<H', 0)        # Status
        + struct.pack('<I', serial)   # SerialNumber
        + bytes([name_len])
        + product_name
        + bytes([0x00])               # State
    )
    # CPF: item_count(2) + item_type(2) + item_len(2) + item_data
    cpf = (
        struct.pack('<H', 1)          # item count = 1
        + struct.pack('<H', 0x000C)  # Identity Item type
        + struct.pack('<H', len(identity_item))
        + identity_item
    )
    # ENIP 24-byte header: cmd=0x0063, length=len(cpf), rest zeros
    hdr = struct.pack('<HHI8sI',
                      0x0063,          # cmd
                      len(cpf),        # payload length
                      0,               # session
                      b'\x00' * 8,     # context
                      0,               # options
                      ) + b'\x00' * 4  # status
    # Fix: struct packs 8-byte context + 4-byte status = 12 bytes in second struct,
    # but the ENIP header is 24 bytes total. Repack properly.
    hdr = struct.pack('<HHII', 0x0063, len(cpf), 0, 0)   # 12 bytes
    hdr += b'\x00' * 8  # sender context 8 bytes
    hdr += struct.pack('<I', 0)  # options 4 bytes  → total 24 bytes
    return hdr + cpf


class TestParseEnipListIdentity:
    def test_basic_parse(self):
        data = _build_enip_list_identity()
        r = parse_enip_list_identity(data)
        assert r is not None
        assert r.confidence == "high"
        assert "Rockwell" in r.vendor
        assert "Allen-Bradley" in r.model or "ControlLogix" in r.model
        assert r.firmware == "2.5"
        assert r.serial == "DEADBEEF"

    def test_returns_none_on_short_data(self):
        assert parse_enip_list_identity(b'\x63\x00' + b'\x00' * 8) is None

    def test_returns_none_on_wrong_command(self):
        data = _build_enip_list_identity()
        bad = b'\x64\x00' + data[2:]   # change cmd to List Interfaces
        assert parse_enip_list_identity(bad) is None

    def test_unknown_vendor_id(self):
        data = _build_enip_list_identity(vendor_id=65535)
        r = parse_enip_list_identity(data)
        assert r is not None
        assert "65535" in r.vendor

    def test_model_name_extracted(self):
        data = _build_enip_list_identity(product_name=b"Test PLC Model X")
        r = parse_enip_list_identity(data)
        assert r is not None
        assert "Test PLC Model X" in r.model


# ── parse_modbus_fc43_mei ─────────────────────────────────────────────────────

def _build_fc43_mei_response(vendor="Siemens AG", product_code="S7-1200", revision="V4.2"):
    """Build a minimal FC43 MEI Read Device Identification response PDU."""
    objs = b''
    for obj_id, val in [(0x00, vendor), (0x01, product_code), (0x02, revision)]:
        enc = val.encode("ascii")
        objs += bytes([obj_id, len(enc)]) + enc
    # FC(1) MEI_type(1) ReadDevID(1) ConformityLevel(1) MoreFollows(1) NextObjId(1) NumObjs(1)
    hdr = bytes([0x2B, 0x0E, 0x01, 0x82, 0x00, 0x00, 3])
    return hdr + objs


class TestParseModbusFc43Mei:
    def test_basic_parse(self):
        pdu = _build_fc43_mei_response()
        r = parse_modbus_fc43_mei(pdu)
        assert r is not None
        assert r.vendor == "Siemens AG"
        assert r.model == "S7-1200"
        assert r.firmware == "V4.2"
        assert r.confidence == "high"

    def test_exception_response_returns_none(self):
        pdu = bytes([0xAB, 0x01])   # exception bit set
        assert parse_modbus_fc43_mei(pdu) is None

    def test_wrong_fc_returns_none(self):
        pdu = bytes([0x03, 0x0E]) + b'\x00' * 6
        assert parse_modbus_fc43_mei(pdu) is None

    def test_too_short_returns_none(self):
        assert parse_modbus_fc43_mei(b'\x2B\x0E') is None

    def test_empty_returns_none(self):
        assert parse_modbus_fc43_mei(b'') is None

    def test_partial_objects(self):
        # Only vendor name present → confidence=medium
        enc = b"ACME Corp"
        pdu = bytes([0x2B, 0x0E, 0x01, 0x82, 0x00, 0x00, 1, 0x00, len(enc)]) + enc
        r = parse_modbus_fc43_mei(pdu)
        assert r is not None
        assert r.vendor == "ACME Corp"
        assert r.model == "unknown"
        assert r.confidence == "medium"


# ── parse_bacnet_iam ──────────────────────────────────────────────────────────

def _build_bacnet_iam(device_id=1234, vendor_id=7):
    """Build a minimal BACnet I-Am APDU (PDU-type=0x10, Service=0x00)."""
    # Object Identifier (app tag 12, 4 bytes): device type (8) << 22 | device_id
    obj_raw = (8 << 22) | (device_id & 0x3FFFFF)
    apdu = bytes([0x10, 0x00])
    apdu += bytes([0xC4]) + struct.pack('>I', obj_raw)   # Object ID
    apdu += bytes([0x21, 0x05])                          # Max APDU = 5 (1476 bytes)
    apdu += bytes([0x91, 0x03])                          # Segmentation = 3 (no-segmentation)
    apdu += bytes([0x22]) + struct.pack('>H', vendor_id) # VendorID (2-byte)
    return apdu


class TestParseBacnetIam:
    def test_device_id_extracted(self):
        apdu = _build_bacnet_iam(device_id=5678, vendor_id=7)
        result = parse_bacnet_iam(apdu)
        assert result is not None
        assert result["device_id"] == 5678

    def test_vendor_id_extracted(self):
        apdu = _build_bacnet_iam(device_id=100, vendor_id=7)
        result = parse_bacnet_iam(apdu)
        assert result is not None
        assert result["vendor_id"] == 7

    def test_wrong_pdu_type_returns_none(self):
        apdu = bytes([0x00, 0x00])   # Confirmed request, not unconfirmed
        assert parse_bacnet_iam(apdu) is None

    def test_wrong_service_returns_none(self):
        apdu = bytes([0x10, 0x08])   # Who-Is, not I-Am
        assert parse_bacnet_iam(apdu) is None

    def test_empty_returns_none(self):
        assert parse_bacnet_iam(b'') is None

    def test_too_short_returns_none(self):
        assert parse_bacnet_iam(bytes([0x10, 0x00])) is None


# ── Device model field ────────────────────────────────────────────────────────

class TestDeviceModelField:
    def test_device_has_model_field(self):
        d = Device("192.168.1.1", 502, "modbus")
        assert hasattr(d, "model")
        assert d.model == "unknown"

    def test_device_model_settable(self):
        d = Device("192.168.1.1", 502, "modbus")
        d.model = "S7-1200"
        assert d.model == "S7-1200"


# ── FuzzModule fingerprint default ────────────────────────────────────────────

class TestFuzzModuleFingerprint:
    def test_default_fingerprint_returns_result(self):
        from protocols.modbus.fuzzer import ModbusFuzzer
        dev = Device("127.0.0.1", 502, "modbus")
        fuzzer = ModbusFuzzer(target=dev, logger=None, delay=0)
        with patch("core.fingerprint.get_mac_from_arp", return_value=None):
            r = fuzzer.fingerprint(active=False)
        assert isinstance(r, FingerprintResult)

    def test_passive_returns_oui_result(self):
        from protocols.ethernetip.fuzzer import EthernetIpFuzzer
        dev = Device("127.0.0.1", 44818, "ethernetip")
        fuzzer = EthernetIpFuzzer(target=dev, logger=None, delay=0)
        with patch("core.fingerprint.get_mac_from_arp", return_value="00:00:BC:AA:BB:CC"):
            r = fuzzer.fingerprint(active=False)
        assert r.confidence in ("low", "medium", "high")
        assert "Rockwell" in r.vendor
