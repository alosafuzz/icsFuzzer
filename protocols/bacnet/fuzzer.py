"""BACnet/IP fuzzer — BVLL/NPDU/APDU over UDP port 47808."""

import socket
import struct
import time
import math
from typing import Optional

from core.base_module import (
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

# ---------------------------------------------------------------------------
# Protocol-specific category names
# ---------------------------------------------------------------------------

CATEGORY_READ_WRITE_PROP = "read_write_property"
CATEGORY_WHOIS_RANGE     = "whois_range"
CATEGORY_COV_FLOOD       = "cov_subscription_flood"
CATEGORY_BBMD            = "bbmd_forwarding"

# ---------------------------------------------------------------------------
# Object type constants
# ---------------------------------------------------------------------------

_OBJ_ANALOG_INPUT  = 0
_OBJ_ANALOG_OUTPUT = 1
_OBJ_ANALOG_VALUE  = 2
_OBJ_BINARY_INPUT  = 3
_OBJ_BINARY_OUTPUT = 4
_OBJ_BINARY_VALUE  = 5
_OBJ_DEVICE        = 8
_OBJ_FILE          = 10
_OBJ_MULTI_STATE_I = 16
_OBJ_MULTI_STATE_O = 17

# ---------------------------------------------------------------------------
# Property ID constants
# ---------------------------------------------------------------------------

_PROP_DESCRIPTION        = 28
_PROP_FIRMWARE_REVISION  = 44
_PROP_APDU_TIMEOUT       = 66
_PROP_MODEL_NAME         = 70
_PROP_APDU_RETRIES       = 73
_PROP_OBJECT_IDENTIFIER  = 75
_PROP_OBJECT_NAME        = 77
_PROP_OBJECT_TYPE        = 79
_PROP_PRESENT_VALUE      = 85
_PROP_UNITS              = 103
_PROP_SEGMENTATION       = 107
_PROP_SYSTEM_STATUS      = 112
_PROP_VENDOR_ID          = 117
_PROP_VENDOR_NAME        = 121
_PROP_MAX_APDU           = 126

# ---------------------------------------------------------------------------
# Service code constants
# ---------------------------------------------------------------------------

_SVC_SUBSCRIBE_COV      = 0x05
_SVC_READ_PROPERTY      = 0x0C
_SVC_READ_PROP_MULTIPLE = 0x0E
_SVC_WRITE_PROPERTY     = 0x0F
_SVC_DEVICE_COMM_CTRL   = 0x11
_SVC_REINITIALIZE       = 0x14

_USVC_I_AM              = 0x00
_USVC_I_HAVE            = 0x01
_USVC_UNCNF_COV_NOTIF   = 0x02
_USVC_WHO_HAS           = 0x06
_USVC_WHO_IS            = 0x08

# ---------------------------------------------------------------------------
# BVLL function code constants
# ---------------------------------------------------------------------------

_BVLL_RESULT            = 0x00
_BVLL_WRITE_BDT         = 0x01
_BVLL_READ_BDT          = 0x02
_BVLL_READ_BDT_ACK      = 0x03
_BVLL_FORWARDED_NPDU    = 0x04
_BVLL_REGISTER_FD       = 0x05
_BVLL_READ_FDT          = 0x06
_BVLL_READ_FDT_ACK      = 0x07
_BVLL_DELETE_FDT_ENTRY  = 0x08
_BVLL_DISTRIB_BCAST     = 0x09
_BVLL_UNICAST           = 0x0A
_BVLL_BROADCAST         = 0x0B
_BVLL_SECURE            = 0x0C

# Default device parameters used in packets
_DEVICE_INSTANCE  = 1234
_DEVICE_VENDOR_ID = 0x1234

# ---------------------------------------------------------------------------
# Wire builders — BVLL / NPDU
# ---------------------------------------------------------------------------

def _bvll(func: int, data: bytes) -> bytes:
    """BVLL header: type=0x81, func, big-endian total length, then data."""
    return bytes([0x81, func]) + struct.pack('>H', 4 + len(data)) + data


def _npdu(ctrl: int = 0x04) -> bytes:
    """NPDU: version=0x01, control byte."""
    return bytes([0x01, ctrl])


def _bacnet_pkt(ctrl: int, apdu: bytes, func: int = _BVLL_UNICAST) -> bytes:
    """Full BACnet/IP packet: BVLL + NPDU + APDU."""
    return _bvll(func, _npdu(ctrl) + apdu)

# ---------------------------------------------------------------------------
# Wire builders — APDU
# ---------------------------------------------------------------------------

def _apdu_confirmed(service: int, invoke_id: int, data: bytes = b'',
                    max_apdu: int = 0x05) -> bytes:
    """Confirmed-Request APDU (PDU type 0x00)."""
    return bytes([0x00, max_apdu, invoke_id & 0xFF, service]) + data


def _apdu_unconfirmed(service: int, data: bytes = b'') -> bytes:
    """Unconfirmed-Request APDU (PDU type 0x10)."""
    return bytes([0x10, service]) + data

# ---------------------------------------------------------------------------
# Wire builders — BACnet tag helpers
# ---------------------------------------------------------------------------

def _ctx_tag(ctx: int, data: bytes) -> bytes:
    """Context-tagged primitive (ctx 0-14, data 0-4 bytes)."""
    n = len(data)
    if n > 4:
        return bytes([(ctx << 4) | 0x08 | 5, n]) + data
    return bytes([(ctx << 4) | 0x08 | n]) + data


def _ctx_open(ctx: int) -> bytes:
    return bytes([(ctx << 4) | 0x08 | 6])


def _ctx_close(ctx: int) -> bytes:
    return bytes([(ctx << 4) | 0x08 | 7])


def _app_unsigned(n: int) -> bytes:
    """Application-tagged unsigned integer (minimum length)."""
    if n == 0:
        return bytes([0x21, 0x00])
    if n <= 0xFF:
        return bytes([0x21, n])
    if n <= 0xFFFF:
        return bytes([0x22]) + struct.pack('>H', n)
    if n <= 0xFFFFFF:
        return bytes([0x23]) + n.to_bytes(3, 'big')
    return bytes([0x24]) + struct.pack('>I', n)


def _app_real(f: float) -> bytes:
    """Application-tagged Real (float32)."""
    return bytes([0x44]) + struct.pack('>f', f)


def _app_enum(n: int) -> bytes:
    """Application-tagged Enumerated (1 byte)."""
    return bytes([0x91, n & 0xFF])


def _app_bool(b: bool) -> bytes:
    """Application-tagged Boolean."""
    return bytes([0x11, 0x01 if b else 0x00])


def _app_obj_id(obj_type: int, instance: int) -> bytes:
    """Application-tagged Object Identifier (4 bytes)."""
    return bytes([0xC4]) + struct.pack('>I', (obj_type << 22) | (instance & 0x3FFFFF))


def _app_char_string(s: str) -> bytes:
    """Application-tagged Character String (UTF-8 encoding=0x00)."""
    enc   = s.encode('utf-8')
    total = 1 + len(enc)          # encoding indicator byte + string bytes
    if total <= 4:
        return bytes([0x75, total, 0x00]) + enc
    if total < 254:
        return bytes([0x75, 0x05, total, 0x00]) + enc
    if total < 65536:
        return bytes([0x75, 0x05, 254]) + struct.pack('>H', total) + bytes([0x00]) + enc
    return bytes([0x75, 0x05, 255]) + struct.pack('>I', total) + bytes([0x00]) + enc


def _obj_id_bytes(obj_type: int, instance: int) -> bytes:
    return struct.pack('>I', (obj_type << 22) | (instance & 0x3FFFFF))


def _prop_ctx_tag(ctx: int, prop_id: int) -> bytes:
    """Context-tagged property identifier (minimum length)."""
    if prop_id <= 0xFF:
        return bytes([(ctx << 4) | 0x08 | 1, prop_id])
    return bytes([(ctx << 4) | 0x08 | 2]) + struct.pack('>H', prop_id)

# ---------------------------------------------------------------------------
# Wire builders — CIP service packets
# ---------------------------------------------------------------------------

def _read_property(obj_type: int, instance: int, prop_id: int,
                   invoke_id: int = 1, array_index: Optional[int] = None) -> bytes:
    """ReadProperty-Request (confirmed service 0x0C)."""
    body = _ctx_tag(0, _obj_id_bytes(obj_type, instance))
    body += _prop_ctx_tag(1, prop_id)
    if array_index is not None:
        body += _ctx_tag(2, struct.pack('>I', array_index))
    return _bacnet_pkt(0x00, _apdu_confirmed(_SVC_READ_PROPERTY, invoke_id, body))


def _write_property(obj_type: int, instance: int, prop_id: int,
                    value: bytes, invoke_id: int = 1,
                    priority: Optional[int] = None) -> bytes:
    """WriteProperty-Request (confirmed service 0x0F)."""
    body = _ctx_tag(0, _obj_id_bytes(obj_type, instance))
    body += _prop_ctx_tag(1, prop_id)
    body += _ctx_open(3)
    body += value
    body += _ctx_close(3)
    if priority is not None:
        body += _ctx_tag(4, bytes([priority & 0xFF]))
    return _bacnet_pkt(0x00, _apdu_confirmed(_SVC_WRITE_PROPERTY, invoke_id, body))


def _who_is(low: Optional[int] = None, high: Optional[int] = None) -> bytes:
    """Who-Is-Request (unconfirmed service 0x08). No range = discover all."""
    body = b''
    if low is not None and high is not None:
        body = _ctx_tag(0, struct.pack('>I', low & 0xFFFFFFFF))
        body += _ctx_tag(1, struct.pack('>I', high & 0xFFFFFFFF))
    return _bacnet_pkt(0x00, _apdu_unconfirmed(_USVC_WHO_IS, body))


def _i_am(device_instance: int = _DEVICE_INSTANCE,
          max_apdu: int = 1476, segmentation: int = 3,
          vendor_id: int = _DEVICE_VENDOR_ID) -> bytes:
    """I-Am-Request (unconfirmed service 0x00)."""
    body  = _app_obj_id(_OBJ_DEVICE, device_instance)
    body += _app_unsigned(max_apdu)
    body += _app_enum(segmentation)
    body += bytes([0x22]) + struct.pack('>H', vendor_id)
    return _bacnet_pkt(0x00, _apdu_unconfirmed(_USVC_I_AM, body))


def _who_has(obj_type: int, instance: int) -> bytes:
    """Who-Has-Request (unconfirmed service 0x06) by object ID."""
    body = _ctx_open(3)
    body += _app_obj_id(obj_type, instance)
    body += _ctx_close(3)
    return _bacnet_pkt(0x00, _apdu_unconfirmed(_USVC_WHO_HAS, body))


def _subscribe_cov(proc_id: int, obj_type: int, instance: int,
                   confirmed: bool = False, lifetime: int = 60,
                   invoke_id: int = 1) -> bytes:
    """SubscribeCOV-Request (confirmed service 0x05)."""
    body  = _ctx_tag(0, bytes([proc_id & 0xFF]))
    body += _ctx_tag(1, _obj_id_bytes(obj_type, instance))
    body += _ctx_tag(2, bytes([0x01 if confirmed else 0x00]))
    body += _ctx_tag(3, struct.pack('>I', lifetime & 0xFFFFFFFF))
    return _bacnet_pkt(0x00, _apdu_confirmed(_SVC_SUBSCRIBE_COV, invoke_id, body))


def _cancel_cov(proc_id: int, obj_type: int, instance: int,
                invoke_id: int = 1) -> bytes:
    """SubscribeCOV with lifetime=0 = cancel subscription."""
    body  = _ctx_tag(0, bytes([proc_id & 0xFF]))
    body += _ctx_tag(1, _obj_id_bytes(obj_type, instance))
    return _bacnet_pkt(0x00, _apdu_confirmed(_SVC_SUBSCRIBE_COV, invoke_id, body))


def _uncnf_cov_notification(proc_id: int, obj_type: int,
                             instance: int, prop_id: int,
                             value: bytes) -> bytes:
    """UnconfirmedCOVNotification (unconfirmed service 0x02)."""
    body  = _ctx_tag(0, bytes([proc_id & 0xFF]))
    body += _ctx_tag(1, _obj_id_bytes(_OBJ_DEVICE, _DEVICE_INSTANCE))
    body += _ctx_tag(2, _obj_id_bytes(obj_type, instance))
    body += _ctx_tag(3, struct.pack('>I', 600))   # time-remaining
    body += _ctx_open(4)
    inner  = _ctx_open(0)
    inner += _prop_ctx_tag(0, prop_id)
    inner += _ctx_open(2)
    inner += value
    inner += _ctx_close(2)
    inner += _ctx_close(0)
    body += inner
    body += _ctx_close(4)
    return _bacnet_pkt(0x00, _apdu_unconfirmed(_USVC_UNCNF_COV_NOTIF, body))


def _device_comm_ctrl(enable_disable: int, invoke_id: int = 1) -> bytes:
    """DeviceCommunicationControl-Request (confirmed service 0x11)."""
    body = _ctx_tag(1, bytes([enable_disable & 0xFF]))
    return _bacnet_pkt(0x00, _apdu_confirmed(_SVC_DEVICE_COMM_CTRL, invoke_id, body))


def _reinitialize_device(state: int = 0, invoke_id: int = 1) -> bytes:
    """ReinitializeDevice-Request (confirmed service 0x14)."""
    body = _ctx_tag(0, bytes([state & 0xFF]))
    return _bacnet_pkt(0x00, _apdu_confirmed(_SVC_REINITIALIZE, invoke_id, body))


def _register_foreign_device(ttl: int = 600) -> bytes:
    """BBMD Register-Foreign-Device (BVLL func 0x05, TTL in seconds)."""
    return _bvll(_BVLL_REGISTER_FD, struct.pack('>H', ttl & 0xFFFF))


def _read_bdt() -> bytes:
    """BBMD Read-Broadcast-Distribution-Table (BVLL func 0x02)."""
    return _bvll(_BVLL_READ_BDT, b'')


def _read_fdt() -> bytes:
    """BBMD Read-Foreign-Device-Table (BVLL func 0x06)."""
    return _bvll(_BVLL_READ_FDT, b'')


def _forwarded_npdu(orig_ip: bytes, orig_port: int, apdu: bytes) -> bytes:
    """BBMD Forwarded-NPDU (BVLL func 0x04): 6-byte originator + NPDU + APDU."""
    orig_addr = orig_ip + struct.pack('>H', orig_port)
    return _bvll(_BVLL_FORWARDED_NPDU, orig_addr + _npdu(0x00) + apdu)


def _distribute_broadcast(apdu: bytes) -> bytes:
    """Distribute-Broadcast-To-Network (BVLL func 0x09): NPDU + APDU."""
    return _bvll(_BVLL_DISTRIB_BCAST, _npdu(0x00) + apdu)

# ---------------------------------------------------------------------------
# Response parser helpers
# ---------------------------------------------------------------------------

def _apdu_type(data: bytes) -> int:
    """Return upper nibble of APDU first byte (PDU type)."""
    return data[0] & 0xF0


def _extract_bacnet_string(frame: bytes) -> Optional[str]:
    """Extract the first BACnet character string value from a raw UDP frame.

    Searches for BACnet application-tag-7 (character string) patterns.
    Returns the string if found, None otherwise.
    """
    # Skip BVLL (4 bytes) + NPDU (2 bytes) + APDU confirmed-ACK header (3 bytes) = 9
    if len(frame) < 10:
        return None
    data = frame[9:]
    pos = 0
    while pos < len(data):
        tag = data[pos]
        tag_num = (tag >> 4) & 0x0F
        lvt = tag & 0x07
        # Application tag 7 = character string
        if (tag & 0x08) == 0 and tag_num == 7:
            pos += 1
            # Decode length
            if lvt < 5:
                str_len = lvt
            elif lvt == 5 and pos < len(data):
                str_len = data[pos]
                pos += 1
            else:
                break
            if pos + str_len > len(data) or str_len < 2:
                break
            encoding = data[pos]    # 0 = UTF-8 (ANSI X3.4)
            raw = data[pos + 1: pos + str_len]
            try:
                if encoding == 0:
                    return raw.decode("utf-8", errors="replace").strip()
                return raw.decode("latin-1", errors="replace").strip()
            except Exception:
                return None
        else:
            # Skip this tag
            pos += 1
            if lvt < 5:
                pos += lvt
            elif lvt == 5 and pos < len(data):
                ext_len = data[pos]
                pos += 1 + ext_len
            else:
                break
    return None


def _skip_npdu(data: bytes, offset: int) -> int:
    """Return offset to APDU after NPDU. Raises if truncated."""
    ctrl = data[offset + 1]
    pos  = offset + 2
    if ctrl & 0x04:   # DEST specifier
        dlen = data[pos + 2]
        pos += 3 + dlen + 1
    if ctrl & 0x02:   # SRC specifier
        slen = data[pos + 2]
        pos += 3 + slen
    return pos

# ---------------------------------------------------------------------------
# BacnetFuzzer
# ---------------------------------------------------------------------------

class BacnetFuzzer(FuzzModule):
    """BACnet/IP fuzzer — UDP, no session handshake required."""

    PROTOCOL_NAME  = "bacnet"
    DEFAULT_PORT   = 47808
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_SEQUENCE,
        CATEGORY_STATE_MACHINE,
        CATEGORY_READ_WRITE_PROP,
        CATEGORY_WHOIS_RANGE,
        CATEGORY_COV_FLOOD,
        CATEGORY_BBMD,
    ]

    _RECV_TIMEOUT = 2.0

    def __init__(self, target: Device, logger, delay: float = 0.0, seeds=None):
        super().__init__(target=target, logger=logger, delay=delay, seeds=seeds)
        self._sock: Optional[socket.socket] = None
        self._target_addr: Optional[tuple] = None

    # ------------------------------------------------------------------
    # Connection management (UDP — no handshake)
    # ------------------------------------------------------------------

    def connect(self, target: Optional[Device] = None) -> None:
        t = target or self.target
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self._RECV_TIMEOUT)
        self._target_addr = (t.ip, t.port)

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._target_addr = None

    def _reconnect(self) -> None:
        self.close()
        self.connect()

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError("BACnet passive discovery requires scapy + CAP_NET_RAW.")

    def fingerprint(self, active: bool = True) -> "FingerprintResult":
        """BACnet fingerprint.

        Passive: OUI lookup from ARP cache.
        Active:  send Who-Is (unicast) and wait for I-Am, then send three
                 Read Property requests for Vendor-Name (121), Model-Name (70),
                 and Firmware-Revision (44) on the responding device object.
        """
        from core.fingerprint import (
            FingerprintResult, fingerprint_from_oui,
            lookup_bacnet_vendor, parse_bacnet_iam,
        )

        oui_result = fingerprint_from_oui(self.target.ip)
        if not active:
            return oui_result

        target_addr = (self.target.ip, self.target.port)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            # Who-Is unicast to the target
            s.sendto(_who_is(), target_addr)
            try:
                data, _ = s.recvfrom(1024)
            except socket.timeout:
                s.close()
                return oui_result

            # Parse I-Am APDU (strip BVLL=4 + NPDU=2 = 6 bytes)
            if len(data) < 8:
                s.close()
                return oui_result
            iam_info = parse_bacnet_iam(data[6:])
            device_id = (iam_info or {}).get("device_id")
            raw_vendor_id = (iam_info or {}).get("vendor_id")
            if device_id is None:
                s.close()
                return oui_result

            # Read Vendor-Name, Model-Name, Firmware-Revision
            props: dict[str, str] = {}
            prop_map = {
                "vendor_name": _PROP_VENDOR_NAME,
                "model_name":  _PROP_MODEL_NAME,
                "firmware":    _PROP_FIRMWARE_REVISION,
            }
            for key, prop_id in prop_map.items():
                expected_iid = prop_id & 0xFF
                pkt = _read_property(_OBJ_DEVICE, device_id, prop_id, invoke_id=expected_iid)
                s.sendto(pkt, target_addr)
                try:
                    resp, _ = s.recvfrom(1024)
                    # Confirmed-ACK: PDU type at resp[9], invoke_id at resp[10].
                    # Discard stale UDP responses whose invoke_id doesn't match.
                    if len(resp) <= 10 or resp[10] != expected_iid:
                        continue
                    txt = _extract_bacnet_string(resp)
                    if txt:
                        props[key] = txt
                except socket.timeout:
                    pass

            s.close()
        except OSError:
            return oui_result

        vendor_name = props.get("vendor_name") or (
            lookup_bacnet_vendor(raw_vendor_id) if raw_vendor_id is not None else "unknown"
        )
        model    = props.get("model_name", "unknown")
        firmware = props.get("firmware", "unknown")
        confidence = "high" if (vendor_name != "unknown" and model != "unknown") else "medium"
        result = FingerprintResult(
            vendor=vendor_name,
            model=model,
            firmware=firmware,
            confidence=confidence,
            method="bacnet_who_is_read_property",
            extra={"device_id": device_id, "vendor_id": raw_vendor_id},
        )
        if oui_result.is_known():
            result.extra["oui_vendor"] = oui_result.vendor
        return result

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError("call connect() before replay_payload()")
        self._sock.sendto(payload, self._target_addr)
        try:
            data, _ = self._sock.recvfrom(65535)
            return data
        except socket.timeout:
            return None

    # ------------------------------------------------------------------
    # generate_cases
    # ------------------------------------------------------------------

    def generate_cases(self, categories=None):
        cats = self._resolve_categories(categories)
        cases = []
        for cat in cats:
            if cat == CATEGORY_BOUNDARY:
                cases.extend(self._gen_boundary())
            elif cat == CATEGORY_BINARY_CORRUPTION:
                cases.extend(self._gen_binary_corruption())
            elif cat == CATEGORY_SEQUENCE:
                cases.extend(self._gen_sequence())
            elif cat == CATEGORY_STATE_MACHINE:
                cases.extend(self._gen_state_machine())
            elif cat == CATEGORY_READ_WRITE_PROP:
                cases.extend(self._gen_read_write_property())
            elif cat == CATEGORY_WHOIS_RANGE:
                cases.extend(self._gen_whois_range())
            elif cat == CATEGORY_COV_FLOOD:
                cases.extend(self._gen_cov_flood())
            elif cat == CATEGORY_BBMD:
                cases.extend(self._gen_bbmd())
        return cases

    def _case(self, cat, desc, payload):
        return (self._next_id(), cat, desc, payload)

    # ------------------------------------------------------------------
    # Category generators
    # ------------------------------------------------------------------

    def _gen_boundary(self):
        C = CATEGORY_BOUNDARY
        cases = []
        # Who-Is variants
        cases.append(self._case(C, "Who-Is broadcast (no range)", _who_is()))
        cases.append(self._case(C, "Who-Is full range 0-4194303",
                                _who_is(0, 4194303)))
        cases.append(self._case(C, "Who-Is single device instance=1234",
                                _who_is(1234, 1234)))
        # I-Am (fuzzer announces itself)
        cases.append(self._case(C, "I-Am device=1234 vendor=0x1234", _i_am()))
        cases.append(self._case(C, "I-Am max-apdu=50 (minimum)", _i_am(max_apdu=50)))
        cases.append(self._case(C, "I-Am segmentation=0 (both)", _i_am(segmentation=0)))
        # Who-Has
        cases.append(self._case(C, "Who-Has Device instance=1234",
                                _who_has(_OBJ_DEVICE, 1234)))
        cases.append(self._case(C, "Who-Has Analog-Input instance=0",
                                _who_has(_OBJ_ANALOG_INPUT, 0)))
        # ReadProperty — Device object properties
        cases.append(self._case(C, "ReadProperty Device Object_Identifier",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_IDENTIFIER, 1)))
        cases.append(self._case(C, "ReadProperty Device Object_Name",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 2)))
        cases.append(self._case(C, "ReadProperty Device Object_Type",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_TYPE, 3)))
        cases.append(self._case(C, "ReadProperty Device Vendor_Identifier",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_VENDOR_ID, 4)))
        cases.append(self._case(C, "ReadProperty Device Vendor_Name",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_VENDOR_NAME, 5)))
        cases.append(self._case(C, "ReadProperty Device Model_Name",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_MODEL_NAME, 6)))
        cases.append(self._case(C, "ReadProperty Device System_Status",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_SYSTEM_STATUS, 7)))
        cases.append(self._case(C, "ReadProperty Device Max_APDU_Length",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_MAX_APDU, 8)))
        # ReadProperty — other object types
        cases.append(self._case(C, "ReadProperty Analog-Input 0 Present_Value",
                                _read_property(_OBJ_ANALOG_INPUT, 0, _PROP_PRESENT_VALUE, 9)))
        cases.append(self._case(C, "ReadProperty Analog-Value 0 Present_Value",
                                _read_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE, 10)))
        cases.append(self._case(C, "ReadProperty Binary-Value 0 Present_Value",
                                _read_property(_OBJ_BINARY_VALUE, 0, _PROP_PRESENT_VALUE, 11)))
        # WriteProperty — safe writes
        cases.append(self._case(C, "WriteProperty Analog-Value 0 Present_Value=1.0",
                                _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                                                _app_real(1.0), 12)))
        cases.append(self._case(C, "WriteProperty Binary-Value 0 Present_Value=false",
                                _write_property(_OBJ_BINARY_VALUE, 0, _PROP_PRESENT_VALUE,
                                                _app_bool(False), 13)))
        # SubscribeCOV
        cases.append(self._case(C, "SubscribeCOV Analog-Input 0 (proc_id=1)",
                                _subscribe_cov(1, _OBJ_ANALOG_INPUT, 0, invoke_id=14)))
        cases.append(self._case(C, "SubscribeCOV Binary-Value 0 (proc_id=2)",
                                _subscribe_cov(2, _OBJ_BINARY_VALUE, 0, invoke_id=15)))
        # BBMD queries
        cases.append(self._case(C, "Read-BDT (BBMD broadcast table)", _read_bdt()))
        cases.append(self._case(C, "Read-FDT (BBMD foreign device table)", _read_fdt()))
        # Register-Foreign-Device
        cases.append(self._case(C, "Register-Foreign-Device TTL=600s",
                                _register_foreign_device(600)))
        # Invoke ID boundary values
        cases.append(self._case(C, "ReadProperty invoke_id=0 (minimum)",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 0)))
        cases.append(self._case(C, "ReadProperty invoke_id=255 (maximum)",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 255)))
        # Max legal instance
        cases.append(self._case(C, "ReadProperty Device instance=4194302 (max-1)",
                                _read_property(_OBJ_DEVICE, 4194302, _PROP_OBJECT_NAME, 16)))
        # NPDU ctrl variants
        cases.append(self._case(C, "ReadProperty NPDU priority=LifeSafety",
                                _bvll(_BVLL_UNICAST,
                                      bytes([0x01, 0x44]) +
                                      _apdu_confirmed(_SVC_READ_PROPERTY, 17,
                                                      _ctx_tag(0, _obj_id_bytes(_OBJ_DEVICE, 1234)) +
                                                      _prop_ctx_tag(1, _PROP_OBJECT_NAME)))))
        return cases

    def _gen_binary_corruption(self):
        C = CATEGORY_BINARY_CORRUPTION
        cases = []

        # Empty and minimal
        cases.append(self._case(C, "Empty payload (0 bytes)", b''))
        cases.append(self._case(C, "Single byte 0x81", b'\x81'))
        cases.append(self._case(C, "All-zero 6 bytes", b'\x00' * 6))
        cases.append(self._case(C, "All-zero 24 bytes", b'\x00' * 24))
        cases.append(self._case(C, "All-0xFF 6 bytes", b'\xFF' * 6))

        # Wrong BVLL type byte
        for wrong_type in (0x00, 0x80, 0x82, 0xFF):
            base = _who_is()
            payload = bytes([wrong_type]) + base[1:]
            cases.append(self._case(C, f"BVLL type=0x{wrong_type:02X} (not 0x81)", payload))

        # Wrong BVLL function codes (not standard)
        for func in (0x0D, 0x0E, 0x0F, 0x10, 0x50, 0xFF):
            payload = bytes([0x81, func]) + struct.pack('>H', 6) + _npdu()
            cases.append(self._case(C, f"BVLL func=0x{func:02X} (undefined)", payload))

        # Length field wrong
        base = _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 1)
        # Claims more than actual
        wrong_len = bytes([0x81, 0x0A]) + struct.pack('>H', 0xFFFF) + base[4:]
        cases.append(self._case(C, "BVLL length=0xFFFF (far more than actual)", wrong_len))
        # Claims fewer bytes than actual
        short_len = bytes([0x81, 0x0A]) + struct.pack('>H', 3) + base[4:]
        cases.append(self._case(C, "BVLL length=3 (less than header size)", short_len))
        # Claims zero
        zero_len = bytes([0x81, 0x0A]) + struct.pack('>H', 0) + base[4:]
        cases.append(self._case(C, "BVLL length=0", zero_len))

        # Truncated at each byte position 0-23
        full = _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 1)
        for i in range(1, min(24, len(full))):
            cases.append(self._case(C, f"Truncated at byte {i} (of {len(full)}-byte packet)",
                                    full[:i]))

        # NPDU version wrong
        for ver in (0x00, 0x02, 0x7F, 0xFF):
            apdu = _apdu_confirmed(_SVC_READ_PROPERTY, 1,
                                   _ctx_tag(0, _obj_id_bytes(_OBJ_DEVICE, 1234)) +
                                   _prop_ctx_tag(1, _PROP_OBJECT_NAME))
            payload = _bvll(_BVLL_UNICAST, bytes([ver, 0x04]) + apdu)
            cases.append(self._case(C, f"NPDU version=0x{ver:02X} (not 0x01)", payload))

        # Random garbage
        cases.append(self._case(C, "Random garbage 64 bytes",
                                bytes(range(64))))
        cases.append(self._case(C, "Repeated 0xAA 24 bytes", b'\xAA' * 24))

        return cases

    def _gen_sequence(self):
        C = CATEGORY_SEQUENCE
        cases = []

        # Duplicate invoke IDs
        pkt = _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 42)
        cases.append(self._case(C, "ReadProperty invoke_id=42 (first)", pkt))
        cases.append(self._case(C, "ReadProperty invoke_id=42 (duplicate)", pkt))

        # Cycling invoke IDs 0x00 → 0xFF → wrap
        for iid in (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF):
            cases.append(self._case(C, f"ReadProperty invoke_id=0x{iid:02X}",
                                    _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, iid)))

        # Mixed confirmed + unconfirmed in sequence
        cases.append(self._case(C, "Who-Is then ReadProperty (interleaved unicast)",
                                _who_is()))
        cases.append(self._case(C, "ReadProperty after Who-Is (interleaved unicast)",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 1)))

        # Multiple Who-Is
        cases.append(self._case(C, "Who-Is no range (1st of flood)", _who_is()))
        cases.append(self._case(C, "Who-Is no range (2nd of flood)", _who_is()))
        cases.append(self._case(C, "Who-Is no range (3rd of flood)", _who_is()))

        # WriteProperty then ReadProperty on same object
        cases.append(self._case(C, "WriteProperty AV0 Present_Value=99.0",
                                _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                                                _app_real(99.0), 50)))
        cases.append(self._case(C, "ReadProperty AV0 Present_Value (verify write)",
                                _read_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE, 51)))

        # Subscribe then cancel
        cases.append(self._case(C, "SubscribeCOV AI0 proc_id=99 (subscribe)",
                                _subscribe_cov(99, _OBJ_ANALOG_INPUT, 0, invoke_id=60)))
        cases.append(self._case(C, "SubscribeCOV AI0 proc_id=99 (cancel via lifetime=0)",
                                _cancel_cov(99, _OBJ_ANALOG_INPUT, 0, invoke_id=61)))

        return cases

    def _gen_state_machine(self):
        C = CATEGORY_STATE_MACHINE
        cases = []

        # Abort APDU sent to target (target should ignore; not a request)
        abort_apdu = bytes([0x70, 0x01, 0x04])  # server-sent abort, reason=segmentation
        cases.append(self._case(C, "Abort APDU (fuzzer sends abort to target)",
                                _bvll(_BVLL_UNICAST, _npdu(0x00) + abort_apdu)))

        # Reject APDU
        reject_apdu = bytes([0x60, 0x01, 0x09])  # reject, unrecognized-service
        cases.append(self._case(C, "Reject APDU (fuzzer sends reject to target)",
                                _bvll(_BVLL_UNICAST, _npdu(0x00) + reject_apdu)))

        # Error APDU
        error_apdu = bytes([0x50, 0x01, 0x0C, 0x91, 0x01, 0x91, 0x07])
        cases.append(self._case(C, "Error APDU (fuzzer sends error to target)",
                                _bvll(_BVLL_UNICAST, _npdu(0x00) + error_apdu)))

        # Simple-ACK sent by fuzzer (target hasn't made a request)
        simple_ack = bytes([0x20, 0x01, 0x0F])
        cases.append(self._case(C, "Simple-ACK sent by fuzzer (unsolicited)",
                                _bvll(_BVLL_UNICAST, _npdu(0x00) + simple_ack)))

        # Complex-ACK sent by fuzzer
        complex_ack = bytes([0x30, 0x01, 0x0C]) + _app_unsigned(42)
        cases.append(self._case(C, "Complex-ACK sent by fuzzer (unsolicited)",
                                _bvll(_BVLL_UNICAST, _npdu(0x00) + complex_ack)))

        # Segment-ACK without segmented exchange
        seg_ack = bytes([0x40, 0x00, 0x01, 0x00, 0x00])
        cases.append(self._case(C, "Segment-ACK without prior segmented request",
                                _bvll(_BVLL_UNICAST, _npdu(0x00) + seg_ack)))

        # DeviceCommunicationControl — disable
        cases.append(self._case(C, "DeviceCommunicationControl: disable (no password)",
                                _device_comm_ctrl(1, invoke_id=20)))
        cases.append(self._case(C, "DeviceCommunicationControl: enable",
                                _device_comm_ctrl(0, invoke_id=21)))
        cases.append(self._case(C, "DeviceCommunicationControl: disable-initiation",
                                _device_comm_ctrl(2, invoke_id=22)))

        # ReinitializeDevice — various states
        cases.append(self._case(C, "ReinitializeDevice: coldstart (state=0)",
                                _reinitialize_device(0, invoke_id=23)))
        cases.append(self._case(C, "ReinitializeDevice: warmstart (state=1)",
                                _reinitialize_device(1, invoke_id=24)))
        cases.append(self._case(C, "ReinitializeDevice: startbackup (state=2)",
                                _reinitialize_device(2, invoke_id=25)))
        cases.append(self._case(C, "ReinitializeDevice: startrestore (state=4)",
                                _reinitialize_device(4, invoke_id=26)))
        cases.append(self._case(C, "ReinitializeDevice: state=255 (undefined)",
                                _reinitialize_device(255, invoke_id=27)))

        # WriteProperty to read-only Device properties
        cases.append(self._case(C, "WriteProperty Device Object_Name (read-only)",
                                _write_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME,
                                                _app_char_string("hacked"), 28)))
        cases.append(self._case(C, "WriteProperty Device Vendor_Identifier (read-only)",
                                _write_property(_OBJ_DEVICE, 1234, _PROP_VENDOR_ID,
                                                _app_unsigned(0xDEAD), 29)))

        # Confirmed request with segmented flag set
        seg_req = bytes([0x02, 0x05, 0x01, _SVC_READ_PROPERTY])  # SEG=1
        seg_req += _ctx_tag(0, _obj_id_bytes(_OBJ_DEVICE, 1234))
        seg_req += _prop_ctx_tag(1, _PROP_OBJECT_NAME)
        cases.append(self._case(C, "Confirmed-Req with SEG=1 (segmented without follow-up)",
                                _bvll(_BVLL_UNICAST, _npdu(0x04) + seg_req)))

        return cases

    def _gen_read_write_property(self):
        C = CATEGORY_READ_WRITE_PROP
        cases = []
        iid = 30

        # ReadProperty across all major object types
        for obj_type, name in [
            (_OBJ_ANALOG_INPUT,  "Analog-Input"),
            (_OBJ_ANALOG_OUTPUT, "Analog-Output"),
            (_OBJ_ANALOG_VALUE,  "Analog-Value"),
            (_OBJ_BINARY_INPUT,  "Binary-Input"),
            (_OBJ_BINARY_OUTPUT, "Binary-Output"),
            (_OBJ_BINARY_VALUE,  "Binary-Value"),
            (_OBJ_FILE,          "File"),
            (_OBJ_MULTI_STATE_I, "Multi-State-Input"),
        ]:
            cases.append(self._case(C, f"ReadProperty {name} 0 Object_Name",
                                    _read_property(obj_type, 0, _PROP_OBJECT_NAME, iid)))
            iid += 1

        # ReadProperty non-existent objects
        cases.append(self._case(C, "ReadProperty Device instance=0x3FFFFF (non-existent)",
                                _read_property(_OBJ_DEVICE, 0x3FFFFF, _PROP_OBJECT_NAME, iid)))
        iid += 1
        cases.append(self._case(C, "ReadProperty Analog-Input instance=9999 (non-existent)",
                                _read_property(_OBJ_ANALOG_INPUT, 9999, _PROP_PRESENT_VALUE, iid)))
        iid += 1

        # ReadProperty non-existent properties
        cases.append(self._case(C, "ReadProperty Device property=0xFFF (undefined)",
                                _read_property(_OBJ_DEVICE, 1234, 0xFFF, iid)))
        iid += 1
        cases.append(self._case(C, "ReadProperty Device property=255 (likely unknown)",
                                _read_property(_OBJ_DEVICE, 1234, 255, iid)))
        iid += 1
        cases.append(self._case(C, "ReadProperty AI0 property=0 (undefined for AI)",
                                _read_property(_OBJ_ANALOG_INPUT, 0, 0, iid)))
        iid += 1

        # ReadProperty with array index
        cases.append(self._case(C, "ReadProperty Device Object_Name array-index=0",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, iid, 0)))
        iid += 1
        cases.append(self._case(C, "ReadProperty Device Object_Name array-index=0xFFFFFFFF",
                                _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, iid, 0xFFFFFFFF)))
        iid += 1

        # WriteProperty — type variations on AV0 Present_Value
        for val, desc in [
            (_app_real(0.0),          "WriteProperty AV0 Present_Value=0.0"),
            (_app_real(-999.9),       "WriteProperty AV0 Present_Value=-999.9"),
            (_app_real(1e38),         "WriteProperty AV0 Present_Value=1e38 (large)"),
            (_app_real(float('nan')), "WriteProperty AV0 Present_Value=NaN"),
            (_app_real(float('inf')), "WriteProperty AV0 Present_Value=+Inf"),
        ]:
            cases.append(self._case(C, desc,
                                    _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                                                    val, iid)))
            iid += 1

        # WriteProperty type mismatch (string to real property)
        cases.append(self._case(C, "WriteProperty AV0 Present_Value=string (type mismatch)",
                                _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                                                _app_char_string("not-a-float"), iid)))
        iid += 1

        # WriteProperty Binary-Value
        cases.append(self._case(C, "WriteProperty BV0 Present_Value=true",
                                _write_property(_OBJ_BINARY_VALUE, 0, _PROP_PRESENT_VALUE,
                                                _app_bool(True), iid)))
        iid += 1
        cases.append(self._case(C, "WriteProperty BV0 Present_Value=enum(255) (out-of-range)",
                                _write_property(_OBJ_BINARY_VALUE, 0, _PROP_PRESENT_VALUE,
                                                _app_enum(255), iid)))
        iid += 1

        # WriteProperty with priorities
        cases.append(self._case(C, "WriteProperty AV0 priority=1 (Life-Safety)",
                                _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                                                _app_real(1.0), iid, priority=1)))
        iid += 1
        cases.append(self._case(C, "WriteProperty AV0 priority=16 (lowest)",
                                _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                                                _app_real(2.0), iid, priority=16)))
        iid += 1

        # WriteProperty null value (relinquish)
        cases.append(self._case(C, "WriteProperty AV0 Present_Value=Null (relinquish)",
                                _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                                                bytes([0x00]), iid)))  # Null tag
        iid += 1

        # WriteProperty with oversized string
        big_str = _app_char_string("A" * 256)
        cases.append(self._case(C, "WriteProperty AV0 Object_Name=256-char string",
                                _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_OBJECT_NAME,
                                                big_str, iid)))
        iid += 1

        return cases

    def _gen_whois_range(self):
        C = CATEGORY_WHOIS_RANGE
        cases = []

        # Standard ranges
        cases.append(self._case(C, "Who-Is no range (discover all)", _who_is()))
        cases.append(self._case(C, "Who-Is range 0-0 (only device 0)", _who_is(0, 0)))
        cases.append(self._case(C, "Who-Is range 1234-1234 (exact device)", _who_is(1234, 1234)))
        cases.append(self._case(C, "Who-Is range 0-4194303 (full range)", _who_is(0, 4194303)))
        cases.append(self._case(C, "Who-Is range 0-4194302 (max-1 high)",
                                _who_is(0, 4194302)))
        cases.append(self._case(C, "Who-Is range 4194303-4194303 (max device ID)",
                                _who_is(4194303, 4194303)))

        # Inverted range (low > high — violates spec)
        cases.append(self._case(C, "Who-Is inverted range low=4194303 high=0",
                                _who_is(4194303, 0)))
        cases.append(self._case(C, "Who-Is inverted range low=1234 high=0",
                                _who_is(1234, 0)))
        cases.append(self._case(C, "Who-Is inverted range low=0xFFFF high=0",
                                _who_is(0xFFFF, 0)))

        # Out-of-range values (> 4194303)
        cases.append(self._case(C, "Who-Is low=0xFFFFFFFF (way out of range)",
                                _who_is(0xFFFFFFFF, 0xFFFFFFFF)))
        cases.append(self._case(C, "Who-Is low=4194304 high=4194304 (just over max)",
                                _who_is(4194304, 4194304)))

        # Range covering common device IDs
        cases.append(self._case(C, "Who-Is range 1-65535 (small devices)",
                                _who_is(1, 65535)))
        cases.append(self._case(C, "Who-Is range 32000-33000 (narrow)",
                                _who_is(32000, 33000)))

        # Who-Is with identical low/high at boundaries
        cases.append(self._case(C, "Who-Is range 0-1 (minimal range)", _who_is(0, 1)))

        # Who-Has variants
        cases.append(self._case(C, "Who-Has Device 1234 (by object ID)",
                                _who_has(_OBJ_DEVICE, 1234)))
        cases.append(self._case(C, "Who-Has Analog-Input 0",
                                _who_has(_OBJ_ANALOG_INPUT, 0)))
        cases.append(self._case(C, "Who-Has object type=63 (undefined)",
                                _who_has(63, 0)))
        cases.append(self._case(C, "Who-Has max instance=0x3FFFFF",
                                _who_has(_OBJ_DEVICE, 0x3FFFFF)))

        # I-Am variants (as device response simulation)
        cases.append(self._case(C, "I-Am device=0 (illegal instance)",
                                _i_am(device_instance=0)))
        cases.append(self._case(C, "I-Am device=4194303 (max instance)",
                                _i_am(device_instance=4194303)))

        return cases

    def _gen_cov_flood(self):
        C = CATEGORY_COV_FLOOD
        cases = []
        iid = 100

        # Subscribe to multiple objects with different proc_ids
        for proc_id, obj_type, obj_inst, name in [
            (1,  _OBJ_ANALOG_INPUT,  0, "Analog-Input 0"),
            (2,  _OBJ_ANALOG_VALUE,  0, "Analog-Value 0"),
            (3,  _OBJ_BINARY_VALUE,  0, "Binary-Value 0"),
            (4,  _OBJ_BINARY_INPUT,  0, "Binary-Input 0"),
            (5,  _OBJ_ANALOG_INPUT,  1, "Analog-Input 1"),
            (6,  _OBJ_ANALOG_INPUT,  2, "Analog-Input 2"),
            (7,  _OBJ_ANALOG_INPUT,  3, "Analog-Input 3"),
            (8,  _OBJ_DEVICE,       1234, "Device 1234"),
        ]:
            cases.append(self._case(C, f"SubscribeCOV {name} proc_id={proc_id}",
                                    _subscribe_cov(proc_id, obj_type, obj_inst,
                                                   invoke_id=iid)))
            iid += 1

        # Subscribe with maximum lifetime
        cases.append(self._case(C, "SubscribeCOV AI0 lifetime=0xFFFFFFFF (max)",
                                _subscribe_cov(10, _OBJ_ANALOG_INPUT, 0,
                                               lifetime=0xFFFFFFFF, invoke_id=iid)))
        iid += 1

        # Subscribe with minimum lifetime
        cases.append(self._case(C, "SubscribeCOV AI0 lifetime=1s (minimum)",
                                _subscribe_cov(11, _OBJ_ANALOG_INPUT, 0,
                                               lifetime=1, invoke_id=iid)))
        iid += 1

        # Cancel subscriptions
        for proc_id in (1, 2, 3):
            cases.append(self._case(C, f"Cancel SubscribeCOV proc_id={proc_id} (lifetime=0)",
                                    _cancel_cov(proc_id, _OBJ_ANALOG_INPUT, 0, invoke_id=iid)))
            iid += 1

        # UnconfirmedCOVNotification (push from fuzzer to target)
        cases.append(self._case(C, "UnconfirmedCOVNotification AI0 Present_Value=3.14",
                                _uncnf_cov_notification(1, _OBJ_ANALOG_INPUT, 0,
                                                        _PROP_PRESENT_VALUE, _app_real(3.14))))
        cases.append(self._case(C, "UnconfirmedCOVNotification BV0 Present_Value=true",
                                _uncnf_cov_notification(2, _OBJ_BINARY_VALUE, 0,
                                                        _PROP_PRESENT_VALUE, _app_bool(True))))

        # Subscribe to non-existent object
        cases.append(self._case(C, "SubscribeCOV non-existent AI 9999",
                                _subscribe_cov(20, _OBJ_ANALOG_INPUT, 9999, invoke_id=iid)))
        iid += 1

        # Subscribe with confirmed notifications
        cases.append(self._case(C, "SubscribeCOV AI0 with confirmed=true",
                                _subscribe_cov(21, _OBJ_ANALOG_INPUT, 0, confirmed=True,
                                               invoke_id=iid)))
        iid += 1

        # Proc_id at boundaries
        cases.append(self._case(C, "SubscribeCOV proc_id=0",
                                _subscribe_cov(0, _OBJ_ANALOG_INPUT, 0, invoke_id=iid)))
        iid += 1
        cases.append(self._case(C, "SubscribeCOV proc_id=255",
                                _subscribe_cov(255, _OBJ_ANALOG_INPUT, 0, invoke_id=iid)))
        iid += 1

        return cases

    def _gen_bbmd(self):
        C = CATEGORY_BBMD
        cases = []

        # Register-Foreign-Device TTL variants
        cases.append(self._case(C, "Register-Foreign-Device TTL=600s (standard)",
                                _register_foreign_device(600)))
        cases.append(self._case(C, "Register-Foreign-Device TTL=0 (instant expiry)",
                                _register_foreign_device(0)))
        cases.append(self._case(C, "Register-Foreign-Device TTL=1 (minimum)",
                                _register_foreign_device(1)))
        cases.append(self._case(C, "Register-Foreign-Device TTL=0xFFFF (maximum)",
                                _register_foreign_device(0xFFFF)))
        cases.append(self._case(C, "Register-Foreign-Device empty body (truncated)",
                                _bvll(_BVLL_REGISTER_FD, b'')))
        cases.append(self._case(C, "Register-Foreign-Device body=1 byte (truncated)",
                                _bvll(_BVLL_REGISTER_FD, b'\x00')))

        # Read BDT / FDT
        cases.append(self._case(C, "Read-BDT request", _read_bdt()))
        cases.append(self._case(C, "Read-FDT request", _read_fdt()))

        # Forwarded-NPDU variants
        fake_orig_ip = bytes([192, 168, 1, 99])
        who_is_apdu = _apdu_unconfirmed(_USVC_WHO_IS)
        cases.append(self._case(C, "Forwarded-NPDU with Who-Is (fake originator 192.168.1.99)",
                                _forwarded_npdu(fake_orig_ip, 47808, who_is_apdu)))
        cases.append(self._case(C, "Forwarded-NPDU with ReadProperty (fake originator)",
                                _forwarded_npdu(fake_orig_ip, 47808,
                                                _apdu_confirmed(_SVC_READ_PROPERTY, 1,
                                                                _ctx_tag(0, _obj_id_bytes(_OBJ_DEVICE, 1234)) +
                                                                _prop_ctx_tag(1, _PROP_OBJECT_NAME)))))
        cases.append(self._case(C, "Forwarded-NPDU originator=0.0.0.0:0",
                                _forwarded_npdu(b'\x00\x00\x00\x00', 0, who_is_apdu)))

        # Distribute-Broadcast-To-Network
        cases.append(self._case(C, "Distribute-Broadcast Who-Is via BBMD",
                                _distribute_broadcast(who_is_apdu)))
        cases.append(self._case(C, "Distribute-Broadcast I-Am via BBMD",
                                _distribute_broadcast(_apdu_unconfirmed(_USVC_I_AM,
                                                                         _app_obj_id(_OBJ_DEVICE, 1234) +
                                                                         _app_unsigned(1476) +
                                                                         _app_enum(3) +
                                                                         bytes([0x22, 0x12, 0x34])))))

        # Write-BDT (normally restricted)
        cases.append(self._case(C, "Write-BDT with empty table",
                                _bvll(_BVLL_WRITE_BDT, b'')))
        cases.append(self._case(C, "Write-BDT with one entry (10-byte entry)",
                                _bvll(_BVLL_WRITE_BDT,
                                      bytes([192, 168, 1, 1]) + struct.pack('>H', 47808) +
                                      bytes([255, 255, 255, 0]))))

        # BVLC-Result injected back at target
        cases.append(self._case(C, "BVLC-Result=0x0000 (success) sent to target",
                                _bvll(_BVLL_RESULT, struct.pack('>H', 0x0000))))
        cases.append(self._case(C, "BVLC-Result=0x0030 (register-failed) sent to target",
                                _bvll(_BVLL_RESULT, struct.pack('>H', 0x0030))))

        # Delete-FDT-Entry
        cases.append(self._case(C, "Delete-FDT-Entry 127.0.0.1:47808",
                                _bvll(_BVLL_DELETE_FDT_ENTRY,
                                      bytes([127, 0, 0, 1]) + struct.pack('>H', 47808))))
        cases.append(self._case(C, "Delete-FDT-Entry 0.0.0.0:0",
                                _bvll(_BVLL_DELETE_FDT_ENTRY, b'\x00' * 6)))

        return cases

    # ------------------------------------------------------------------
    # Send phase
    # ------------------------------------------------------------------

    def fuzz(self, categories=None) -> list:
        if self._sock is None:
            raise RuntimeError("call connect() before fuzz()")
        cases   = self.generate_cases(categories)
        results = []
        total   = len(cases)
        for i, (case_id, cat, desc, payload) in enumerate(cases, 1):
            print(f"\r[bacnet] {i}/{total}  {case_id}  {desc[:60]}", end="", flush=True)
            result = self._send_case(case_id, cat, desc, payload)
            results.append(result)
            if self.logger:
                self.logger.log(result)
            if self.delay:
                time.sleep(self.delay)
        print()
        return results

    def _send_case(self, case_id: str, category: str,
                   description: str, payload: bytes) -> FuzzResult:
        result = FuzzResult(
            case_id=case_id,
            protocol=self.PROTOCOL_NAME,
            target=f"{self.target.ip}:{self.target.port}",
            category=category,
            description=description,
            payload=payload,
        )
        t0 = time.monotonic()
        try:
            self._sock.sendto(payload, self._target_addr)
            try:
                data, _ = self._sock.recvfrom(65535)
                result.response = data
                result.duration_ms = (time.monotonic() - t0) * 1000
                self._classify_response(data, result)
            except socket.timeout:
                result.anomaly         = ANOMALY_TIMEOUT
                result.crash_indicator = True
                result.duration_ms     = (time.monotonic() - t0) * 1000
        except OSError as e:
            result.anomaly         = ANOMALY_NO_RESPONSE
            result.crash_indicator = True
            self._reconnect()
        return result

    def _classify_response(self, data: bytes, result: FuzzResult) -> None:
        if len(data) < 4 or data[0] != 0x81:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        func = data[1]

        # BVLC-Result
        if func == _BVLL_RESULT:
            if len(data) < 6:
                result.anomaly         = ANOMALY_MALFORMED_RESPONSE
                result.crash_indicator = True
                return
            code = struct.unpack_from('>H', data, 4)[0]
            if code != 0x0000:
                result.anomaly         = ANOMALY_EXCEPTION
                result.crash_indicator = False
            return

        # BBMD responses with no NPDU/APDU
        if func in (_BVLL_READ_BDT_ACK, _BVLL_READ_FDT_ACK):
            return  # success, no anomaly

        # Packets with NPDU+APDU
        if func not in (_BVLL_UNICAST, _BVLL_BROADCAST, _BVLL_FORWARDED_NPDU):
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        try:
            npdu_start = 4 + (6 if func == _BVLL_FORWARDED_NPDU else 0)
            apdu_start = _skip_npdu(data, npdu_start)
            apdu = data[apdu_start:]
        except (IndexError, Exception):
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        if not apdu:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        pdu_type = apdu[0] & 0xF0

        if pdu_type in (0x20, 0x30, 0x10):
            # Simple-ACK, Complex-ACK, Unconfirmed (I-Am, I-Have, etc.) — all OK
            return

        if pdu_type in (0x50, 0x60, 0x70):
            # Error, Reject, Abort — spec-compliant errors
            result.anomaly         = ANOMALY_EXCEPTION
            result.crash_indicator = False
            if len(apdu) >= 1:
                result.response_decoded = {"pdu_type": f"0x{pdu_type:02X}",
                                           "raw": apdu.hex()}
            return

        # Unknown PDU type
        result.anomaly         = ANOMALY_MALFORMED_RESPONSE
        result.crash_indicator = True
