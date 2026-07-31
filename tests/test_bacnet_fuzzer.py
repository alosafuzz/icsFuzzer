"""BACnet fuzzer generator and unit tests — no live target required."""

import math
import struct

import pytest

from protocols.bacnet.fuzzer import (
    BacnetFuzzer,
    _bvll,
    _npdu,
    _bacnet_pkt,
    _apdu_confirmed,
    _apdu_unconfirmed,
    _ctx_tag,
    _ctx_open,
    _ctx_close,
    _app_unsigned,
    _app_real,
    _app_enum,
    _app_bool,
    _app_obj_id,
    _app_char_string,
    _obj_id_bytes,
    _prop_ctx_tag,
    _read_property,
    _write_property,
    _who_is,
    _i_am,
    _who_has,
    _subscribe_cov,
    _cancel_cov,
    _uncnf_cov_notification,
    _device_comm_ctrl,
    _reinitialize_device,
    _register_foreign_device,
    _read_bdt,
    _read_fdt,
    _forwarded_npdu,
    _distribute_broadcast,
    _BVLL_UNICAST,
    _BVLL_BROADCAST,
    _BVLL_RESULT,
    _BVLL_READ_BDT,
    _BVLL_READ_BDT_ACK,
    _BVLL_READ_FDT,
    _BVLL_REGISTER_FD,
    _BVLL_FORWARDED_NPDU,
    _BVLL_DISTRIB_BCAST,
    _OBJ_ANALOG_INPUT,
    _OBJ_ANALOG_VALUE,
    _OBJ_BINARY_VALUE,
    _OBJ_DEVICE,
    _PROP_OBJECT_NAME,
    _PROP_OBJECT_TYPE,
    _PROP_PRESENT_VALUE,
    _PROP_VENDOR_ID,
    _SVC_READ_PROPERTY,
    _SVC_WRITE_PROPERTY,
    _SVC_SUBSCRIBE_COV,
    _SVC_DEVICE_COMM_CTRL,
    _SVC_REINITIALIZE,
    _USVC_WHO_IS,
    _USVC_I_AM,
    _USVC_WHO_HAS,
    _DEVICE_INSTANCE,
    _DEVICE_VENDOR_ID,
    CATEGORY_READ_WRITE_PROP,
    CATEGORY_WHOIS_RANGE,
    CATEGORY_COV_FLOOD,
    CATEGORY_BBMD,
)
from core.base_module import (
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
)


@pytest.fixture
def device():
    return Device(ip="127.0.0.1", port=47809, protocol="bacnet")


@pytest.fixture
def fuzzer(device):
    return BacnetFuzzer(target=device, logger=None, delay=0)


# ---------------------------------------------------------------------------
# TestBVLLBuilders
# ---------------------------------------------------------------------------

class TestBVLLBuilders:
    def test_bvll_type_byte(self):
        pkt = _bvll(0x0A, b'\x01\x00')
        assert pkt[0] == 0x81

    def test_bvll_func_byte(self):
        pkt = _bvll(0x0A, b'')
        assert pkt[1] == 0x0A

    def test_bvll_length_big_endian(self):
        data = b'\x01\x02\x03\x04'
        pkt  = _bvll(0x0A, data)
        length = struct.unpack_from('>H', pkt, 2)[0]
        assert length == 8   # 4 header + 4 data

    def test_bvll_empty_data_length_4(self):
        pkt = _bvll(0x02, b'')
        length = struct.unpack_from('>H', pkt, 2)[0]
        assert length == 4

    def test_bvll_data_appended(self):
        pkt = _bvll(0x0A, b'\xAA\xBB')
        assert pkt[4:] == b'\xAA\xBB'

    def test_npdu_version(self):
        n = _npdu()
        assert n[0] == 0x01

    def test_npdu_ctrl_default(self):
        n = _npdu()
        assert n[1] == 0x04   # expecting reply

    def test_npdu_ctrl_no_reply(self):
        n = _npdu(0x00)
        assert n[1] == 0x00

    def test_bacnet_pkt_structure(self):
        pkt = _bacnet_pkt(0x04, b'\x10\x08')
        # BVLL type
        assert pkt[0] == 0x81
        # BVLL func = UNICAST
        assert pkt[1] == _BVLL_UNICAST
        # NPDU version
        assert pkt[4] == 0x01
        # NPDU ctrl
        assert pkt[5] == 0x04
        # APDU
        assert pkt[6] == 0x10
        assert pkt[7] == 0x08


class TestTagBuilders:
    def test_ctx_tag_len_1(self):
        t = _ctx_tag(0, b'\x42')
        assert t[0] == 0x09   # (0<<4)|0x08|1
        assert t[1] == 0x42

    def test_ctx_tag_len_4(self):
        t = _ctx_tag(0, b'\x00\x00\x00\x01')
        assert t[0] == 0x0C   # (0<<4)|0x08|4

    def test_ctx_tag_1_len_1(self):
        t = _ctx_tag(1, b'\x55')
        assert t[0] == 0x19   # (1<<4)|0x08|1

    def test_ctx_open_ctx0(self):
        assert _ctx_open(0) == bytes([0x0E])   # (0<<4)|0x08|6

    def test_ctx_close_ctx0(self):
        assert _ctx_close(0) == bytes([0x0F])  # (0<<4)|0x08|7

    def test_ctx_open_ctx3(self):
        assert _ctx_open(3) == bytes([0x3E])

    def test_ctx_close_ctx3(self):
        assert _ctx_close(3) == bytes([0x3F])

    def test_app_unsigned_0(self):
        t = _app_unsigned(0)
        assert t == bytes([0x21, 0x00])

    def test_app_unsigned_255(self):
        t = _app_unsigned(255)
        assert t == bytes([0x21, 0xFF])

    def test_app_unsigned_256(self):
        t = _app_unsigned(256)
        assert t[0] == 0x22
        assert struct.unpack_from('>H', t, 1)[0] == 256

    def test_app_unsigned_65536(self):
        t = _app_unsigned(65536)
        assert t[0] == 0x23

    def test_app_real_ieee754(self):
        t = _app_real(1.0)
        assert t[0] == 0x44
        f = struct.unpack_from('>f', t, 1)[0]
        assert abs(f - 1.0) < 1e-5

    def test_app_real_nan(self):
        t = _app_real(float('nan'))
        f = struct.unpack_from('>f', t, 1)[0]
        assert math.isnan(f)

    def test_app_enum(self):
        assert _app_enum(8) == bytes([0x91, 0x08])

    def test_app_bool_false(self):
        assert _app_bool(False) == bytes([0x11, 0x00])

    def test_app_bool_true(self):
        assert _app_bool(True) == bytes([0x11, 0x01])

    def test_app_obj_id_device_1234(self):
        t = _app_obj_id(_OBJ_DEVICE, 1234)
        assert t[0] == 0xC4
        word = struct.unpack_from('>I', t, 1)[0]
        assert (word >> 22) == 8     # device type
        assert (word & 0x3FFFFF) == 1234

    def test_app_char_string(self):
        t = _app_char_string("hi")
        assert t[0] == 0x75
        assert t[2] == 0x00   # UTF-8 encoding indicator
        assert t[3:] == b'hi'

    def test_obj_id_bytes(self):
        b = _obj_id_bytes(_OBJ_ANALOG_INPUT, 5)
        word = struct.unpack_from('>I', b)[0]
        assert (word >> 22) == 0   # analog input
        assert (word & 0x3FFFFF) == 5

    def test_prop_ctx_tag_1byte(self):
        t = _prop_ctx_tag(1, 85)
        assert t[0] == 0x19
        assert t[1] == 85

    def test_prop_ctx_tag_2byte(self):
        t = _prop_ctx_tag(1, 0x200)
        assert t[0] == 0x1A
        assert struct.unpack_from('>H', t, 1)[0] == 0x200


class TestAPDUBuilders:
    def test_apdu_confirmed_pdu_type(self):
        apdu = _apdu_confirmed(0x0C, 1)
        assert apdu[0] == 0x00  # Confirmed-Request

    def test_apdu_confirmed_invoke_id(self):
        apdu = _apdu_confirmed(0x0C, 42)
        assert apdu[2] == 42

    def test_apdu_confirmed_service(self):
        apdu = _apdu_confirmed(0x0C, 1)
        assert apdu[3] == 0x0C  # ReadProperty

    def test_apdu_confirmed_max_apdu(self):
        apdu = _apdu_confirmed(0x0C, 1, max_apdu=0x05)
        assert apdu[1] == 0x05

    def test_apdu_unconfirmed_pdu_type(self):
        apdu = _apdu_unconfirmed(0x08)
        assert apdu[0] == 0x10  # Unconfirmed-Request

    def test_apdu_unconfirmed_service(self):
        apdu = _apdu_unconfirmed(0x08)
        assert apdu[1] == 0x08  # Who-Is


class TestServiceBuilders:
    def test_read_property_bvll_type(self):
        pkt = _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 1)
        assert pkt[0] == 0x81

    def test_read_property_confirmed_request(self):
        pkt    = _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 1)
        apdu   = pkt[6:]   # skip BVLL(4) + NPDU(2)
        assert apdu[0] == 0x00   # Confirmed-Request
        assert apdu[3] == _SVC_READ_PROPERTY

    def test_read_property_invoke_id(self):
        pkt  = _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 77)
        apdu = pkt[6:]
        assert apdu[2] == 77

    def test_read_property_obj_id_context_tag(self):
        pkt  = _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 1)
        apdu = pkt[6:]
        body = apdu[4:]   # skip confirmed-req header (4 bytes)
        assert body[0] == 0x0C   # context tag 0, len 4

    def test_read_property_object_instance(self):
        pkt  = _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 1)
        apdu = pkt[6:]
        body = apdu[4:]
        word = struct.unpack_from('>I', body, 1)[0]
        assert (word & 0x3FFFFF) == 1234

    def test_write_property_service_code(self):
        pkt  = _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                               _app_real(1.0), 1)
        apdu = pkt[6:]
        assert apdu[3] == _SVC_WRITE_PROPERTY

    def test_write_property_context3_opening(self):
        pkt  = _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                               _app_real(1.0), 1)
        assert b'\x3E' in pkt   # context[3] opening tag

    def test_write_property_context3_closing(self):
        pkt  = _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                               _app_real(1.0), 1)
        assert b'\x3F' in pkt   # context[3] closing tag

    def test_write_property_with_priority(self):
        pkt = _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                              _app_real(1.0), 1, priority=8)
        # Priority context tag 4 = (4<<4)|0x08|1 = 0x49
        assert b'\x49' in pkt

    def test_who_is_no_range(self):
        pkt = _who_is()
        apdu = pkt[6:]
        assert apdu[0] == 0x10   # Unconfirmed-Request
        assert apdu[1] == _USVC_WHO_IS
        assert len(apdu) == 2    # no range parameters

    def test_who_is_with_range(self):
        pkt = _who_is(0, 4194303)
        assert len(pkt) > 6 + 2   # has range data

    def test_who_is_range_context_tags(self):
        pkt  = _who_is(1234, 1234)
        apdu = pkt[6:]
        body = apdu[2:]   # skip service header
        assert body[0] == 0x0C   # context tag 0, len 4

    def test_i_am_pdu_type(self):
        pkt  = _i_am()
        apdu = pkt[6:]
        assert apdu[0] == 0x10   # Unconfirmed-Request
        assert apdu[1] == _USVC_I_AM

    def test_i_am_device_instance(self):
        pkt  = _i_am(device_instance=999)
        apdu = pkt[6:]
        body = apdu[2:]
        # First element: application-tagged object identifier
        assert body[0] == 0xC4
        word = struct.unpack_from('>I', body, 1)[0]
        assert (word & 0x3FFFFF) == 999

    def test_who_has_pdu_type(self):
        pkt  = _who_has(_OBJ_DEVICE, 1234)
        apdu = pkt[6:]
        assert apdu[0] == 0x10
        assert apdu[1] == _USVC_WHO_HAS

    def test_subscribe_cov_service(self):
        pkt  = _subscribe_cov(1, _OBJ_ANALOG_INPUT, 0, invoke_id=1)
        apdu = pkt[6:]
        assert apdu[3] == _SVC_SUBSCRIBE_COV

    def test_cancel_cov_no_lifetime(self):
        pkt = _cancel_cov(1, _OBJ_ANALOG_INPUT, 0, invoke_id=1)
        # Should only have proc_id and obj_id context tags, no lifetime
        assert pkt[6 + 3] == _SVC_SUBSCRIBE_COV

    def test_device_comm_ctrl_service(self):
        pkt  = _device_comm_ctrl(1, invoke_id=1)
        apdu = pkt[6:]
        assert apdu[3] == _SVC_DEVICE_COMM_CTRL

    def test_reinitialize_service(self):
        pkt  = _reinitialize_device(0, invoke_id=1)
        apdu = pkt[6:]
        assert apdu[3] == _SVC_REINITIALIZE

    def test_register_foreign_device_bvll_func(self):
        pkt = _register_foreign_device(600)
        assert pkt[1] == _BVLL_REGISTER_FD

    def test_register_foreign_device_ttl(self):
        pkt = _register_foreign_device(300)
        ttl = struct.unpack_from('>H', pkt, 4)[0]
        assert ttl == 300

    def test_read_bdt_func(self):
        pkt = _read_bdt()
        assert pkt[1] == _BVLL_READ_BDT

    def test_read_fdt_func(self):
        pkt = _read_fdt()
        assert pkt[1] == _BVLL_READ_FDT

    def test_forwarded_npdu_func(self):
        pkt = _forwarded_npdu(b'\x7F\x00\x00\x01', 47808,
                              _apdu_unconfirmed(_USVC_WHO_IS))
        assert pkt[1] == _BVLL_FORWARDED_NPDU

    def test_forwarded_npdu_orig_ip(self):
        pkt = _forwarded_npdu(bytes([192, 168, 1, 1]), 47808,
                              _apdu_unconfirmed(_USVC_WHO_IS))
        # Originator IP at offset 4
        assert pkt[4:8] == bytes([192, 168, 1, 1])

    def test_distribute_broadcast_func(self):
        pkt = _distribute_broadcast(_apdu_unconfirmed(_USVC_WHO_IS))
        assert pkt[1] == _BVLL_DISTRIB_BCAST


# ---------------------------------------------------------------------------
# TestGenerateCases
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def test_all_categories_present(self, fuzzer):
        cases = fuzzer.generate_cases()
        cats  = {c[1] for c in cases}
        assert CATEGORY_BOUNDARY          in cats
        assert CATEGORY_BINARY_CORRUPTION in cats
        assert CATEGORY_SEQUENCE          in cats
        assert CATEGORY_STATE_MACHINE     in cats
        assert CATEGORY_READ_WRITE_PROP   in cats
        assert CATEGORY_WHOIS_RANGE       in cats
        assert CATEGORY_COV_FLOOD         in cats
        assert CATEGORY_BBMD              in cats

    def test_minimum_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases()) >= 185

    def test_unique_case_ids(self, fuzzer):
        cases = fuzzer.generate_cases()
        ids   = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_case_ids_prefixed(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert all(c[0].startswith("bacnet-") for c in cases)

    def test_all_payloads_bytes(self, fuzzer):
        for case_id, _, _, payload in fuzzer.generate_cases():
            assert isinstance(payload, bytes), f"{case_id}: not bytes"

    def test_descriptions_non_empty(self, fuzzer):
        for case_id, _, desc, _ in fuzzer.generate_cases():
            assert desc and len(desc) > 0

    def test_subset_category(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        assert all(c[1] == CATEGORY_BOUNDARY for c in cases)

    def test_none_returns_all(self, fuzzer):
        assert len(fuzzer.generate_cases()) == len(fuzzer.generate_cases(None))


# ---------------------------------------------------------------------------
# TestBoundaryCategory
# ---------------------------------------------------------------------------

class TestBoundaryCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_BOUNDARY])) >= 25

    def test_who_is_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("Who-Is" in d for d in descs)

    def test_i_am_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("I-Am" in d for d in descs)

    def test_read_property_device_name(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("ReadProperty" in d and "Object_Name" in d for d in descs)

    def test_write_property_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("WriteProperty" in d for d in descs)

    def test_subscribe_cov_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("SubscribeCOV" in d for d in descs)

    def test_read_bdt_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("Read-BDT" in d or "BDT" in d for d in descs)

    def test_invoke_id_0_and_255(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("invoke_id=0" in d for d in descs)
        assert any("invoke_id=255" in d for d in descs)

    def test_boundary_payloads_start_with_0x81(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        for case_id, _, _, payload in cases:
            assert len(payload) > 0 and payload[0] == 0x81, \
                f"{case_id}: boundary payload doesn't start with 0x81"


# ---------------------------------------------------------------------------
# TestBinaryCorruptionCategory
# ---------------------------------------------------------------------------

class TestBinaryCorruptionCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])) >= 40

    def test_empty_payload_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert any(c[3] == b'' for c in cases)

    def test_all_zero_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert any(c[3] == b'\x00' * 6 or c[3] == b'\x00' * 24 for c in cases)

    def test_truncated_cases_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])]
        assert any("Truncated" in d for d in descs)

    def test_wrong_bvll_type(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])]
        assert any("BVLL type" in d for d in descs)

    def test_wrong_bvll_func(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])]
        assert any("BVLL func" in d for d in descs)

    def test_wrong_length_field(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])]
        assert any("length" in d.lower() for d in descs)

    def test_wrong_npdu_version(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])]
        assert any("NPDU version" in d for d in descs)

    def test_single_byte_payload(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert any(len(c[3]) == 1 for c in cases)


# ---------------------------------------------------------------------------
# TestSequenceCategory
# ---------------------------------------------------------------------------

class TestSequenceCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_SEQUENCE])) >= 12

    def test_duplicate_invoke_id(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SEQUENCE])]
        assert sum(1 for d in descs if "invoke_id=42" in d) >= 2

    def test_invoke_id_range(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SEQUENCE])]
        assert any("invoke_id=0x00" in d for d in descs)
        assert any("invoke_id=0xFF" in d for d in descs)

    def test_who_is_flood(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SEQUENCE])]
        assert sum(1 for d in descs if "Who-Is" in d) >= 3

    def test_write_then_read(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SEQUENCE])]
        assert any("WriteProperty" in d for d in descs)
        assert any("ReadProperty" in d and "verify" in d for d in descs)


# ---------------------------------------------------------------------------
# TestStateMachineCategory
# ---------------------------------------------------------------------------

class TestStateMachineCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_STATE_MACHINE])) >= 15

    def test_abort_apdu(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("Abort" in d for d in descs)

    def test_reject_apdu(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("Reject" in d for d in descs)

    def test_simple_ack_unsolicited(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("Simple-ACK" in d for d in descs)

    def test_dcc_disable(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("DeviceCommunicationControl" in d and "disable" in d for d in descs)

    def test_reinitialize_coldstart(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("ReinitializeDevice" in d and "coldstart" in d for d in descs)

    def test_write_readonly_device_property(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("WriteProperty Device" in d and "read-only" in d for d in descs)

    def test_abort_payload_structure(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        abort_cases = [c for c in cases if "Abort" in c[2] and "sends abort" in c[2]]
        assert abort_cases
        payload = abort_cases[0][3]
        # BVLL type
        assert payload[0] == 0x81
        # APDU at offset 6
        assert payload[6] & 0xF0 == 0x70   # Abort PDU type


# ---------------------------------------------------------------------------
# TestReadWritePropertyCategory
# ---------------------------------------------------------------------------

class TestReadWritePropertyCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])) >= 25

    def test_all_major_object_types(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])]
        for name in ("Analog-Input", "Analog-Output", "Analog-Value",
                     "Binary-Input", "Binary-Output", "Binary-Value"):
            assert any(name in d for d in descs), f"Missing {name}"

    def test_non_existent_object(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])]
        assert any("non-existent" in d or "0x3FFFFF" in d for d in descs)

    def test_non_existent_property(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])]
        assert any("0xFFF" in d or "undefined" in d.lower() for d in descs)

    def test_nan_present_value(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])]
        assert any("NaN" in d for d in descs)

    def test_inf_present_value(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])]
        assert any("Inf" in d for d in descs)

    def test_type_mismatch(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])]
        assert any("type mismatch" in d or "string" in d.lower() for d in descs)

    def test_priority_variants(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])]
        assert any("priority=1" in d for d in descs)
        assert any("priority=16" in d for d in descs)

    def test_array_index_variants(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])]
        assert any("array-index" in d for d in descs)

    def test_oversized_string(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_READ_WRITE_PROP])]
        assert any("256" in d or "oversized" in d.lower() for d in descs)


# ---------------------------------------------------------------------------
# TestWhoisRangeCategory
# ---------------------------------------------------------------------------

class TestWhoisRangeCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_WHOIS_RANGE])) >= 15

    def test_no_range_case(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_WHOIS_RANGE])]
        assert any("no range" in d for d in descs)

    def test_full_range_case(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_WHOIS_RANGE])]
        assert any("4194303" in d and "full range" in d for d in descs)

    def test_inverted_range(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_WHOIS_RANGE])]
        assert any("inverted" in d for d in descs)

    def test_out_of_range_values(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_WHOIS_RANGE])]
        assert any("0xFFFFFFFF" in d or "out of range" in d.lower() for d in descs)

    def test_who_has_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_WHOIS_RANGE])]
        assert any("Who-Has" in d for d in descs)

    def test_i_am_boundary(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_WHOIS_RANGE])]
        assert any("I-Am device=0" in d or "device=4194303" in d for d in descs)

    def test_no_range_payload_length(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_WHOIS_RANGE])
        no_range = [c for c in cases if "no range" in c[2]]
        assert no_range
        pkt  = no_range[0][3]
        apdu = pkt[6:]
        assert apdu[0] == 0x10 and apdu[1] == _USVC_WHO_IS
        assert len(apdu) == 2   # no range parameters


# ---------------------------------------------------------------------------
# TestCOVFloodCategory
# ---------------------------------------------------------------------------

class TestCOVFloodCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_COV_FLOOD])) >= 15

    def test_multiple_proc_ids(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_COV_FLOOD])]
        assert any("proc_id=1" in d for d in descs)
        assert any("proc_id=5" in d for d in descs)

    def test_max_lifetime(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_COV_FLOOD])]
        assert any("0xFFFFFFFF" in d or "max" in d.lower() for d in descs)

    def test_cancel_subscription(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_COV_FLOOD])]
        assert any("Cancel" in d or "lifetime=0" in d for d in descs)

    def test_uncnf_cov_notification(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_COV_FLOOD])]
        assert any("UnconfirmedCOVNotification" in d for d in descs)

    def test_non_existent_object_subscribe(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_COV_FLOOD])]
        assert any("non-existent" in d or "9999" in d for d in descs)

    def test_proc_id_boundary(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_COV_FLOOD])]
        assert any("proc_id=0" in d for d in descs)
        assert any("proc_id=255" in d for d in descs)


# ---------------------------------------------------------------------------
# TestBBMDCategory
# ---------------------------------------------------------------------------

class TestBBMDCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_BBMD])) >= 15

    def test_register_fd_ttl_variants(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BBMD])]
        assert any("TTL=0" in d for d in descs)
        assert any("TTL=0xFFFF" in d for d in descs)
        assert any("TTL=600" in d for d in descs)

    def test_read_bdt_fdt(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BBMD])]
        assert any("Read-BDT" in d for d in descs)
        assert any("Read-FDT" in d for d in descs)

    def test_forwarded_npdu(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BBMD])]
        assert any("Forwarded-NPDU" in d for d in descs)

    def test_distribute_broadcast(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BBMD])]
        assert any("Distribute-Broadcast" in d or "Distrib" in d for d in descs)

    def test_write_bdt(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BBMD])]
        assert any("Write-BDT" in d or "write_bdt" in d.lower() for d in descs)

    def test_bvlc_result_injection(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BBMD])]
        assert any("BVLC-Result" in d for d in descs)

    def test_register_fd_empty_body(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BBMD])]
        assert any("truncated" in d.lower() and ("Register" in d or "FD" in d) for d in descs)

    def test_forwarded_npdu_has_orig_addr(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BBMD])
        fwd   = [c for c in cases if "Forwarded-NPDU" in c[2] and "192.168" in c[2]]
        assert fwd
        pkt = fwd[0][3]
        assert pkt[1] == _BVLL_FORWARDED_NPDU
        # Originator IP at offset 4
        assert pkt[4] == 192


# ---------------------------------------------------------------------------
# TestHardwareGate
# ---------------------------------------------------------------------------

class TestHardwareGate:
    def test_fuzz_raises_without_connect(self, device):
        fuzzer = BacnetFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.fuzz()

    def test_replay_raises_without_connect(self, device):
        fuzzer = BacnetFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.replay_payload(_who_is())

    def test_connect_fails_on_closed_port(self, device):
        fuzzer = BacnetFuzzer(target=device, logger=None, delay=0)
        # For UDP, connect() always succeeds (no actual packet sent)
        # but sending to a closed port will raise on recvfrom (timeout)
        fuzzer.connect(Device(ip="127.0.0.1", port=19998, protocol="bacnet"))
        # Should not raise — UDP connect is always local socket creation
        fuzzer.close()

    def test_close_safe_when_not_connected(self, device):
        fuzzer = BacnetFuzzer(target=device, logger=None, delay=0)
        fuzzer.close()   # should not raise

    def test_generate_cases_no_connection_needed(self, fuzzer):
        # generate_cases should not require a socket
        cases = fuzzer.generate_cases()
        assert len(cases) > 0
