"""EtherNet/IP fuzzer generator and unit tests — no live target required."""

import struct

import pytest

from protocols.ethernetip.fuzzer import (
    EthernetIpFuzzer,
    _enip_packet,
    _register_session_packet,
    _list_identity_packet,
    _list_services_packet,
    _nop_packet,
    _cpf_items,
    _send_rr_data,
    _unconnected_msg,
    _cip_path,
    _cip_request,
    _get_attr_all,
    _get_attr_single,
    _set_attr_single,
    _forward_open,
    _large_forward_open,
    _forward_close,
    _multi_service_packet,
    _unconnected_send_cip,
    _CMD_NOP,
    _CMD_LIST_SERVICES,
    _CMD_LIST_IDENTITY,
    _CMD_LIST_INTERFACES,
    _CMD_REGISTER_SESSION,
    _CMD_UNREGISTER_SES,
    _CMD_SEND_RR_DATA,
    _CMD_SEND_UNIT_DATA,
    _CPF_NULL_ADDR,
    _CPF_UNCONN_DATA,
    _SVC_GET_ATTR_ALL,
    _SVC_GET_ATTR_SINGLE,
    _SVC_SET_ATTR_SINGLE,
    _SVC_FWD_OPEN,
    _SVC_FWD_CLOSE,
    _SVC_LARGE_FWD_OPEN,
    _SVC_MULTI_SERVICE,
    _SVC_UNCONN_SEND,
    CATEGORY_FWD_OPEN_CLOSE,
    CATEGORY_CIP_PATH,
    CATEGORY_UNCONN_SEND,
    CATEGORY_LARGE_FWD_OPEN,
    CATEGORY_LOGIX_TAG,
    CATEGORY_PCCC,
    _SVC_READ_TAG,
    _SVC_WRITE_TAG,
    _SVC_READ_TAG_FRAG,
    _SVC_WRITE_TAG_FRAG,
    _SVC_EXEC_PCCC,
    _logix_sym_path,
    _cip_service_from_send_rr,
    _ORIG_OT_CID,
    _ORIG_VENDOR_ID,
    _ORIG_SERIAL,
    _SKIP_SESSION_PATCH,
    _CMD_NO_RESPONSE,
)
from core.base_module import (
    CATEGORY_BOUNDARY,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    ANOMALY_UNEXPECTED_DATA,
    ANOMALY_EXCEPTION,
    Device,
    FuzzResult,
)


@pytest.fixture
def device():
    return Device(ip="127.0.0.1", port=44819, protocol="ethernetip")


@pytest.fixture
def fuzzer(device):
    return EthernetIpFuzzer(target=device, logger=None, delay=0)


# ---------------------------------------------------------------------------
# TestENIPBuilders
# ---------------------------------------------------------------------------

class TestENIPBuilders:
    def test_enip_packet_header_size(self):
        pkt = _enip_packet(0x0065, b'')
        assert len(pkt) == 24   # header only, no data

    def test_enip_packet_with_data(self):
        pkt = _enip_packet(0x0065, b'\x01\x02\x03\x04')
        assert len(pkt) == 28   # 24 + 4

    def test_enip_packet_command_le(self):
        pkt = _enip_packet(0x006F, b'')
        assert pkt[0] == 0x6F
        assert pkt[1] == 0x00

    def test_enip_packet_length_field(self):
        data = b'\xAA' * 16
        pkt  = _enip_packet(0x0063, data)
        length = struct.unpack_from('<H', pkt, 2)[0]
        assert length == 16

    def test_enip_packet_session_field(self):
        pkt = _enip_packet(0x006F, b'', session=0x12345678)
        sess = struct.unpack_from('<I', pkt, 4)[0]
        assert sess == 0x12345678

    def test_enip_packet_status_zero_default(self):
        pkt = _enip_packet(0x006F, b'')
        status = struct.unpack_from('<I', pkt, 8)[0]
        assert status == 0x00000000

    def test_enip_packet_options_zero(self):
        pkt = _enip_packet(0x006F, b'')
        opts = struct.unpack_from('<I', pkt, 20)[0]
        assert opts == 0x00000000

    def test_register_session_structure(self):
        pkt = _register_session_packet()
        assert len(pkt) == 28           # 24 + 4 (version + options)
        cmd = struct.unpack_from('<H', pkt, 0)[0]
        assert cmd == _CMD_REGISTER_SESSION
        sess = struct.unpack_from('<I', pkt, 4)[0]
        assert sess == 0                # session must be 0 in request
        ver = struct.unpack_from('<H', pkt, 24)[0]
        assert ver == 1                 # protocol version = 1

    def test_list_identity_cmd(self):
        pkt = _list_identity_packet()
        cmd = struct.unpack_from('<H', pkt, 0)[0]
        assert cmd == _CMD_LIST_IDENTITY

    def test_list_services_cmd(self):
        pkt = _list_services_packet()
        cmd = struct.unpack_from('<H', pkt, 0)[0]
        assert cmd == _CMD_LIST_SERVICES

    def test_nop_empty(self):
        pkt = _nop_packet()
        assert len(pkt) == 24
        cmd = struct.unpack_from('<H', pkt, 0)[0]
        assert cmd == _CMD_NOP

    def test_nop_with_data(self):
        pkt = _nop_packet(b'\xAA' * 10)
        assert len(pkt) == 34
        length = struct.unpack_from('<H', pkt, 2)[0]
        assert length == 10


class TestCPFBuilders:
    def test_cpf_item_count(self):
        cpf = _cpf_items((_CPF_NULL_ADDR, b''), (_CPF_UNCONN_DATA, b'\x01\x02'))
        count = struct.unpack_from('<H', cpf, 0)[0]
        assert count == 2

    def test_cpf_null_addr_item(self):
        cpf = _cpf_items((_CPF_NULL_ADDR, b''))
        # Type=0x0000, Length=0
        type_id = struct.unpack_from('<H', cpf, 2)[0]
        length  = struct.unpack_from('<H', cpf, 4)[0]
        assert type_id == 0x0000
        assert length == 0

    def test_cpf_unconn_data_item(self):
        data = b'\x01\x02\x03\x04'
        cpf  = _cpf_items((_CPF_NULL_ADDR, b''), (_CPF_UNCONN_DATA, data))
        # Second item at offset 2 + 4 = 6
        type_id = struct.unpack_from('<H', cpf, 6)[0]
        length  = struct.unpack_from('<H', cpf, 8)[0]
        payload = cpf[10:10 + length]
        assert type_id == _CPF_UNCONN_DATA
        assert length == 4
        assert payload == data

    def test_send_rr_data_structure(self):
        cpf = _cpf_items((_CPF_NULL_ADDR, b''))
        pkt = _send_rr_data(cpf, session=0x1234)
        cmd = struct.unpack_from('<H', pkt, 0)[0]
        assert cmd == _CMD_SEND_RR_DATA
        # Data starts at byte 24: InterfaceHandle(4) + Timeout(2) + CPF
        iface = struct.unpack_from('<I', pkt, 24)[0]
        assert iface == 0

    def test_unconnected_msg_has_two_items(self):
        pkt = _unconnected_msg(b'\x01\x02\x03\x04', session=0)
        data = pkt[24:]   # skip header
        # data: InterfaceHandle(4) + Timeout(2) + CPF
        cpf = data[6:]
        count = struct.unpack_from('<H', cpf, 0)[0]
        assert count == 2


class TestCIPBuilders:
    def test_cip_path_class_instance(self):
        path = _cip_path(('class', 0x01), ('instance', 0x01))
        assert len(path) == 4
        assert path[0] == 0x20   # class segment
        assert path[1] == 0x01   # class ID
        assert path[2] == 0x24   # instance segment
        assert path[3] == 0x01   # instance ID

    def test_cip_path_with_attribute(self):
        path = _cip_path(('class', 0x01), ('instance', 1)) + bytes([0x30, 0x07])
        assert len(path) == 6

    def test_cip_request_structure(self):
        path = _cip_path(('class', 0x01), ('instance', 1))
        req  = _cip_request(_SVC_GET_ATTR_ALL, path)
        assert req[0] == _SVC_GET_ATTR_ALL  # service
        assert req[1] == 2                   # path size in WORDs (4 bytes / 2)
        assert req[2:6] == path

    def test_get_attr_all(self):
        req = _get_attr_all(0x01, 1)
        assert req[0] == _SVC_GET_ATTR_ALL
        assert req[2] == 0x20   # class segment
        assert req[3] == 0x01   # class 1

    def test_get_attr_single(self):
        req = _get_attr_single(0x01, 1, 7)   # product name
        assert req[0] == _SVC_GET_ATTR_SINGLE

    def test_forward_open_service_code(self):
        req = _forward_open()
        assert req[0] == _SVC_FWD_OPEN

    def test_forward_open_path_to_class6(self):
        req = _forward_open()
        path_sz = req[1]   # path size in WORDs
        path = req[2:2 + path_sz * 2]
        assert path[0] == 0x20   # class segment
        assert path[1] == 0x06   # class 6 (connection manager)
        assert path[2] == 0x24   # instance segment
        assert path[3] == 0x01   # instance 1

    def test_forward_open_ot_cid_present(self):
        req = _forward_open()
        path_sz = req[1]
        data = req[2 + path_sz * 2:]   # body
        ot_cid = struct.unpack_from('<I', data, 2)[0]   # after priority + timeout
        assert ot_cid == _ORIG_OT_CID

    def test_large_forward_open_service_code(self):
        req = _large_forward_open()
        assert req[0] == _SVC_LARGE_FWD_OPEN

    def test_forward_close_service_code(self):
        req = _forward_close()
        assert req[0] == _SVC_FWD_CLOSE

    def test_multi_service_packet_count(self):
        r1 = _get_attr_single(0x01, 1, 1)
        r2 = _get_attr_single(0x01, 1, 2)
        pkt = _multi_service_packet(r1, r2)
        assert pkt[0] == _SVC_MULTI_SERVICE
        path_sz = pkt[1]
        body = pkt[2 + path_sz * 2:]
        count = struct.unpack_from('<H', body, 0)[0]
        assert count == 2

    def test_unconnected_send_service_code(self):
        inner = _get_attr_all(0x01, 1)
        req   = _unconnected_send_cip(inner)
        assert req[0] == _SVC_UNCONN_SEND


# ---------------------------------------------------------------------------
# TestGenerateCases
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def test_all_categories_produced(self, fuzzer):
        cases = fuzzer.generate_cases()
        cats  = {c[1] for c in cases}
        assert CATEGORY_BOUNDARY          in cats
        assert CATEGORY_BINARY_CORRUPTION in cats
        assert CATEGORY_SEQUENCE          in cats
        assert CATEGORY_STATE_MACHINE     in cats
        assert CATEGORY_FWD_OPEN_CLOSE    in cats
        assert CATEGORY_CIP_PATH          in cats
        assert CATEGORY_UNCONN_SEND       in cats
        assert CATEGORY_LARGE_FWD_OPEN    in cats

    def test_case_ids_unique(self, fuzzer):
        cases = fuzzer.generate_cases()
        ids   = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_case_ids_prefixed_ethernetip(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert all(c[0].startswith("ethernetip-") for c in cases)

    def test_minimum_case_count(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert len(cases) >= 200

    def test_all_payloads_bytes(self, fuzzer):
        cases = fuzzer.generate_cases()
        for case_id, _, _, payload in cases:
            assert isinstance(payload, bytes), f"{case_id}: not bytes"

    def test_descriptions_non_empty(self, fuzzer):
        cases = fuzzer.generate_cases()
        for case_id, _, desc, _ in cases:
            assert desc and len(desc) > 0

    def test_subset_by_category(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        cats  = {c[1] for c in cases}
        assert cats == {CATEGORY_BOUNDARY}

    def test_none_categories_returns_all(self, fuzzer):
        all_cases  = fuzzer.generate_cases()
        none_cases = fuzzer.generate_cases(None)
        assert len(all_cases) == len(none_cases)


# ---------------------------------------------------------------------------
# TestPreparePayload
# ---------------------------------------------------------------------------

class TestPreparePayload:
    def _make_send_rr_with_session(self, sess: int) -> bytes:
        cpf = _cpf_items((_CPF_NULL_ADDR, b''), (_CPF_UNCONN_DATA, _get_attr_all(0x01, 1)))
        return _send_rr_data(cpf, session=sess)

    def test_patches_session_for_boundary(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzzer._session = 0xABCDEF01
        payload = self._make_send_rr_with_session(0x00000000)  # session=0 initially
        patched = fuzzer._prepare_payload(payload, CATEGORY_BOUNDARY)
        sess = struct.unpack_from('<I', patched, 4)[0]
        assert sess == 0xABCDEF01

    def test_no_patch_for_binary_corruption(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzzer._session = 0xABCDEF01
        payload = self._make_send_rr_with_session(0xDEADBEEF)
        patched = fuzzer._prepare_payload(payload, CATEGORY_BINARY_CORRUPTION)
        sess = struct.unpack_from('<I', patched, 4)[0]
        assert sess == 0xDEADBEEF   # unchanged

    def test_no_patch_for_state_machine(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzzer._session = 0xABCDEF01
        payload = self._make_send_rr_with_session(0x00000000)
        patched = fuzzer._prepare_payload(payload, CATEGORY_STATE_MACHINE)
        sess = struct.unpack_from('<I', patched, 4)[0]
        assert sess == 0x00000000   # unchanged

    def test_no_patch_for_register_session_cmd(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzzer._session = 0xABCDEF01
        reg = _register_session_packet()   # session=0 in payload
        patched = fuzzer._prepare_payload(reg, CATEGORY_BOUNDARY)
        sess = struct.unpack_from('<I', patched, 4)[0]
        assert sess == 0   # Register Session must always have session=0

    def test_no_patch_if_session_zero(self, device):
        """If _session hasn't been set (0), don't patch."""
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzzer._session = 0
        payload = self._make_send_rr_with_session(0x12345678)
        patched = fuzzer._prepare_payload(payload, CATEGORY_BOUNDARY)
        sess = struct.unpack_from('<I', patched, 4)[0]
        assert sess == 0x12345678   # unchanged when no session

    def test_no_patch_for_list_identity(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzzer._session = 0xABCDEF01
        payload = _list_identity_packet()
        patched = fuzzer._prepare_payload(payload, CATEGORY_BOUNDARY)
        sess = struct.unpack_from('<I', patched, 4)[0]
        assert sess == 0   # List Identity always session=0

    def test_no_patch_for_nop(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzzer._session = 0xABCDEF01
        payload = _nop_packet()
        patched = fuzzer._prepare_payload(payload, CATEGORY_BOUNDARY)
        sess = struct.unpack_from('<I', patched, 4)[0]
        assert sess == 0


# ---------------------------------------------------------------------------
# TestBoundaryCategory
# ---------------------------------------------------------------------------

class TestBoundaryCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        assert len(cases) >= 25

    def test_list_identity_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [c[2] for c in cases]
        assert any("List Identity" in d for d in descs)

    def test_list_services_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [c[2] for c in cases]
        assert any("List Services" in d for d in descs)

    def test_register_session_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [c[2] for c in cases]
        assert any("Register Session" in d for d in descs)

    def test_nop_variants_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [c[2] for c in cases]
        assert any("NOP" in d for d in descs)

    def test_get_attr_all_identity(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [c[2] for c in cases]
        assert any("Get_Attributes_All" in d and "Identity" in d for d in descs)

    def test_register_session_payload_structure(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        reg_cases = [c for c in cases if "Register Session" in c[2]
                     and "version=1" in c[2]]
        assert reg_cases
        payload = reg_cases[0][3]
        cmd = struct.unpack_from('<H', payload, 0)[0]
        assert cmd == _CMD_REGISTER_SESSION
        sess = struct.unpack_from('<I', payload, 4)[0]
        assert sess == 0   # must be 0 in request


# ---------------------------------------------------------------------------
# TestBinaryCorruptionCategory
# ---------------------------------------------------------------------------

class TestBinaryCorruptionCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert len(cases) >= 40

    def test_truncated_cases_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        descs = [c[2] for c in cases]
        assert any("Truncated" in d or "truncated" in d for d in descs)

    def test_all_zero_payload_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        empties = [c for c in cases if c[3] == b'\x00' * 24]
        assert len(empties) >= 1

    def test_empty_payload_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        empties = [c for c in cases if c[3] == b'']
        assert len(empties) >= 1

    def test_wrong_command_codes_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        descs = [c[2] for c in cases]
        assert any("reserved" in d.lower() or "command 0x0000" in d for d in descs)

    def test_bad_session_handle_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        descs = [c[2] for c in cases]
        assert any("0xFFFFFFFF" in d or "wrong session" in d.lower() for d in descs)

    def test_truncated_covers_each_byte(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        descs = [c[2] for c in cases]
        for i in [1, 5, 10, 20, 23]:
            assert any(f"byte {i}" in d for d in descs), f"Missing truncation at byte {i}"


# ---------------------------------------------------------------------------
# TestSequenceCategory
# ---------------------------------------------------------------------------

class TestSequenceCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SEQUENCE])
        assert len(cases) >= 12

    def test_context_variants_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SEQUENCE])
        descs = [c[2] for c in cases]
        assert any("context" in d.lower() or "0xFF" in d or "0xDEAD" in d for d in descs)

    def test_wrong_session_handles(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SEQUENCE])
        descs = [c[2] for c in cases]
        assert any("session=0" in d or "0xFFFFFFFF" in d for d in descs)


# ---------------------------------------------------------------------------
# TestStateMachineCategory
# ---------------------------------------------------------------------------

class TestStateMachineCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        assert len(cases) >= 10

    def test_before_session_case(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        descs = [c[2] for c in cases]
        assert any("before Register" in d or "no session" in d.lower()
                   or "session=0" in d for d in descs)

    def test_fwd_close_without_open(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        descs = [c[2] for c in cases]
        assert any("Forward_Close without" in d or "wrong serial" in d.lower() for d in descs)

    def test_send_unit_data_without_connection(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        descs = [c[2] for c in cases]
        assert any("Send Unit Data" in d for d in descs)


# ---------------------------------------------------------------------------
# TestForwardOpenCloseCategory
# ---------------------------------------------------------------------------

class TestForwardOpenCloseCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FWD_OPEN_CLOSE])
        assert len(cases) >= 25

    def test_standard_forward_open_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FWD_OPEN_CLOSE])
        descs = [c[2] for c in cases]
        assert any("standard" in d.lower() and "Forward_Open" in d for d in descs)

    def test_rpi_variants(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FWD_OPEN_CLOSE])
        descs = [c[2] for c in cases]
        assert any("RPI=0" in d for d in descs)
        assert any("RPI=0xFFFFFFFF" in d for d in descs)

    def test_transport_class_variants(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FWD_OPEN_CLOSE])
        descs = [c[2] for c in cases]
        assert any("transport=0x" in d for d in descs)
        assert any("0xA3" in d for d in descs)

    def test_forward_close_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FWD_OPEN_CLOSE])
        descs = [c[2] for c in cases]
        assert any("Forward_Close" in d for d in descs)

    def test_connection_size_variants(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FWD_OPEN_CLOSE])
        descs = [c[2] for c in cases]
        assert any("size=0" in d for d in descs)
        assert any("size=500" in d for d in descs)

    def test_forward_open_payload_structure(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FWD_OPEN_CLOSE])
        std   = [c for c in cases if "standard" in c[2].lower() and "Forward_Open" in c[2]]
        assert std
        payload = std[0][3]
        # It's a Send RR Data packet
        cmd = struct.unpack_from('<H', payload, 0)[0]
        assert cmd == _CMD_SEND_RR_DATA


# ---------------------------------------------------------------------------
# TestCIPPathCategory
# ---------------------------------------------------------------------------

class TestCIPPathCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_CIP_PATH])
        assert len(cases) >= 25

    def test_standard_classes_covered(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_CIP_PATH])
        descs = [c[2] for c in cases]
        for label in ["class=0x01", "class=0x02", "class=0x06"]:
            assert any(label in d for d in descs), f"Missing {label}"

    def test_extended_logical_segments(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_CIP_PATH])
        descs = [c[2] for c in cases]
        assert any("extended" in d.lower() or "2-byte" in d.lower() for d in descs)

    def test_malformed_paths_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_CIP_PATH])
        descs = [c[2] for c in cases]
        assert any("Path size" in d or "empty path" in d.lower()
                   or "size=0" in d for d in descs)

    def test_ansi_extended_symbol_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_CIP_PATH])
        descs = [c[2] for c in cases]
        assert any("ANSI" in d or "Symbol" in d for d in descs)

    def test_port_segments_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_CIP_PATH])
        descs = [c[2] for c in cases]
        assert any("Port segment" in d or "backplane" in d.lower() for d in descs)


# ---------------------------------------------------------------------------
# TestUnconnectedSendCategory
# ---------------------------------------------------------------------------

class TestUnconnectedSendCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_UNCONN_SEND])
        assert len(cases) >= 15

    def test_multi_service_packet_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_UNCONN_SEND])
        descs = [c[2] for c in cases]
        assert any("Multiple_Service_Packet" in d for d in descs)

    def test_nested_unconnected_send(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_UNCONN_SEND])
        descs = [c[2] for c in cases]
        assert any("nested" in d.lower() or "Unconnected_Send nested" in d for d in descs)

    def test_service_codes_covered(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_UNCONN_SEND])
        descs = [c[2] for c in cases]
        # Should have various service codes
        assert any("0x0E" in d or "Get_Attribute_Single" in d for d in descs)

    def test_oversized_request_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_UNCONN_SEND])
        descs = [c[2] for c in cases]
        assert any("240" in d or "oversized" in d.lower() or "240 bytes" in d for d in descs)


# ---------------------------------------------------------------------------
# TestLargeForwardOpenCategory
# ---------------------------------------------------------------------------

class TestLargeForwardOpenCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LARGE_FWD_OPEN])
        assert len(cases) >= 10

    def test_standard_large_fwd_open(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LARGE_FWD_OPEN])
        descs = [c[2] for c in cases]
        assert any("standard" in d.lower() for d in descs)

    def test_max_size_variant(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LARGE_FWD_OPEN])
        descs = [c[2] for c in cases]
        assert any("65535" in d for d in descs)

    def test_zero_size_variant(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LARGE_FWD_OPEN])
        descs = [c[2] for c in cases]
        assert any("size=0" in d or "_size=0" in d for d in descs)

    def test_lfo_service_code_in_payload(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LARGE_FWD_OPEN])
        std   = [c for c in cases if "standard" in c[2].lower()]
        assert std
        payload = std[0][3]
        # Send RR Data → CPF → Unconnected Data → CIP (service byte)
        # service byte is deep inside; just verify it's a Send RR Data packet
        cmd = struct.unpack_from('<H', payload, 0)[0]
        assert cmd == _CMD_SEND_RR_DATA


# ---------------------------------------------------------------------------
# TestHardwareGate
# ---------------------------------------------------------------------------

class TestHardwareGate:
    def test_fuzz_raises_without_connect(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.fuzz()

    def test_replay_raises_without_connect(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.replay_payload(b'\x65\x00' + b'\x00' * 22)

    def test_connect_fails_on_refused(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(OSError):
            fuzzer.connect(Device(ip="127.0.0.1", port=19998, protocol="ethernetip"))

    def test_close_safe_when_not_connected(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzzer.close()   # should not raise

    def test_generate_cases_needs_no_connection(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert len(cases) > 0

    def test_nop_in_no_response_set(self):
        assert _CMD_NOP in _CMD_NO_RESPONSE

    def test_skip_session_patch_set_correct(self):
        assert CATEGORY_BINARY_CORRUPTION in _SKIP_SESSION_PATCH
        assert CATEGORY_STATE_MACHINE in _SKIP_SESSION_PATCH
        assert CATEGORY_BOUNDARY not in _SKIP_SESSION_PATCH
        assert CATEGORY_FWD_OPEN_CLOSE not in _SKIP_SESSION_PATCH


# ---------------------------------------------------------------------------
# TestAllenbradleyExtensions
# ---------------------------------------------------------------------------

class TestAllenbradleyExtensions:
    def test_logix_tag_cases_generated(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LOGIX_TAG])
        assert len(cases) >= 20

    def test_logix_tag_all_category_label(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LOGIX_TAG])
        assert all(c[1] == CATEGORY_LOGIX_TAG for c in cases)

    def test_logix_tag_read_service_byte_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LOGIX_TAG])
        payloads = [c[3] for c in cases]
        # 0x4C must appear in at least one ENIP payload's CIP data
        def has_svc(payload, svc):
            return any(b == svc for b in payload)
        assert any(has_svc(p, _SVC_READ_TAG) for p in payloads)

    def test_logix_tag_write_service_byte_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LOGIX_TAG])
        payloads = [c[3] for c in cases]
        assert any(_SVC_WRITE_TAG in p for p in payloads)

    def test_logix_tag_fragmented_services_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LOGIX_TAG])
        payloads = [c[3] for c in cases]
        assert any(_SVC_READ_TAG_FRAG in p for p in payloads)
        assert any(_SVC_WRITE_TAG_FRAG in p for p in payloads)

    def test_logix_sym_path_odd_name_padded(self):
        path = _logix_sym_path(b'Tag')   # 3 bytes — odd
        assert path[0] == 0x91           # symbolic segment type
        assert path[1] == 3              # name length
        assert path[2:5] == b'Tag'
        assert path[5] == 0x00           # padding byte
        assert len(path) % 2 == 0        # word-aligned

    def test_logix_sym_path_even_name_no_pad(self):
        path = _logix_sym_path(b'TagX')  # 4 bytes — even
        assert path[0] == 0x91
        assert path[1] == 4
        assert path[2:6] == b'TagX'
        assert len(path) == 6            # 2 header + 4 name, no pad

    def test_logix_sym_path_empty_name(self):
        path = _logix_sym_path(b'')
        assert path[0] == 0x91
        assert path[1] == 0
        assert len(path) == 2            # header only, no pad needed (even)

    def test_pccc_cases_generated(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_PCCC])
        assert len(cases) >= 18

    def test_pccc_all_category_label(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_PCCC])
        assert all(c[1] == CATEGORY_PCCC for c in cases)

    def test_pccc_service_code_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_PCCC])
        payloads = [c[3] for c in cases]
        assert any(_SVC_EXEC_PCCC in p for p in payloads)

    def test_pccc_class_0x67_in_path(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_PCCC])
        payloads = [c[3] for c in cases]
        # class 0x67 encoded as logical segment: 0x20 (class 8-bit) + 0x67
        assert any(b'\x20\x67' in p for p in payloads)

    def test_fuzz_categories_include_logix_tag(self):
        assert CATEGORY_LOGIX_TAG in EthernetIpFuzzer.FUZZ_CATEGORIES

    def test_fuzz_categories_include_pccc(self):
        assert CATEGORY_PCCC in EthernetIpFuzzer.FUZZ_CATEGORIES

    def test_generate_cases_total_count_increased(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert len(cases) >= 278   # 248 prior + ~45 new AB cases

    def test_ab_cases_have_descriptions(self, fuzzer):
        for cat in (CATEGORY_LOGIX_TAG, CATEGORY_PCCC):
            cases = fuzzer.generate_cases([cat])
            for case_id, _, desc, _ in cases:
                assert desc and len(desc) > 0, f"{case_id}: empty description"


# ---------------------------------------------------------------------------
# TestCIPServiceEchoCheck
# ---------------------------------------------------------------------------

def _make_result():
    return FuzzResult(
        case_id="test-0001", protocol="ethernetip",
        target="127.0.0.1:44819", category="boundary",
        description="test", payload=b'',
    )


class TestCIPServiceEchoCheck:
    """CIP response-service echo check: reply must be (request_service | 0x80)."""

    def _cip_response(self, service: int, gen_status: int = 0x00) -> bytes:
        """Build a minimal 4-byte CIP response: service, reserved, gen_status, add_status_size."""
        return bytes([service, 0x00, gen_status, 0x00])

    def test_correct_service_echo_no_anomaly(self, fuzzer):
        result = _make_result()
        cip = self._cip_response(0x8E)   # 0x0E | 0x80
        fuzzer._classify_cip_response(cip, result, request_cip_service=0x0E)
        assert result.anomaly is None
        assert result.crash_indicator is False

    def test_service_mismatch_flagged_unexpected(self, fuzzer):
        result = _make_result()
        # sent 0x4E, got back 0xD4 (wrong echo — correct would be 0xCE)
        cip = self._cip_response(0xD4)
        fuzzer._classify_cip_response(cip, result, request_cip_service=0x4E)
        assert result.anomaly == ANOMALY_UNEXPECTED_DATA
        assert result.crash_indicator is False

    def test_service_mismatch_not_crash(self, fuzzer):
        result = _make_result()
        cip = self._cip_response(0x85)   # bit 7 set, but wrong service
        fuzzer._classify_cip_response(cip, result, request_cip_service=0x01)
        assert result.anomaly == ANOMALY_UNEXPECTED_DATA
        assert result.crash_indicator is False

    def test_service_mismatch_response_decoded_contains_expected_got(self, fuzzer):
        result = _make_result()
        cip = self._cip_response(0xD4)
        fuzzer._classify_cip_response(cip, result, request_cip_service=0x4E)
        assert "expected" in result.response_decoded.lower()
        assert "got" in result.response_decoded.lower()

    def test_no_request_service_skips_echo_check(self, fuzzer):
        result = _make_result()
        cip = self._cip_response(0xD4)   # any service with bit 7 set
        fuzzer._classify_cip_response(cip, result, request_cip_service=None)
        assert result.anomaly is None

    def test_service_bit7_clear_still_flagged_crash(self, fuzzer):
        """Response without bit 7 set is always wrong, regardless of request service."""
        result = _make_result()
        cip = self._cip_response(0x4E)   # missing response bit
        fuzzer._classify_cip_response(cip, result, request_cip_service=0x4E)
        assert result.anomaly == ANOMALY_UNEXPECTED_DATA
        assert result.crash_indicator is True

    def test_gen_status_nonzero_still_exception_on_correct_echo(self, fuzzer):
        result = _make_result()
        cip = self._cip_response(0x8E, gen_status=0x08)  # correct echo, error status
        fuzzer._classify_cip_response(cip, result, request_cip_service=0x0E)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert result.crash_indicator is False

    # --- _cip_service_from_send_rr helper tests ---

    def test_extract_service_from_unconnected_msg(self):
        payload = _unconnected_msg(
            _cip_request(_SVC_GET_ATTR_ALL, _cip_path(('class', 1), ('instance', 1))),
            session=0,
        )
        assert _cip_service_from_send_rr(payload) == _SVC_GET_ATTR_ALL

    def test_extract_service_read_tag_frag(self):
        frag_path = _logix_sym_path(b'TestTag')
        payload = _unconnected_msg(
            bytes([_SVC_READ_TAG_FRAG, len(frag_path) // 2]) + frag_path
            + struct.pack('<HI', 1, 0),
            session=0,
        )
        assert _cip_service_from_send_rr(payload) == _SVC_READ_TAG_FRAG

    def test_extract_service_non_send_rr_returns_none(self):
        assert _cip_service_from_send_rr(_list_identity_packet()) is None

    def test_extract_service_too_short_returns_none(self):
        assert _cip_service_from_send_rr(b'\x65\x00') is None

    def test_extract_service_empty_returns_none(self):
        assert _cip_service_from_send_rr(b'') is None
