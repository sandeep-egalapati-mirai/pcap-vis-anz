"""Unit tests for OT/ICS protocol parsers in app.py."""
import struct
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import parse_modbus, parse_dnp3, parse_s7comm, parse_enip, parse_iec104, parse_bacnet


# ── Modbus ────────────────────────────────────────────────────────────────────

def _modbus_pkt(transaction_id, unit_id, func_code, data=b""):
    length = 2 + len(data)  # unit_id + func_code + data
    hdr = struct.pack(">HHHBB", transaction_id, 0, length, unit_id, func_code)
    return hdr + data


def test_modbus_read_holding_registers():
    pkt = _modbus_pkt(1, 1, 3, struct.pack(">HH", 100, 10))
    r = parse_modbus(pkt)
    assert r is not None
    assert r["function_code"] == 3
    assert r["function_name"] == "Read Holding Registers"
    assert r["is_write"] is False
    assert r["is_error"] is False
    assert r["register_address"] == 100
    assert r["quantity"] == 10
    assert r["unit_id"] == 1
    assert r["unit_id_zero"] is False


def test_modbus_bulk_read_quantity():
    pkt = _modbus_pkt(1, 1, 3, struct.pack(">HH", 0, 125))
    r = parse_modbus(pkt)
    assert r["quantity"] == 125


def test_modbus_write_single_register():
    pkt = _modbus_pkt(2, 5, 6, struct.pack(">HH", 200, 42))
    r = parse_modbus(pkt)
    assert r["function_code"] == 6
    assert r["is_write"] is True
    assert r["register_address"] == 200


def test_modbus_exception_response():
    # FC 3 error = 0x83, exception code 2 = Illegal Data Address
    pkt = _modbus_pkt(3, 1, 0x83, bytes([2]))
    r = parse_modbus(pkt)
    assert r is not None
    assert r["is_error"] is True
    assert r["exception_code"] == 2
    assert r["exception_name"] == "Illegal Data Address"
    assert r["function_code"] == 3  # real FC = 0x83 & 0x7F


def test_modbus_broadcast_unit_id():
    pkt = _modbus_pkt(1, 0, 6, struct.pack(">HH", 0, 1))
    r = parse_modbus(pkt)
    assert r["unit_id_zero"] is True


def test_modbus_invalid_protocol_id():
    # Protocol ID must be 0; if not, should return None
    bad = struct.pack(">HHHBB", 1, 9999, 2, 1, 3)
    assert parse_modbus(bad) is None


def test_modbus_too_short():
    assert parse_modbus(b"\x00\x01") is None
    assert parse_modbus(None) is None


# ── DNP3 ─────────────────────────────────────────────────────────────────────

def _dnp3_pkt(direction_bit, dst, src, app_fc, group_byte=0):
    ctrl = (0x80 if direction_bit else 0x00) | 0x44  # PRM=1, FCB=1
    pkt = bytes([0x05, 0x64, 14, ctrl]) + \
          dst.to_bytes(2, "little") + src.to_bytes(2, "little") + \
          bytes([0xFF, 0xFF,  # CRC placeholder
                 0xC0, app_fc,  # app control + FC
                 group_byte, 0x01])  # object group + variation
    return pkt


def test_dnp3_master_role():
    pkt = _dnp3_pkt(direction_bit=1, dst=2, src=1, app_fc=1)
    r = parse_dnp3(pkt)
    assert r is not None
    assert r["role"] == "master"
    assert r["src_address"] == 1
    assert r["dst_address"] == 2
    assert r["function_code"] == 1


def test_dnp3_outstation_role():
    pkt = _dnp3_pkt(direction_bit=0, dst=1, src=2, app_fc=129)
    r = parse_dnp3(pkt)
    assert r["role"] == "outstation"


def test_dnp3_control_is_write():
    pkt = _dnp3_pkt(direction_bit=1, dst=2, src=1, app_fc=3)  # FC 3 = Select
    r = parse_dnp3(pkt)
    assert r["is_write"] is True


def test_dnp3_data_object_group_binary_output_control():
    pkt = _dnp3_pkt(direction_bit=1, dst=2, src=1, app_fc=5, group_byte=12)
    r = parse_dnp3(pkt)
    assert r["data_object_group"] == "Binary Output Control (CROB)"


def test_dnp3_invalid_start_bytes():
    assert parse_dnp3(b"\x06\x64" + b"\x00" * 10) is None
    assert parse_dnp3(None) is None


# ── S7comm ────────────────────────────────────────────────────────────────────

def _s7_pkt(rosctr, func_code, param_data=b""):
    # TPKT(4) + COTP(3) + S7 header(10) + param
    param_len = 1 + len(param_data)  # func_code byte + extra
    data_len = 0
    tpkt = bytes([0x03, 0x00, 0x00, 20 + len(param_data)])
    cotp = bytes([0x02, 0xF0, 0x80])
    s7hdr = bytes([0x32, rosctr, 0, 0, 0, 1, 0, param_len, 0, data_len])
    params = bytes([func_code]) + param_data
    return tpkt + cotp + s7hdr + params


def test_s7_read_variable():
    pkt = _s7_pkt(rosctr=1, func_code=0x04)
    r = parse_s7comm(pkt)
    assert r is not None
    assert r["function_code"] == 0x04
    assert r["function_name"] == "Read Variable"
    assert r["is_write"] is False


def test_s7_write_variable():
    pkt = _s7_pkt(rosctr=1, func_code=0x05)
    r = parse_s7comm(pkt)
    assert r["is_write"] is True


def test_s7_plc_stop():
    pkt = _s7_pkt(rosctr=1, func_code=0x29)
    r = parse_s7comm(pkt)
    assert r["function_code"] == 0x29
    assert r["is_write"] is True


def test_s7_invalid_tpkt():
    pkt = bytes([0x04, 0x00, 0x00, 20]) + b"\x00" * 20
    assert parse_s7comm(pkt) is None


def test_s7_too_short():
    assert parse_s7comm(b"\x03\x00") is None
    assert parse_s7comm(None) is None


# ── IEC-104 ──────────────────────────────────────────────────────────────────

def _iec104_pkt(ctrl1, ctrl2=0, ctrl3=0, ctrl4=0, body=b""):
    # APDU: start byte 0x68 + length + 4 control bytes + body
    length = 4 + len(body)
    return bytes([0x68, length, ctrl1, ctrl2, ctrl3, ctrl4]) + body


def test_iec104_u_frame_startdt():
    # U-frame: ctrl1 bit 0 = 1 and bit 1 = 1 (U-frame marker)
    pkt = _iec104_pkt(0x07)
    r = parse_iec104(pkt)
    assert r is not None
    assert r["frame_type"] == "U"


def test_iec104_i_frame_with_asdu():
    # I-frame: ctrl1 bit 0 = 0
    # ASDU: type_id=45 (Single Command), VSQ=1, COT=6 (Activation), CA=1, IOA=1
    asdu = bytes([45, 1, 6, 0, 1, 0, 1, 0, 0])
    pkt = _iec104_pkt(0x00, 0x00, 0x00, 0x00, asdu)
    r = parse_iec104(pkt)
    assert r is not None
    assert r["frame_type"] == "I"
    assert r["type_id"] == 45
    assert r["is_write"] is True  # type_id 45-50 with COT=6


def test_iec104_invalid_start():
    assert parse_iec104(b"\x69\x04" + b"\x00" * 10) is None


# ── Helpers ───────────────────────────────────────────────────────────────────

def test_modbus_write_multiple_registers():
    pkt = _modbus_pkt(1, 1, 16, struct.pack(">HH", 50, 5) + b"\x0a" + bytes(10))
    r = parse_modbus(pkt)
    assert r["function_code"] == 16
    assert r["is_write"] is True
    assert r["register_address"] == 50
    assert r["quantity"] == 5


# ── EtherNet/IP ───────────────────────────────────────────────────────────────

def _enip_hdr(command, session_handle=0, status=0, data=b""):
    """Build a minimal EtherNet/IP encapsulation header (24 bytes) + optional data."""
    length = len(data)
    sender_context = b"\x00" * 8
    options = 0
    hdr = struct.pack("<HHIIQ I",
        command, length, session_handle, status,
        int.from_bytes(sender_context, "little"), options)
    return hdr + data


def test_enip_register_session():
    pkt = _enip_hdr(0x0065, session_handle=0)
    r = parse_enip(pkt)
    assert r is not None
    assert r["command"] == 0x0065
    assert r["command_name"] == "Register Session"
    assert r["is_error"] is False
    assert r["is_write"] is False


def _enip_send_rr(cip_service_byte):
    """Build a Send RR Data payload whose CIP service byte lands at data[10].
    Parser uses cip_offset=10: interface_handle(4)+timeout(2)+item_count(2)+null_type(2)=10 bytes."""
    cpf = struct.pack("<IHHH", 0, 0, 2, 0x0000) + bytes([cip_service_byte])
    return _enip_hdr(0x006F, data=cpf)


def test_enip_send_rr_data_read_tag():
    pkt = _enip_send_rr(0x4C)
    r = parse_enip(pkt)
    assert r is not None
    assert r["command_name"] == "Send RR Data"
    assert r["cip_service"] == 0x4C
    assert r["cip_service_name"] == "Read Tag"
    assert r["is_write"] is False
    assert r["is_response"] is False


def test_enip_send_rr_data_write_tag():
    pkt = _enip_send_rr(0x4D)
    r = parse_enip(pkt)
    assert r is not None
    assert r["cip_service"] == 0x4D
    assert r["cip_service_name"] == "Write Tag"
    assert r["is_write"] is True


def test_enip_error_status():
    pkt = _enip_hdr(0x0065, status=0x0008)  # non-zero status = error
    r = parse_enip(pkt)
    assert r is not None
    assert r["is_error"] is True


def test_enip_too_short():
    assert parse_enip(b"\x65\x00\x04\x00") is None


def test_enip_empty():
    assert parse_enip(b"") is None
    assert parse_enip(None) is None


def test_enip_unknown_command():
    pkt = _enip_hdr(0x9999)
    r = parse_enip(pkt)
    assert r is not None
    assert "Unknown" in r["command_name"]
