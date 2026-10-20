# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Tyler M

# scapy.contrib.description = DICOM (Digital Imaging and Communications in Medicine)
# scapy.contrib.status = loads

"""
DICOM (Digital Imaging and Communications in Medicine) Protocol
Reference: DICOM PS3.8 - Network Communication Support for Message Exchange
https://dicom.nema.org/medical/dicom/current/output/html/part08.html
"""

import logging
import socket
import ssl
import struct
import threading
import time
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    Union,
)

from scapy.arch import get_if_addr
from scapy.compat import Self, plain_str
from scapy.config import conf
from scapy.error import Scapy_Exception
from scapy.fields import (
    BitField,
    ByteEnumField,
    ByteField,
    Field,
    FieldLenField,
    IntField,
    LenField,
    MultiEnumField,
    PacketListField,
    ShortField,
    StrFixedLenField,
    StrLenField,
)
from scapy.layers.inet import TCP
from scapy.packet import Packet, bind_layers
from scapy.supersocket import SSLStreamSocket, StreamSocket
from scapy.volatile import RandInt, RandNum, RandShort, RandString

__all__ = [
    "APP_CONTEXT_UID",
    "A_ABORT",
    "A_ASSOCIATE_AC",
    "A_ASSOCIATE_RJ",
    "A_ASSOCIATE_RQ",
    "A_RELEASE_RP",
    "A_RELEASE_RQ",
    "CT_IMAGE_STORAGE_SOP_CLASS_UID",
    "C_CANCEL_RQ",
    "C_ECHO_RQ",
    "C_ECHO_RSP",
    "C_FIND_RQ",
    "C_FIND_RSP",
    "C_GET_RQ",
    "C_GET_RSP",
    "C_MOVE_RQ",
    "C_MOVE_RSP",
    "C_STORE_RQ",
    "C_STORE_RSP",
    "DEFAULT_TRANSFER_SYNTAX_UID",
    "DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN_UID",
    "DICOM",
    "DICOMAEDIMSEField",
    "DICOMAETitleField",
    "DICOMATField",
    "DICOMAbstractSyntax",
    "DICOMApplicationContext",
    "DICOMAsyncOperationsWindow",
    "DICOMElementField",
    "DICOMGenericItem",
    "DICOMImplementationClassUID",
    "DICOMImplementationVersionName",
    "DICOMMaximumLength",
    "DICOMPresentationContextAC",
    "DICOMPresentationContextRQ",
    "DICOMSCPSCURoleSelection",
    "DICOMSOPClassCommonExtendedNegotiation",
    "DICOMSOPClassExtendedNegotiation",
    "DICOMSocket",
    "DICOMTransferSyntax",
    "DICOMUIDField",
    "DICOMUIDFieldRaw",
    "DICOMULField",
    "DICOMUSField",
    "DICOMUserIdentity",
    "DICOMUserIdentityResponse",
    "DICOMUserInformation",
    "DICOMVariableItem",
    "DICOM_Client",
    "DICOM_IMPLEMENTATION_CLASS_UID",
    "DICOM_PORT",
    "DICOM_PORT_ALT",
    "DICOM_Server",
    "DIMSEPacket",
    "DIMSE_STATUS_CODES",
    "EXPLICIT_VR_BIG_ENDIAN_UID",
    "EXPLICIT_VR_LITTLE_ENDIAN_UID",
    "HTJ2K_LOSSLESS_RPCL_UID",
    "HTJ2K_LOSSLESS_UID",
    "HTJ2K_UID",
    "IMPLICIT_VR_LITTLE_ENDIAN_UID",
    "JPEG_2000_LOSSLESS_UID",
    "JPEG_2000_UID",
    "JPEG_BASELINE_UID",
    "JPEG_LOSSLESS_UID",
    "JPEG_LS_LOSSLESS_UID",
    "JPEG_LS_LOSSY_UID",
    "MODALITY_WORKLIST_FIND_SOP_CLASS_UID",
    "MR_IMAGE_STORAGE_SOP_CLASS_UID",
    "N_ACTION_RQ",
    "N_ACTION_RSP",
    "N_CREATE_RQ",
    "N_CREATE_RSP",
    "N_DELETE_RQ",
    "N_DELETE_RSP",
    "N_EVENT_REPORT_RQ",
    "N_EVENT_REPORT_RSP",
    "N_GET_RQ",
    "N_GET_RSP",
    "N_SET_RQ",
    "N_SET_RSP",
    "PATIENT_ROOT_QR_FIND_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_GET_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID",
    "P_DATA_TF",
    "PresentationDataValueItem",
    "RLE_LOSSLESS_UID",
    "SECONDARY_CAPTURE_SOP_CLASS_UID",
    "STUDY_ROOT_QR_FIND_SOP_CLASS_UID",
    "STUDY_ROOT_QR_GET_SOP_CLASS_UID",
    "STUDY_ROOT_QR_MOVE_SOP_CLASS_UID",
    "VERIFICATION_SOP_CLASS_UID",
    "_uid_to_bytes",
    "_uid_to_bytes_raw",
    "build_presentation_context_rq",
    "build_user_information",
    "dicom_build_p_data_tf",
    "parse_dimse_status",
]

log_dicom = logging.getLogger("scapy.contrib.dicom")

DICOM_PORT = 104
DICOM_PORT_ALT = 11112
# UUID derived UID (PS3.5 B.2) of uuid5(NAMESPACE_URL, "https://scapy.net/")
DICOM_IMPLEMENTATION_CLASS_UID = "2.25.215909175953424803731768305582361092425"
APP_CONTEXT_UID = "1.2.840.10008.3.1.1.1"
DEFAULT_TRANSFER_SYNTAX_UID = "1.2.840.10008.1.2"
VERIFICATION_SOP_CLASS_UID = "1.2.840.10008.1.1"
CT_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.2"
MR_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.4"
SECONDARY_CAPTURE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.7"

# Transfer Syntax UIDs (PS3.5 Annex A)
IMPLICIT_VR_LITTLE_ENDIAN_UID = DEFAULT_TRANSFER_SYNTAX_UID
EXPLICIT_VR_LITTLE_ENDIAN_UID = "1.2.840.10008.1.2.1"
DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN_UID = "1.2.840.10008.1.2.1.99"
EXPLICIT_VR_BIG_ENDIAN_UID = "1.2.840.10008.1.2.2"
JPEG_BASELINE_UID = "1.2.840.10008.1.2.4.50"
JPEG_LOSSLESS_UID = "1.2.840.10008.1.2.4.70"
JPEG_LS_LOSSLESS_UID = "1.2.840.10008.1.2.4.80"
JPEG_LS_LOSSY_UID = "1.2.840.10008.1.2.4.81"
JPEG_2000_LOSSLESS_UID = "1.2.840.10008.1.2.4.90"
JPEG_2000_UID = "1.2.840.10008.1.2.4.91"
HTJ2K_LOSSLESS_UID = "1.2.840.10008.1.2.4.201"
HTJ2K_LOSSLESS_RPCL_UID = "1.2.840.10008.1.2.4.202"
HTJ2K_UID = "1.2.840.10008.1.2.4.203"
RLE_LOSSLESS_UID = "1.2.840.10008.1.2.5"

PATIENT_ROOT_QR_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.1"
PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.2"
PATIENT_ROOT_QR_GET_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.3"
STUDY_ROOT_QR_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.1"
STUDY_ROOT_QR_MOVE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.2"
STUDY_ROOT_QR_GET_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.3"
MODALITY_WORKLIST_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.31"

PDU_TYPES = {
    0x01: "A-ASSOCIATE-RQ",
    0x02: "A-ASSOCIATE-AC",
    0x03: "A-ASSOCIATE-RJ",
    0x04: "P-DATA-TF",
    0x05: "A-RELEASE-RQ",
    0x06: "A-RELEASE-RP",
    0x07: "A-ABORT",
}

ITEM_TYPES = {
    0x10: "Application Context",
    0x20: "Presentation Context RQ",
    0x21: "Presentation Context AC",
    0x30: "Abstract Syntax",
    0x40: "Transfer Syntax",
    0x50: "User Information",
    0x51: "Maximum Length",
    0x52: "Implementation Class UID",
    0x53: "Asynchronous Operations Window",
    0x54: "SCP/SCU Role Selection",
    0x55: "Implementation Version Name",
    0x56: "SOP Class Extended Negotiation",
    0x57: "SOP Class Common Extended Negotiation",
    0x58: "User Identity",
    0x59: "User Identity Server Response",
}


def _uid_to_bytes(uid: Union[str, bytes]) -> bytes:
    """Convert UID to bytes with even-length padding (null byte if needed)."""
    if isinstance(uid, bytes):
        b_uid = uid
    elif isinstance(uid, str):
        b_uid = uid.encode("ascii")
    else:
        return b""
    if len(b_uid) % 2 != 0:
        b_uid += b"\x00"
    return b_uid


def _uid_to_bytes_raw(uid: Union[str, bytes]) -> bytes:
    """Convert UID to bytes without padding."""
    if isinstance(uid, bytes):
        return uid
    elif isinstance(uid, str):
        return uid.encode("ascii")
    else:
        return b""


class DICOMAETitleField(StrFixedLenField):
    """DICOM AE Title field - 16 bytes, space-padded per PS3.5 Section 6.2."""

    def __init__(self, name: str, default: bytes = b"") -> None:
        super(DICOMAETitleField, self).__init__(name, default, length=16)

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        return val.ljust(16, b" ")[:16]

    def m2i(self, pkt: Optional[Packet], val: bytes) -> bytes:
        return val

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").rstrip()
        return str(val).rstrip()


class DICOMElementField(Field[Any, bytes]):
    """DICOM data element field with explicit tag and length encoding."""

    __slots__ = ["tag_group", "tag_elem"]

    def __init__(self, name: str, default: Any, tag_group: int,
                 tag_elem: int) -> None:
        self.tag_group = tag_group
        self.tag_elem = tag_elem
        Field.__init__(self, name, default)

    def addfield(self, pkt: Optional[Packet], s: bytes, val: Any) -> bytes:
        # None omits the element (optional or automatically computed)
        if val is None:
            return s
        val = self.i2m(pkt, val)
        hdr = struct.pack("<HHI", self.tag_group, self.tag_elem, len(val))
        return s + hdr + val

    def getfield(self, pkt: Optional[Packet], s: bytes) -> Tuple[bytes, Any]:
        if len(s) < 8:
            return s, None
        tag_g, tag_e, length = struct.unpack("<HHI", s[:8])
        # Another tag means that this element is absent
        if (tag_g, tag_e) != (self.tag_group, self.tag_elem):
            return s, None
        # Ensure the buffer contains the full value as declared by the length
        if len(s) < 8 + length:
            raise Scapy_Exception(
                "Not enough bytes to decode DICOM element value: "
                f"expected {length} bytes, only {len(s) - 8} available"
            )
        return s[8 + length:], self.m2i(pkt, s[8:8 + length])

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        if isinstance(val, str):
            return val.encode("ascii")
        return val

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            try:
                return val.decode("ascii").rstrip("\x00")
            except UnicodeDecodeError:
                return val.hex()
        return repr(val)

    def randval(self) -> RandString:
        return RandString(8)


class DICOMUIDField(DICOMElementField):
    """DICOM UID element field with automatic even-length padding."""

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        return _uid_to_bytes(val)

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        return plain_str(val).rstrip("\x00")

    def randval(self) -> str:
        return "1.2.3.%d.%d.%d" % (
            RandNum(1, 99999)._fix(),
            RandNum(1, 99999)._fix(),
            RandNum(1, 99999)._fix()
        )


class DICOMUIDFieldRaw(DICOMElementField):
    """DICOM UID element field without automatic padding."""

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        return _uid_to_bytes_raw(val)


class DICOMUSField(DICOMElementField):
    """DICOM Unsigned Short (US) element field."""

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        return struct.pack("<H", val)

    def m2i(self, pkt: Optional[Packet], val: bytes) -> int:
        if len(val) >= 2:
            return struct.unpack("<H", val[:2])[0]
        return 0

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if val is None:
            return repr(val)
        return "0x%04X" % val

    def randval(self) -> RandShort:
        return RandShort()


class DICOMULField(DICOMElementField):
    """DICOM Unsigned Long (UL) element field."""

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        return struct.pack("<I", val)

    def m2i(self, pkt: Optional[Packet], val: bytes) -> int:
        if len(val) >= 4:
            return struct.unpack("<I", val[:4])[0]
        return 0

    def randval(self) -> RandInt:
        return RandInt()


class DICOMAEDIMSEField(DICOMElementField):
    """DICOM AE element field for DIMSE - 16 bytes, space-padded."""

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        if isinstance(val, str):
            val = val.encode("ascii")
        return val.ljust(16, b" ")[:16]

    def i2repr(self, pkt: Optional[Packet], val: Any) -> str:
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").strip()
        return str(val).strip()


class DICOMATField(DICOMElementField):
    """DICOM Attribute Tag (AT) element field: a list of (group, element)."""

    # The list is a single value, not a set of values to iterate on
    islist = 1

    def i2m(self, pkt: Optional[Packet], val: Any) -> bytes:
        return b"".join(struct.pack("<HH", group, elem) for group, elem in val)

    def m2i(self, pkt: Optional[Packet], val: bytes) -> List[Tuple[int, int]]:
        return [
            struct.unpack("<HH", val[i:i + 4])
            for i in range(0, len(val) - 3, 4)
        ]

    def randval(self) -> List[Tuple[int, int]]:
        return []


def _dimse_us_element(dimse_bytes: bytes, tag_elem: int) -> Optional[int]:
    """Extract a US element of the command group from DIMSE command bytes."""
    try:
        if len(dimse_bytes) < 12:
            return None
        cmd_group_len = struct.unpack("<I", dimse_bytes[8:12])[0]
        offset = 12
        group_end_offset = offset + cmd_group_len
        while offset < group_end_offset and offset + 8 <= len(dimse_bytes):
            tag_group, elem = struct.unpack(
                "<HH", dimse_bytes[offset:offset + 4]
            )
            value_len = struct.unpack(
                "<I", dimse_bytes[offset + 4:offset + 8]
            )[0]
            if (
                tag_group == 0x0000
                and elem == tag_elem
                and value_len == 2
            ):
                # Ensure there are at least 2 bytes available for the value
                if offset + 10 > len(dimse_bytes) or offset + 10 > group_end_offset:
                    break
                return struct.unpack(
                    "<H", dimse_bytes[offset + 8:offset + 10]
                )[0]
            offset += 8 + value_len
    except struct.error:
        return None
    return None


class DIMSEPacket(Packet):
    """Base class for DIMSE command packets with automatic group length."""

    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt: Optional[bytes] = None, *args: Any,
                      **kargs: Any) -> Type[Packet]:
        # Pick the command class from the Command Field (0000,0100)
        command_field = _dimse_us_element(_pkt or b"", 0x0100)
        for command_cls in cls.__subclasses__():
            if command_cls.command_field.default == command_field:
                return command_cls
        return cls

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.command_group_length is None:
            pkt = struct.pack("<HHII", 0x0000, 0x0000, 4, len(pkt)) + pkt
        return pkt + pay


DIMSE_COMMAND_FIELDS = {
    0x0001: "C-STORE-RQ",
    0x8001: "C-STORE-RSP",
    0x0020: "C-FIND-RQ",
    0x8020: "C-FIND-RSP",
    0x0010: "C-GET-RQ",
    0x8010: "C-GET-RSP",
    0x0021: "C-MOVE-RQ",
    0x8021: "C-MOVE-RSP",
    0x0030: "C-ECHO-RQ",
    0x8030: "C-ECHO-RSP",
    0x0FFF: "C-CANCEL-RQ",
    0x0100: "N-EVENT-REPORT-RQ",
    0x8100: "N-EVENT-REPORT-RSP",
    0x0110: "N-GET-RQ",
    0x8110: "N-GET-RSP",
    0x0120: "N-SET-RQ",
    0x8120: "N-SET-RSP",
    0x0130: "N-ACTION-RQ",
    0x8130: "N-ACTION-RSP",
    0x0140: "N-CREATE-RQ",
    0x8140: "N-CREATE-RSP",
    0x0150: "N-DELETE-RQ",
    0x8150: "N-DELETE-RSP",
}

DATA_SET_TYPES = {
    0x0000: "Data Set Present",
    0x0001: "Data Set Present",
    0x0101: "No Data Set",
}

PRIORITY_VALUES = {
    0x0000: "MEDIUM",
    0x0001: "HIGH",
    0x0002: "LOW",
}

# DIMSE status codes (PS3.7 Annex C)
DIMSE_STATUS_CODES = {
    0x0000: "Success",
    0x0105: "No such attribute",
    0x0106: "Invalid attribute value",
    0x0107: "Attribute list error",
    0x0110: "Processing failure",
    0x0111: "Duplicate SOP instance",
    0x0112: "No such SOP instance",
    0x0113: "No such event type",
    0x0114: "No such argument",
    0x0115: "Invalid argument value",
    0x0116: "Attribute value out of range",
    0x0117: "Invalid object instance",
    0x0118: "No such SOP class",
    0x0119: "Class-instance conflict",
    0x0120: "Missing attribute",
    0x0121: "Missing attribute value",
    0x0122: "Refused: SOP class not supported",
    0x0123: "No such action type",
    0x0124: "Refused: not authorized",
    0x0210: "Duplicate invocation",
    0x0211: "Unrecognized operation",
    0x0212: "Mistyped argument",
    0x0213: "Resource limitation",
    0xFE00: "Cancel",
    0xFF00: "Pending",
    0xFF01: "Pending: optional keys not supported",
}


class C_ECHO_RQ(DIMSEPacket):
    """C-ECHO-RQ DIMSE Command for verification."""

    name = "C-ECHO-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0030, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-ECHO-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_ECHO_RSP(DIMSEPacket):
    """C-ECHO-RSP DIMSE Response."""

    name = "C-ECHO-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8030, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-ECHO-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_ECHO_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_STORE_RQ(DIMSEPacket):
    """C-STORE-RQ DIMSE Command for storing DICOM objects."""

    name = "C-STORE-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0001, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid",
                      "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
        # Only present in the C-STORE sub-operations of a C-MOVE
        DICOMAEDIMSEField("move_originator_ae_title", None, 0x0000, 0x1030),
        DICOMUSField("move_originator_message_id", None, 0x0000, 0x1031),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-STORE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_STORE_RSP(DIMSEPacket):
    """C-STORE-RSP DIMSE Response."""

    name = "C-STORE-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8001, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMATField("offending_element", None, 0x0000, 0x0901),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
        DICOMUIDField("affected_sop_instance_uid",
                      "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-STORE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_STORE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_FIND_RQ(DIMSEPacket):
    """C-FIND-RQ DIMSE Command for querying DICOM objects."""

    name = "C-FIND-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0020, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-FIND-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_FIND_RSP(DIMSEPacket):
    """C-FIND-RSP DIMSE Response."""

    name = "C-FIND-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8020, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMATField("offending_element", None, 0x0000, 0x0901),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-FIND-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_FIND_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_MOVE_RQ(DIMSEPacket):
    """C-MOVE-RQ DIMSE Command for retrieving DICOM objects."""

    name = "C-MOVE-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0021, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMAEDIMSEField("move_destination", b"", 0x0000, 0x0600),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-MOVE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_MOVE_RSP(DIMSEPacket):
    """C-MOVE-RSP DIMSE Response."""

    name = "C-MOVE-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8021, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMATField("offending_element", None, 0x0000, 0x0901),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
        DICOMUSField("num_remaining", 0, 0x0000, 0x1020),
        DICOMUSField("num_completed", 0, 0x0000, 0x1021),
        DICOMUSField("num_failed", 0, 0x0000, 0x1022),
        DICOMUSField("num_warning", 0, 0x0000, 0x1023),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-MOVE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_MOVE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_GET_RQ(DIMSEPacket):
    """C-GET-RQ DIMSE Command for retrieving objects on same association."""

    name = "C-GET-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_GET_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0010, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-GET-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class C_GET_RSP(DIMSEPacket):
    """C-GET-RSP DIMSE Response."""

    name = "C-GET-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_GET_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8010, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMATField("offending_element", None, 0x0000, 0x0901),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
        DICOMUSField("num_remaining", 0, 0x0000, 0x1020),
        DICOMUSField("num_completed", 0, 0x0000, 0x1021),
        DICOMUSField("num_failed", 0, 0x0000, 0x1022),
        DICOMUSField("num_warning", 0, 0x0000, 0x1023),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-GET-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, C_GET_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_CANCEL_RQ(DIMSEPacket):
    """C-CANCEL-RQ DIMSE Command for cancelling a C-FIND, C-GET or C-MOVE."""

    name = "C-CANCEL-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUSField("command_field", 0x0FFF, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
    ]

    def mysummary(self) -> str:
        return self.sprintf("C-CANCEL-RQ msg_id=%message_id_responded%")


class N_EVENT_REPORT_RQ(DIMSEPacket):
    """N-EVENT-REPORT-RQ DIMSE Command for reporting an event."""

    name = "N-EVENT-REPORT-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0100, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMUSField("event_type_id", 0, 0x0000, 0x1002),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-EVENT-REPORT-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_EVENT_REPORT_RSP(DIMSEPacket):
    """N-EVENT-REPORT-RSP DIMSE Response."""

    name = "N-EVENT-REPORT-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8100, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
        DICOMUSField("error_id", None, 0x0000, 0x0903),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMUSField("event_type_id", 0, 0x0000, 0x1002),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-EVENT-REPORT-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_EVENT_REPORT_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_GET_RQ(DIMSEPacket):
    """N-GET-RQ DIMSE Command for retrieving attribute values."""

    name = "N-GET-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0110, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
        DICOMATField("attribute_identifier_list", None, 0x0000, 0x1005),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-GET-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_GET_RSP(DIMSEPacket):
    """N-GET-RSP DIMSE Response."""

    name = "N-GET-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8110, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
        DICOMUSField("error_id", None, 0x0000, 0x0903),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMATField("attribute_identifier_list", None, 0x0000, 0x1005),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-GET-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_GET_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_SET_RQ(DIMSEPacket):
    """N-SET-RQ DIMSE Command for modifying attribute values."""

    name = "N-SET-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0120, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-SET-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_SET_RSP(DIMSEPacket):
    """N-SET-RSP DIMSE Response."""

    name = "N-SET-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8120, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
        DICOMUSField("error_id", None, 0x0000, 0x0903),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMATField("attribute_identifier_list", None, 0x0000, 0x1005),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-SET-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_SET_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_ACTION_RQ(DIMSEPacket):
    """N-ACTION-RQ DIMSE Command for performing an action."""

    name = "N-ACTION-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0130, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
        DICOMUSField("action_type_id", 0, 0x0000, 0x1008),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-ACTION-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_ACTION_RSP(DIMSEPacket):
    """N-ACTION-RSP DIMSE Response."""

    name = "N-ACTION-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8130, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
        DICOMUSField("error_id", None, 0x0000, 0x0903),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMUSField("action_type_id", 0, 0x0000, 0x1008),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-ACTION-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_ACTION_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_CREATE_RQ(DIMSEPacket):
    """N-CREATE-RQ DIMSE Command for creating a SOP Instance."""

    name = "N-CREATE-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0140, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-CREATE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_CREATE_RSP(DIMSEPacket):
    """N-CREATE-RSP DIMSE Response."""

    name = "N-CREATE-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8140, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
        DICOMUSField("error_id", None, 0x0000, 0x0903),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMATField("attribute_identifier_list", None, 0x0000, 0x1005),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-CREATE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_CREATE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_DELETE_RQ(DIMSEPacket):
    """N-DELETE-RQ DIMSE Command for deleting a SOP Instance."""

    name = "N-DELETE-RQ"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0150, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-DELETE-RQ msg_id=%message_id%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id)


class N_DELETE_RSP(DIMSEPacket):
    """N-DELETE-RSP DIMSE Response."""

    name = "N-DELETE-RSP"
    fields_desc = [
        DICOMULField("command_group_length", None, 0x0000, 0x0000),
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8150, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMElementField("error_comment", None, 0x0000, 0x0902),
        DICOMUSField("error_id", None, 0x0000, 0x0903),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self) -> str:
        return self.sprintf("N-DELETE-RSP status=%status%")

    def hashret(self) -> bytes:
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other: Packet) -> int:
        if isinstance(other, N_DELETE_RQ):
            return self.message_id_responded == other.message_id
        return 0


def parse_dimse_status(dimse_bytes: bytes) -> Optional[int]:
    """Extract status code from DIMSE response bytes."""
    return _dimse_us_element(dimse_bytes, 0x0900)


class DICOMGenericItem(Packet):
    """Generic fallback for unrecognized DICOM variable items."""

    name = "DICOM Generic Item"
    fields_desc = [
        StrLenField(
            "data", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.data)
            )
        ),
    ]


class DICOMVariableItem(Packet):
    """DICOM variable item header with type and length fields."""

    name = "DICOM Variable Item"
    fields_desc = [
        ByteEnumField("item_type", 0x10, ITEM_TYPES),
        ByteField("reserved", 0),
        LenField("length", None, fmt="!H"),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        if self.length is not None:
            if len(s) < self.length:
                raise Scapy_Exception("PDU payload incomplete")
            return s[:self.length], s[self.length:]
        return s, b""

    def mysummary(self) -> str:
        return self.sprintf("Item %item_type%")


class DICOMApplicationContext(Packet):
    """DICOM Application Context item."""

    name = "DICOM Application Context"
    fields_desc = [
        StrLenField(
            "uid", _uid_to_bytes_raw(APP_CONTEXT_UID),
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def mysummary(self) -> str:
        return "AppContext %s" % plain_str(self.uid).rstrip("\x00")


class DICOMAbstractSyntax(Packet):
    """DICOM Abstract Syntax item."""

    name = "DICOM Abstract Syntax"
    fields_desc = [
        StrLenField(
            "uid", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def mysummary(self) -> str:
        return "AbstractSyntax %s" % plain_str(self.uid).rstrip("\x00")


class DICOMTransferSyntax(Packet):
    """DICOM Transfer Syntax item."""

    name = "DICOM Transfer Syntax"
    fields_desc = [
        StrLenField(
            "uid", _uid_to_bytes_raw(DEFAULT_TRANSFER_SYNTAX_UID),
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def mysummary(self) -> str:
        return "TransferSyntax %s" % plain_str(self.uid).rstrip("\x00")


class DICOMPresentationContextRQ(Packet):
    """DICOM Presentation Context item for association requests."""

    name = "DICOM Presentation Context RQ"
    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("reserved3", 0),
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=64,
            length_from=lambda pkt: (
                pkt.underlayer.length - 4
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        return "PresentationContext-RQ ctx_id=%d" % self.context_id


class DICOMPresentationContextAC(Packet):
    """DICOM Presentation Context item for association accepts."""

    name = "DICOM Presentation Context AC"

    RESULT_CODES = {
        0: "acceptance",
        1: "user-rejection",
        2: "no-reason",
        3: "abstract-syntax-not-supported",
        4: "transfer-syntaxes-not-supported",
    }

    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteEnumField("result", 0, RESULT_CODES),
        ByteField("reserved2", 0),
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=8,
            length_from=lambda pkt: (
                pkt.underlayer.length - 4
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        return self.sprintf(
            "PresentationContext-AC ctx_id=%context_id% result=%result%"
        )


class DICOMMaximumLength(Packet):
    """DICOM Maximum Length sub-item (0 means no maximum)."""

    name = "DICOM Maximum Length"
    fields_desc = [
        IntField("max_pdu_length", 16384),
    ]

    def mysummary(self) -> str:
        if self.max_pdu_length == 0:
            return "MaxLength unlimited"
        return "MaxLength %d" % self.max_pdu_length


class DICOMImplementationClassUID(Packet):
    """DICOM Implementation Class UID sub-item."""

    name = "DICOM Implementation Class UID"
    fields_desc = [
        StrLenField(
            "uid", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.uid)
            )
        ),
    ]

    def mysummary(self) -> str:
        return "ImplClassUID %s" % plain_str(self.uid).rstrip("\x00")


class DICOMImplementationVersionName(Packet):
    """DICOM Implementation Version Name sub-item."""

    name = "DICOM Implementation Version Name"
    fields_desc = [
        StrLenField(
            "version_name", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else len(pkt.version_name)
            )
        ),
    ]

    def mysummary(self) -> str:
        return "ImplVersion %s" % plain_str(self.version_name).rstrip("\x00")


class DICOMAsyncOperationsWindow(Packet):
    """DICOM Asynchronous Operations Window sub-item."""

    name = "DICOM Async Operations Window"
    fields_desc = [
        ShortField("max_ops_invoked", 1),
        ShortField("max_ops_performed", 1),
    ]

    def mysummary(self) -> str:
        return "AsyncOps inv=%d perf=%d" % (
            self.max_ops_invoked, self.max_ops_performed
        )


class DICOMSCPSCURoleSelection(Packet):
    """DICOM SCP/SCU Role Selection sub-item."""

    name = "DICOM SCP/SCU Role Selection"
    fields_desc = [
        FieldLenField("uid_length", None, length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.uid_length),
        ByteField("scu_role", 0),
        ByteField("scp_role", 0),
    ]

    def mysummary(self) -> str:
        return "RoleSelection SCU=%d SCP=%d" % (self.scu_role, self.scp_role)


class DICOMSOPClassExtendedNegotiation(Packet):
    """DICOM SOP Class Extended Negotiation sub-item (PS3.7 D.3.3.5)."""

    name = "DICOM SOP Class Extended Negotiation"
    fields_desc = [
        FieldLenField("sop_class_uid_length", None,
                      length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.sop_class_uid_length),
        StrLenField("service_class_application_information", b"",
                    length_from=lambda pkt: (
                        pkt.underlayer.length - 2 - pkt.sop_class_uid_length
                        if pkt.underlayer and pkt.underlayer.length
                        else 0
                    )),
    ]

    def mysummary(self) -> str:
        return "SOPClassExtNeg %s" % plain_str(self.sop_class_uid).rstrip("\x00")


class DICOMSOPClassCommonExtendedNegotiation(Packet):
    """DICOM SOP Class Common Extended Negotiation sub-item (PS3.7 D.3.3.6)."""

    name = "DICOM SOP Class Common Extended Negotiation"
    fields_desc = [
        FieldLenField("sop_class_uid_length", None,
                      length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.sop_class_uid_length),
        FieldLenField("service_class_uid_length", None,
                      length_of="service_class_uid", fmt="!H"),
        StrLenField("service_class_uid", b"",
                    length_from=lambda pkt: pkt.service_class_uid_length),
        FieldLenField("related_sop_class_uid_length", None,
                      length_of="related_sop_class_uids", fmt="!H"),
        StrLenField("related_sop_class_uids", b"",
                    length_from=lambda pkt: pkt.related_sop_class_uid_length),
    ]

    def mysummary(self) -> str:
        uid = plain_str(self.sop_class_uid).rstrip("\x00")
        return "SOPClassCommonExtNeg %s" % uid


USER_IDENTITY_TYPES = {
    1: "Username",
    2: "Username and Passcode",
    3: "Kerberos Service Ticket",
    4: "SAML Assertion",
    5: "JSON Web Token (JWT)",
}


class DICOMUserIdentity(Packet):
    """DICOM User Identity sub-item."""

    name = "DICOM User Identity"
    fields_desc = [
        ByteEnumField("user_identity_type", 1, USER_IDENTITY_TYPES),
        ByteField("positive_response_requested", 0),
        FieldLenField("primary_field_length", None,
                      length_of="primary_field", fmt="!H"),
        StrLenField("primary_field", b"",
                    length_from=lambda pkt: pkt.primary_field_length),
        # Always present, only non-empty for Username and Passcode
        FieldLenField("secondary_field_length", None,
                      length_of="secondary_field", fmt="!H"),
        StrLenField("secondary_field", b"",
                    length_from=lambda pkt: pkt.secondary_field_length),
    ]

    def mysummary(self) -> str:
        return self.sprintf("UserIdentity %user_identity_type%")


class DICOMUserIdentityResponse(Packet):
    """DICOM User Identity Server Response sub-item."""

    name = "DICOM User Identity Response"
    fields_desc = [
        FieldLenField("response_length", None,
                      length_of="server_response", fmt="!H"),
        StrLenField("server_response", b"",
                    length_from=lambda pkt: pkt.response_length),
    ]

    def mysummary(self) -> str:
        return "UserIdentityResponse"


class DICOMUserInformation(Packet):
    """DICOM User Information item."""

    name = "DICOM User Information"
    fields_desc = [
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        return "UserInfo (%d items)" % len(self.sub_items)


bind_layers(DICOMVariableItem, DICOMApplicationContext, item_type=0x10)
bind_layers(DICOMVariableItem, DICOMPresentationContextRQ, item_type=0x20)
bind_layers(DICOMVariableItem, DICOMPresentationContextAC, item_type=0x21)
bind_layers(DICOMVariableItem, DICOMAbstractSyntax, item_type=0x30)
bind_layers(DICOMVariableItem, DICOMTransferSyntax, item_type=0x40)
bind_layers(DICOMVariableItem, DICOMUserInformation, item_type=0x50)
bind_layers(DICOMVariableItem, DICOMMaximumLength, item_type=0x51)
bind_layers(DICOMVariableItem, DICOMImplementationClassUID, item_type=0x52)
bind_layers(DICOMVariableItem, DICOMAsyncOperationsWindow, item_type=0x53)
bind_layers(DICOMVariableItem, DICOMSCPSCURoleSelection, item_type=0x54)
bind_layers(DICOMVariableItem, DICOMImplementationVersionName, item_type=0x55)
bind_layers(DICOMVariableItem, DICOMSOPClassExtendedNegotiation, item_type=0x56)
bind_layers(DICOMVariableItem, DICOMSOPClassCommonExtendedNegotiation, item_type=0x57)
bind_layers(DICOMVariableItem, DICOMUserIdentity, item_type=0x58)
bind_layers(DICOMVariableItem, DICOMUserIdentityResponse, item_type=0x59)
bind_layers(DICOMVariableItem, DICOMGenericItem)


class DICOM(Packet):
    """DICOM Upper Layer (UL) PDU header."""

    name = "DICOM UL"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, PDU_TYPES),
        ByteField("reserved1", 0),
        LenField("length", None, fmt="!I"),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        if self.length is not None:
            return s[:self.length], s[self.length:]
        return s, b""

    @classmethod
    def tcp_reassemble(cls, data: bytes, metadata: Dict[str, Any],
                       session: Dict[str, Any]) -> Optional[Packet]:
        if len(data) < 6:
            return None
        length = struct.unpack("!I", data[2:6])[0] + 6
        if len(data) >= length:
            return cls(data)
        return None

    def mysummary(self) -> str:
        return self.sprintf("DICOM %pdu_type%")


class PresentationDataValueItem(Packet):
    """Presentation Data Value (PDV) item within P-DATA-TF PDU."""

    name = "PresentationDataValueItem"
    fields_desc = [
        FieldLenField("length", None, length_of="data", fmt="!I",
                      adjust=lambda pkt, x: x + 2),
        ByteField("context_id", 1),
        BitField("reserved_bits", 0, 6),
        BitField("is_last", 0, 1),
        BitField("is_command", 0, 1),
        StrLenField("data", b"",
                    length_from=lambda pkt: max(0, (pkt.length or 2) - 2)),
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, bytes]:
        return b"", s

    def mysummary(self) -> str:
        cmd_or_data = "CMD" if self.is_command else "DATA"
        last = " LAST" if self.is_last else ""
        return "PDV ctx=%d %s%s len=%d" % (
            self.context_id, cmd_or_data, last, len(self.data)
        )


class A_ASSOCIATE_RQ(Packet):
    """A-ASSOCIATE-RQ PDU for initiating DICOM associations."""

    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        DICOMAETitleField("called_ae_title", b""),
        DICOMAETitleField("calling_ae_title", b""),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField(
            "variable_items", [],
            DICOMVariableItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length - 68
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        called = self.called_ae_title.strip().decode("ascii", errors="replace")
        calling = self.calling_ae_title.strip().decode("ascii", errors="replace")
        return "A-ASSOCIATE-RQ %s -> %s" % (calling, called)


class A_ASSOCIATE_AC(Packet):
    """A-ASSOCIATE-AC PDU for accepting DICOM associations."""

    name = "A-ASSOCIATE-AC"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        DICOMAETitleField("called_ae_title", b""),
        DICOMAETitleField("calling_ae_title", b""),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField(
            "variable_items", [],
            DICOMVariableItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length - 68
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        called = self.called_ae_title.strip().decode("ascii", errors="replace")
        calling = self.calling_ae_title.strip().decode("ascii", errors="replace")
        return "A-ASSOCIATE-AC %s <- %s" % (calling, called)

    def answers(self, other: Packet) -> bool:
        return isinstance(other, A_ASSOCIATE_RQ)


class A_ASSOCIATE_RJ(Packet):
    """A-ASSOCIATE-RJ PDU for rejecting DICOM associations."""

    name = "A-ASSOCIATE-RJ"

    RESULT_CODES = {
        1: "rejected-permanent",
        2: "rejected-transient",
    }

    SOURCE_CODES = {
        1: "DICOM UL service-user",
        2: "DICOM UL service-provider (ACSE)",
        3: "DICOM UL service-provider (Presentation)",
    }

    # Reason/Diag. values depend on the source (PS3.8 Table 9-21)
    REASON_CODES = {
        1: {
            1: "no-reason-given",
            2: "application-context-name-not-supported",
            3: "calling-AE-title-not-recognized",
            7: "called-AE-title-not-recognized",
        },
        2: {
            1: "no-reason-given",
            2: "protocol-version-not-supported",
        },
        3: {
            1: "temporary-congestion",
            2: "local-limit-exceeded",
        },
    }

    fields_desc = [
        ByteField("reserved1", 0),
        ByteEnumField("result", 1, RESULT_CODES),
        ByteEnumField("source", 1, SOURCE_CODES),
        MultiEnumField("reason_diag", 1, REASON_CODES,
                       depends_on=lambda pkt: pkt.source, fmt="B"),
    ]

    def mysummary(self) -> str:
        return self.sprintf("A-ASSOCIATE-RJ %result% %source%")

    def answers(self, other: Packet) -> bool:
        return isinstance(other, A_ASSOCIATE_RQ)


class P_DATA_TF(Packet):
    """P-DATA-TF PDU for transferring DICOM data."""

    name = "P-DATA-TF"
    fields_desc = [
        PacketListField(
            "pdv_items", [],
            PresentationDataValueItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and pkt.underlayer.length
                else 0
            )
        ),
    ]

    def mysummary(self) -> str:
        return "P-DATA-TF (%d PDVs)" % len(self.pdv_items)

    def answers(self, other: Packet) -> bool:
        # A DIMSE response carries the Message ID (0000,0110) of its request
        # in Message ID Being Responded To (0000,0120)
        if not isinstance(other, P_DATA_TF):
            return False
        requests = [
            (pdv.context_id, _dimse_us_element(pdv.data, 0x0110))
            for pdv in other.pdv_items if pdv.is_command
        ]
        for pdv in self.pdv_items:
            message_id = _dimse_us_element(pdv.data, 0x0120)
            if (pdv.is_command and message_id is not None and
                    (pdv.context_id, message_id) in requests):
                return True
        return False


class A_RELEASE_RQ(Packet):
    """A-RELEASE-RQ PDU for requesting association release."""

    name = "A-RELEASE-RQ"
    fields_desc = [IntField("reserved1", 0)]

    def mysummary(self) -> str:
        return "A-RELEASE-RQ"


class A_RELEASE_RP(Packet):
    """A-RELEASE-RP PDU for confirming association release."""

    name = "A-RELEASE-RP"
    fields_desc = [IntField("reserved1", 0)]

    def mysummary(self) -> str:
        return "A-RELEASE-RP"

    def answers(self, other: Packet) -> bool:
        return isinstance(other, A_RELEASE_RQ)


class A_ABORT(Packet):
    """A-ABORT PDU for aborting DICOM associations."""

    name = "A-ABORT"

    SOURCE_CODES = {
        0: "DICOM UL service-user",
        2: "DICOM UL service-provider",
    }

    # Reason/Diag. values, only significant for a provider abort (PS3.8 9.3.8)
    REASON_CODES = {
        2: {
            0: "reason-not-specified",
            1: "unrecognized-PDU",
            2: "unexpected-PDU",
            4: "unrecognized-PDU-parameter",
            5: "unexpected-PDU-parameter",
            6: "invalid-PDU-parameter-value",
        },
    }

    fields_desc = [
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteEnumField("source", 0, SOURCE_CODES),
        MultiEnumField("reason_diag", 0, REASON_CODES,
                       depends_on=lambda pkt: pkt.source, fmt="B"),
    ]

    def mysummary(self) -> str:
        return self.sprintf("A-ABORT %source%")


bind_layers(TCP, DICOM, dport=DICOM_PORT)
bind_layers(TCP, DICOM, sport=DICOM_PORT)
bind_layers(TCP, DICOM, dport=DICOM_PORT_ALT)
bind_layers(TCP, DICOM, sport=DICOM_PORT_ALT)
bind_layers(DICOM, A_ASSOCIATE_RQ, pdu_type=0x01)
bind_layers(DICOM, A_ASSOCIATE_AC, pdu_type=0x02)
bind_layers(DICOM, A_ASSOCIATE_RJ, pdu_type=0x03)
bind_layers(DICOM, P_DATA_TF, pdu_type=0x04)
bind_layers(DICOM, A_RELEASE_RQ, pdu_type=0x05)
bind_layers(DICOM, A_RELEASE_RP, pdu_type=0x06)
bind_layers(DICOM, A_ABORT, pdu_type=0x07)


def build_presentation_context_rq(context_id: int,
                                  abstract_syntax_uid: str,
                                  transfer_syntax_uids: List[str]) -> Packet:
    """Build a Presentation Context RQ item."""
    abs_uid = _uid_to_bytes_raw(abstract_syntax_uid)
    abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=abs_uid)

    sub_items = [abs_syn]
    for ts_uid in transfer_syntax_uids:
        ts = DICOMVariableItem() / DICOMTransferSyntax(uid=_uid_to_bytes_raw(ts_uid))
        sub_items.append(ts)

    return DICOMVariableItem() / DICOMPresentationContextRQ(
        context_id=context_id,
        sub_items=sub_items,
    )


def build_user_information(max_pdu_length: int = 16384,
                           implementation_class_uid: Optional[str] = None,
                           implementation_version: Optional[Union[str, bytes]] = None,
                           roles: Optional[Dict[str, Tuple[int, int]]] = None,
                           user_identity: Optional[Packet] = None,
                           ) -> Packet:
    """Build a User Information item.

    ``roles`` maps SOP Class UIDs to (scu_role, scp_role) and ``user_identity``
    is a DICOMUserIdentity sub-item.
    """
    sub_items = [
        DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=max_pdu_length)
    ]

    if implementation_class_uid:
        uid = _uid_to_bytes_raw(implementation_class_uid)
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationClassUID(uid=uid)
        )

    if roles:
        for sop_class_uid, (scu_role, scp_role) in roles.items():
            sub_items.append(
                DICOMVariableItem() / DICOMSCPSCURoleSelection(
                    sop_class_uid=_uid_to_bytes_raw(sop_class_uid),
                    scu_role=scu_role,
                    scp_role=scp_role,
                )
            )

    if implementation_version:
        if isinstance(implementation_version, bytes):
            ver_bytes = implementation_version
        else:
            ver_bytes = implementation_version.encode('ascii')
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationVersionName(version_name=ver_bytes)
        )

    if user_identity is not None:
        sub_items.append(DICOMVariableItem() / user_identity)

    return DICOMVariableItem() / DICOMUserInformation(sub_items=sub_items)


def dicom_build_p_data_tf(context_id: int, command: Union[Packet, bytes],
                          dataset: Optional[bytes] = None,
                          max_pdu_length: int = 16384) -> Iterator[Packet]:
    """Build the P-DATA-TF PDUs of a DIMSE message, one PDV per PDU.

    The command, then the data set, are cut in fragments of an even length
    that fit in ``max_pdu_length`` (0 means no maximum), see PS3.8 Annex E.
    """
    # The PDV item header takes 6 bytes of the maximum PDU length
    max_pdv_data = max((max_pdu_length - 6) & ~1, 2)
    for is_command, data in ((1, bytes(command)), (0, dataset)):
        if data is None:
            continue
        step = max_pdv_data if max_pdu_length else max(len(data), 1)
        for offset in range(0, max(len(data), 1), step):
            yield DICOM() / P_DATA_TF(pdv_items=[PresentationDataValueItem(
                context_id=context_id,
                data=data[offset:offset + step],
                is_command=is_command,
                is_last=1 if offset + step >= len(data) else 0,
            )])


class DICOM_Client:
    """DICOM client (SCU) for associations and DIMSE operations."""

    def __init__(self, dst_ip: str, dst_port: int, dst_ae: str,
                 src_ae: str = "SCAPY_SCU", read_timeout: int = 10) -> None:
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_ae = dst_ae
        self.src_ae = src_ae
        self.sock: Optional[socket.socket] = None
        self.stream: Optional[StreamSocket] = None
        self.assoc_established = False
        self.accepted_contexts: Dict[int, Tuple[str, str]] = {}
        self.read_timeout = read_timeout
        self._current_message_id_counter = int(time.time()) % 50000
        self._proposed_max_pdu = 16384
        self.max_pdu_length = 16384
        self._proposed_context_map: Dict[int, str] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        if self.assoc_established:
            try:
                self.release()
            except (socket.error, socket.timeout, OSError):
                pass
        self.close()
        return False

    def connect(self) -> bool:
        try:
            self.sock = socket.create_connection(
                (self.dst_ip, self.dst_port),
                timeout=self.read_timeout,
            )
            self.stream = StreamSocket(self.sock, basecls=DICOM)
            return True
        except (socket.error, socket.timeout, OSError) as e:
            log_dicom.error("Connection failed: %s", e)
            return False

    def send(self, pkt: Packet) -> None:
        self.stream.send(pkt)

    def recv(self) -> Optional[Packet]:
        try:
            return self.stream.recv()
        except socket.timeout:
            return None
        except (socket.error, OSError) as e:
            log_dicom.error("Error receiving PDU: %s", e)
            return None

    def sr1(self, *args, **kargs):
        # type: (*Any, **Any) -> Optional[Packet]
        """Send one packet and receive one answer."""
        timeout = kargs.pop("timeout", self.read_timeout)
        kargs.setdefault("verbose", False)
        try:
            return self.stream.sr1(*args, timeout=timeout, **kargs)
        except (socket.error, OSError) as e:
            log_dicom.error("Error in sr1: %s", e)
            return None

    def send_raw_bytes(self, raw_bytes: bytes) -> None:
        self.sock.sendall(raw_bytes)

    def associate(self, requested_contexts: Optional[Dict[str, List[str]]] = None,
                  roles: Optional[Dict[str, Tuple[int, int]]] = None) -> bool:
        """Request an association.

        ``roles`` maps SOP Class UIDs to the proposed (scu_role, scp_role),
        e.g. to be the Storage SCP of a C-GET.
        """
        if not self.stream and not self.connect():
            return False

        if requested_contexts is None:
            requested_contexts = {
                VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
            }

        self._proposed_context_map = {}
        self.accepted_contexts = {}

        variable_items: List[Packet] = [
            DICOMVariableItem() / DICOMApplicationContext()
        ]

        ctx_id = 1
        for abs_syntax, trn_syntaxes in requested_contexts.items():
            self._proposed_context_map[ctx_id] = abs_syntax
            pctx = build_presentation_context_rq(ctx_id, abs_syntax, trn_syntaxes)
            variable_items.append(pctx)
            ctx_id += 2

        user_info = build_user_information(
            max_pdu_length=self._proposed_max_pdu,
            implementation_class_uid=DICOM_IMPLEMENTATION_CLASS_UID,
            roles=roles,
        )
        variable_items.append(user_info)

        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.dst_ae,
            calling_ae_title=self.src_ae,
            variable_items=variable_items,
        )

        response = self.sr1(assoc_rq)

        if response:
            if response.haslayer(A_ASSOCIATE_AC):
                self.assoc_established = True
                self._parse_accepted_contexts(response)
                self._parse_max_pdu_length(response)
                return True
            elif response.haslayer(A_ASSOCIATE_RJ):
                log_dicom.error(
                    "Association rejected: result=%d, source=%d, reason=%d",
                    response[A_ASSOCIATE_RJ].result,
                    response[A_ASSOCIATE_RJ].source,
                    response[A_ASSOCIATE_RJ].reason_diag,
                )
                return False

        log_dicom.error("Association failed: no valid response received")
        return False

    def _parse_max_pdu_length(self, response: Packet) -> None:
        try:
            for item in response[A_ASSOCIATE_AC].variable_items:
                if item.item_type != 0x50:
                    continue
                if not item.haslayer(DICOMUserInformation):
                    continue
                user_info = item[DICOMUserInformation]
                for sub_item in user_info.sub_items:
                    if sub_item.item_type != 0x51:
                        continue
                    if not sub_item.haslayer(DICOMMaximumLength):
                        continue
                    max_len = sub_item[DICOMMaximumLength]
                    server_max = max_len.max_pdu_length
                    if server_max == 0:
                        server_max = self._proposed_max_pdu
                    self.max_pdu_length = min(
                        self._proposed_max_pdu, server_max
                    )
                    return
        except (KeyError, IndexError, AttributeError):
            pass
        self.max_pdu_length = self._proposed_max_pdu

    def _parse_accepted_contexts(self, response: Packet) -> None:
        for item in response[A_ASSOCIATE_AC].variable_items:
            if not item.haslayer(DICOMPresentationContextAC):
                continue
            pctx = item[DICOMPresentationContextAC]
            ctx_id = pctx.context_id
            result = pctx.result

            if result != 0:
                continue

            abs_syntax = self._proposed_context_map.get(ctx_id)
            if abs_syntax is None:
                continue

            for sub_item in pctx.sub_items:
                if not sub_item.haslayer(DICOMTransferSyntax):
                    continue
                ts_uid = sub_item[DICOMTransferSyntax].uid
                ts_uid = ts_uid.rstrip(b"\x00").decode("ascii")
                self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)
                break

    def _get_next_message_id(self) -> int:
        self._current_message_id_counter += 1
        return self._current_message_id_counter & 0xFFFF

    def _find_accepted_context_id(self, sop_class_uid: str,
                                  transfer_syntax_uid: Optional[str] = None
                                  ) -> Optional[int]:
        for ctx_id, (abs_syntax, ts_syntax) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid:
                if transfer_syntax_uid is None or transfer_syntax_uid == ts_syntax:
                    return ctx_id
        return None

    def c_echo(self) -> Optional[int]:
        if not self.assoc_established:
            log_dicom.error("Association not established")
            return None

        echo_ctx_id = self._find_accepted_context_id(VERIFICATION_SOP_CLASS_UID)
        if echo_ctx_id is None:
            log_dicom.error("No accepted context for Verification SOP Class")
            return None

        msg_id = self._get_next_message_id()
        dimse_rq = bytes(C_ECHO_RQ(message_id=msg_id))

        pdv_rq = PresentationDataValueItem(
            context_id=echo_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[pdv_rq])

        response = self.sr1(pdata_rq)

        if response and response.haslayer(P_DATA_TF):
            for pdv in response[P_DATA_TF].pdv_items:
                if pdv.is_command and _dimse_us_element(pdv.data, 0x0120) == msg_id:
                    return parse_dimse_status(pdv.data)
        return None

    def c_store(self, dataset_bytes: bytes, sop_class_uid: str,
                sop_instance_uid: str, transfer_syntax_uid: str
                ) -> Optional[int]:
        if not self.assoc_established:
            log_dicom.error("Association not established")
            return None

        store_ctx_id = self._find_accepted_context_id(
            sop_class_uid,
            transfer_syntax_uid,
        )
        if store_ctx_id is None:
            log_dicom.error(
                "No accepted context for SOP %s with TS %s",
                sop_class_uid,
                transfer_syntax_uid,
            )
            return None

        # Fragments have an even length (PS3.8 Annex E) and the PDV item
        # header takes 6 bytes of the negotiated maximum PDU length
        if (self.max_pdu_length - 6) & ~1 < 2:
            log_dicom.error("Maximum PDU length too small: %d", self.max_pdu_length)
            return None

        msg_id = self._get_next_message_id()

        dimse_rq = bytes(C_STORE_RQ(
            affected_sop_class_uid=sop_class_uid,
            affected_sop_instance_uid=sop_instance_uid,
            message_id=msg_id,
        ))
        for pdu in dicom_build_p_data_tf(store_ctx_id, dimse_rq, dataset_bytes,
                                         self.max_pdu_length):
            self.send(pdu)

        # Skip the PDUs that do not answer the C-STORE-RQ
        cmd_pdv = PresentationDataValueItem(
            context_id=store_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_cmd = DICOM() / P_DATA_TF(pdv_items=[cmd_pdv])
        response = self.stream.sniff(
            count=1,
            timeout=self.read_timeout,
            lfilter=lambda pkt: pkt.answers(pdata_cmd),
        )

        if response and response[0].haslayer(P_DATA_TF):
            for pdv in response[0][P_DATA_TF].pdv_items:
                if pdv.is_command and _dimse_us_element(pdv.data, 0x0120) == msg_id:
                    return parse_dimse_status(pdv.data)
        return None

    def release(self) -> bool:
        if not self.assoc_established:
            return True

        release_rq = DICOM() / A_RELEASE_RQ()
        response = self.sr1(release_rq)
        self.close()

        if response:
            return response.haslayer(A_RELEASE_RP)
        return False

    def close(self) -> None:
        if self.stream:
            try:
                self.stream.close()
            except (socket.error, OSError):
                pass
        self.sock = None
        self.stream = None
        self.assoc_established = False


class DICOM_Server:
    """DICOM server: association acceptor, SCP for Verification and Storage.

    ``supported_contexts`` maps the accepted abstract syntaxes to their
    transfer syntaxes, by order of preference. ``roles`` maps SOP Class UIDs
    to the (scu_role, scp_role) accepted for the requestor, (1, 0) otherwise.
    ``store_handler`` is called with the C-STORE-RQ, the transfer syntax UID
    and the data set, and returns the C-STORE status. ``ae_title`` is the
    Called AE Title to accept, any when None. ``max_pdu_length`` is the
    Maximum Length proposed to the requestor, whose own Maximum Length is
    ``peer_max_pdu_length``.

    Every PDU sent comes from make_reply(), negotiate(), accept_context() and
    dimse_reply(): override them to answer other requests, to act as SCU on
    the association through ``stream``, or to send malformed, unexpected or
    no PDUs at all.
    """

    def __init__(self, ae_title: Optional[str] = None,
                 supported_contexts: Optional[Dict[str, List[str]]] = None,
                 roles: Optional[Dict[str, Tuple[int, int]]] = None,
                 store_handler: Optional[Callable[[Packet, str, bytes], int]] = None,
                 read_timeout: int = 10, max_pdu_length: int = 16384) -> None:
        if supported_contexts is None:
            transfer_syntaxes = [
                IMPLICIT_VR_LITTLE_ENDIAN_UID,
                EXPLICIT_VR_LITTLE_ENDIAN_UID,
            ]
            supported_contexts = {
                VERIFICATION_SOP_CLASS_UID: transfer_syntaxes,
                CT_IMAGE_STORAGE_SOP_CLASS_UID: transfer_syntaxes,
                MR_IMAGE_STORAGE_SOP_CLASS_UID: transfer_syntaxes,
                SECONDARY_CAPTURE_SOP_CLASS_UID: transfer_syntaxes,
            }
        self.ae_title = ae_title
        self.supported_contexts = supported_contexts
        self.roles = roles or {}
        self.store_handler = store_handler
        self.read_timeout = read_timeout
        self.max_pdu_length = max_pdu_length
        self.peer_max_pdu_length = 0
        self.stream: Optional[StreamSocket] = None
        self.assoc_established = False
        self.awaiting_close = False
        self.accepted_contexts: Dict[int, Tuple[str, str]] = {}
        self.request: Optional[Packet] = None
        self.command = b""
        self.dataset = b""

    def accept_context(self, abstract_syntax: str,
                       transfer_syntaxes: List[str]) -> Tuple[int, str]:
        """Return the result and the transfer syntax of a proposed
        presentation context (PS3.8 9.3.3.2).
        """
        if abstract_syntax not in self.supported_contexts:
            return 3, DEFAULT_TRANSFER_SYNTAX_UID
        # One transfer syntax, by our order of preference
        for transfer_syntax in self.supported_contexts[abstract_syntax]:
            if transfer_syntax in transfer_syntaxes:
                return 0, transfer_syntax
        # The transfer syntax is not significant for a rejected context
        return 4, DEFAULT_TRANSFER_SYNTAX_UID

    def negotiate(self, pdu: Packet) -> Union[Packet, bytes]:
        """Answer an A-ASSOCIATE-RQ with an A-ASSOCIATE-AC or -RJ (PS3.8 9.3)."""
        assoc_rq = pdu[A_ASSOCIATE_RQ]
        # Only bit 0 of the protocol version is tested
        if not assoc_rq.protocol_version & 1:
            return DICOM() / A_ASSOCIATE_RJ(result=1, source=2, reason_diag=2)
        called_ae_title = plain_str(assoc_rq.called_ae_title).strip()
        if self.ae_title is not None and called_ae_title != self.ae_title:
            return DICOM() / A_ASSOCIATE_RJ(result=1, source=1, reason_diag=7)
        app_contexts = [
            plain_str(item[DICOMApplicationContext].uid).rstrip("\x00")
            for item in assoc_rq.variable_items
            if item.haslayer(DICOMApplicationContext)
        ]
        if app_contexts != [APP_CONTEXT_UID]:
            return DICOM() / A_ASSOCIATE_RJ(result=1, source=1, reason_diag=2)

        variable_items: List[Packet] = [
            DICOMVariableItem() / DICOMApplicationContext()
        ]
        roles = {}
        for item in assoc_rq.variable_items:
            if item.haslayer(DICOMUserInformation):
                # A proposed role is accepted (1) or turned down (0)
                for sub_item in item[DICOMUserInformation].sub_items:
                    if sub_item.haslayer(DICOMSCPSCURoleSelection):
                        role = sub_item[DICOMSCPSCURoleSelection]
                        uid = plain_str(role.sop_class_uid).rstrip("\x00")
                        scu_role, scp_role = self.roles.get(uid, (1, 0))
                        # The SOP Class UID is the one of the request
                        roles[role.sop_class_uid] = (role.scu_role & scu_role,
                                                     role.scp_role & scp_role)
            if not item.haslayer(DICOMPresentationContextRQ):
                continue
            pctx = item[DICOMPresentationContextRQ]
            abstract_syntax = ""
            proposed = []
            for sub_item in pctx.sub_items:
                if sub_item.haslayer(DICOMAbstractSyntax):
                    uid = sub_item[DICOMAbstractSyntax].uid
                    abstract_syntax = plain_str(uid).rstrip("\x00")
                elif sub_item.haslayer(DICOMTransferSyntax):
                    uid = sub_item[DICOMTransferSyntax].uid
                    proposed.append(plain_str(uid).rstrip("\x00"))
            result, transfer_syntax = self.accept_context(abstract_syntax, proposed)
            variable_items.append(
                DICOMVariableItem() / DICOMPresentationContextAC(
                    context_id=pctx.context_id,
                    result=result,
                    sub_items=[
                        DICOMVariableItem() / DICOMTransferSyntax(uid=transfer_syntax)
                    ],
                )
            )
        variable_items.append(build_user_information(
            max_pdu_length=self.max_pdu_length,
            implementation_class_uid=DICOM_IMPLEMENTATION_CLASS_UID,
            roles=roles,
        ))
        # The AE titles and the reserved field are the ones of the request
        return DICOM() / A_ASSOCIATE_AC(
            called_ae_title=assoc_rq.called_ae_title,
            calling_ae_title=assoc_rq.calling_ae_title,
            reserved2=assoc_rq.reserved2,
            variable_items=variable_items,
        )

    def dimse_reply(self, request: Packet, context_id: int, dataset: bytes
                    ) -> Union[None, Packet, bytes, Iterable[Union[Packet, bytes]]]:
        """Answer a DIMSE request with a response command, sent on its
        presentation context, or with PDUs, e.g. from dicom_build_p_data_tf()
        for a response with a data set, or with None.
        """
        # The Affected SOP Class and Instance UIDs are the ones of the request
        if isinstance(request, C_ECHO_RQ):
            return C_ECHO_RSP(
                affected_sop_class_uid=request.affected_sop_class_uid,
                message_id_responded=request.message_id,
            )
        if isinstance(request, C_STORE_RQ):
            status = 0x0000
            if self.store_handler is not None:
                transfer_syntax = self.accepted_contexts[context_id][1]
                status = self.store_handler(request, transfer_syntax, dataset)
            return C_STORE_RSP(
                affected_sop_class_uid=request.affected_sop_class_uid,
                affected_sop_instance_uid=request.affected_sop_instance_uid,
                message_id_responded=request.message_id,
                status=status,
            )
        # Unrecognized operation, for the requests that have a response
        message_id = getattr(request, "message_id", None)
        if message_id is None:
            return None
        for rsp_cls in DIMSEPacket.__subclasses__():
            if rsp_cls.command_field.default != request.command_field | 0x8000:
                continue
            # The other parameters are the ones of the request, or absent
            fields = {}
            for field in rsp_cls.fields_desc:
                if field.name in ("affected_sop_class_uid", "affected_sop_instance_uid",
                                  "action_type_id", "event_type_id"):
                    requested = field.name.replace("affected", "requested")
                    fields[field.name] = getattr(request, field.name,
                                                 getattr(request, requested, None))
            return rsp_cls(message_id_responded=message_id, status=0x0211, **fields)
        return None

    def make_reply(self, pdu: Optional[Packet]
                   ) -> Union[None, Packet, bytes, Iterable[Union[Packet, bytes]]]:
        """Answer a received PDU, or None after ``read_timeout`` seconds
        without one (PS3.8 9.2).
        """
        if pdu is None:
            if not self.assoc_established:
                return None
            self.assoc_established = False
            return DICOM() / A_ABORT()
        if pdu.haslayer(A_ABORT):
            self.assoc_established = False
            return None
        if self.awaiting_close:
            # Sta13: AA-7 for an A-ASSOCIATE-RQ or an unrecognized PDU, else AA-6
            if pdu.pdu_type not in PDU_TYPES:
                return DICOM() / A_ABORT(source=2, reason_diag=1)
            if pdu.haslayer(A_ASSOCIATE_RQ):
                return DICOM() / A_ABORT(source=2, reason_diag=2)
            return None
        if pdu.haslayer(A_ASSOCIATE_RQ) and not self.assoc_established:
            max_length = pdu.getlayer(DICOMMaximumLength)
            self.peer_max_pdu_length = max_length.max_pdu_length if max_length else 0
            self.request = None
            self.command = self.dataset = b""
            reply = self.negotiate(pdu)
            # The association follows the A-ASSOCIATE-AC sent, if any
            ac = DICOM(bytes(reply))
            self.assoc_established = ac.haslayer(A_ASSOCIATE_AC)
            self.accepted_contexts = {}
            if self.assoc_established:
                abstract_syntaxes = {}
                for item in pdu[A_ASSOCIATE_RQ].variable_items:
                    uid = item.getlayer(DICOMAbstractSyntax)
                    if item.haslayer(DICOMPresentationContextRQ) and uid:
                        context_id = item[DICOMPresentationContextRQ].context_id
                        abstract_syntaxes[context_id] = (
                            plain_str(uid.uid).rstrip("\x00")
                        )
                for item in ac[A_ASSOCIATE_AC].variable_items:
                    uid = item.getlayer(DICOMTransferSyntax)
                    if (item.haslayer(DICOMPresentationContextAC) and uid and
                            item[DICOMPresentationContextAC].result == 0):
                        context_id = item[DICOMPresentationContextAC].context_id
                        self.accepted_contexts[context_id] = (
                            abstract_syntaxes.get(context_id, ""),
                            plain_str(uid.uid).rstrip("\x00"),
                        )
            return reply
        if not self.assoc_established:
            # AA-1: unexpected PDU before the association
            return DICOM() / A_ABORT()
        if pdu.haslayer(A_RELEASE_RQ):
            self.assoc_established = False
            return DICOM() / A_RELEASE_RP()
        if not pdu.haslayer(P_DATA_TF):
            # AA-8: unexpected or unrecognized PDU
            self.assoc_established = False
            reason = 2 if pdu.pdu_type in PDU_TYPES else 1
            return DICOM() / A_ABORT(source=2, reason_diag=reason)
        replies: List[Union[Packet, bytes]] = []
        # The fragments of a command, then of its data set, are concatenated
        # until their last fragment (PS3.8 Annex E)
        for pdv in pdu[P_DATA_TF].pdv_items:
            if (not isinstance(pdv, PresentationDataValueItem) or
                    pdv.context_id not in self.accepted_contexts):
                log_dicom.info("Invalid PDV %s", pdv.summary())
                self.assoc_established = False
                return DICOM() / A_ABORT(source=2, reason_diag=6)
            if pdv.is_command:
                self.command += pdv.data
                if not pdv.is_last:
                    continue
                try:
                    self.request = DIMSEPacket(self.command)
                except Scapy_Exception as e:
                    log_dicom.info("Invalid DIMSE command: %s", e)
                    self.assoc_established = False
                    return DICOM() / A_ABORT(source=2, reason_diag=6)
                # Wait for the data set, unless there is none
                data_set_type = _dimse_us_element(self.command, 0x0800)
                self.command = self.dataset = b""
                if data_set_type not in (None, 0x0101):
                    continue
            else:
                self.dataset += pdv.data
                if not pdv.is_last or self.request is None:
                    continue
            response = self.dimse_reply(self.request, pdv.context_id, self.dataset)
            self.request = None
            self.dataset = b""
            if isinstance(response, DIMSEPacket):
                response = dicom_build_p_data_tf(
                    pdv.context_id, response,
                    max_pdu_length=self.peer_max_pdu_length,
                )
            if isinstance(response, (Packet, bytes)):
                replies.append(response)
            elif response is not None:
                replies.extend(response)
        return replies

    def handle(self, sock: socket.socket) -> None:
        """Answer the PDUs received on a connected socket until the peer
        closes it or aborts, or until ``read_timeout`` seconds without PDU.
        """
        sock.settimeout(self.read_timeout)
        if isinstance(sock, ssl.SSLSocket):
            self.stream = SSLStreamSocket(sock, basecls=DICOM)
        else:
            self.stream = StreamSocket(sock, basecls=DICOM)
        self.assoc_established = self.awaiting_close = False
        try:
            while True:
                try:
                    pdu: Optional[Packet] = self.stream.recv()
                except socket.timeout:
                    log_dicom.info("No PDU for %d seconds", self.read_timeout)
                    pdu = None
                replies = self.make_reply(pdu)
                if replies is None:
                    replies = []
                elif isinstance(replies, (Packet, bytes)):
                    replies = [replies]
                for reply in replies:
                    data = bytes(reply)
                    self.stream.send(data)
                    # Sta13 after an A-ASSOCIATE-RJ, an A-RELEASE-RP or an A-ABORT
                    if data[:1] in (b"\x03", b"\x06", b"\x07"):
                        self.awaiting_close = True
                if pdu is None or pdu.haslayer(A_ABORT):
                    break
        except EOFError:
            log_dicom.debug("Connection closed by the peer")
        except OSError as e:
            log_dicom.info("Connection error: %s", e)
        finally:
            self.stream.close()
            self.assoc_established = False

    @classmethod
    def spawn(cls, port: int = DICOM_PORT_ALT, iface: Optional[str] = None,
              local_ip: Optional[str] = None, bg: bool = False,
              **kwargs: Any) -> Optional[socket.socket]:
        """Listen on a port and run one server, built with ``kwargs``, per
        connection.

        With ``bg=True``, returns the listening socket: shut it down and close
        it to stop the server.
        """
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ssock.bind((local_ip or get_if_addr(iface or conf.iface), port))
        ssock.listen(5)

        def _run() -> None:
            try:
                while True:
                    sock, address = ssock.accept()
                    log_dicom.info("Connection from %s:%d", *address)
                    threading.Thread(
                        target=cls(**kwargs).handle, args=(sock,), daemon=True,
                    ).start()
            except OSError as e:
                log_dicom.debug("Server stopped: %s", e)
            finally:
                ssock.close()

        if bg:
            threading.Thread(target=_run, daemon=True).start()
            return ssock
        _run()
        return None


# Old name: DICOMSocket
DICOMSocket = DICOM_Client
