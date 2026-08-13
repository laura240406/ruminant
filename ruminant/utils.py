from .oids import OIDS
from .constants import (
    PGP_HASHES,
    PGP_PUBLIC_KEYS,
    PGP_CIPHERS,
    PGP_AEADS,
    PGP_SIGNATURE_TYPES,
    PGP_S2K_TYPES,
    CXX_OPERATORS,
)
from .buf import Buf, _decode
from .modules import chew
from .module import debug
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
import zlib
import bz2
import base64
import struct
import json
import tempfile
import re
import lzma
from typing import Any, cast


# inner part of xml_to_dict
def _xml_to_dict(elem):
    res = {}

    if elem.tag:
        res["tag"] = elem.tag

    if elem.attrib:
        res["attributes"] = elem.attrib

        # attribute special handling
        for k, v in elem.attrib.items():
            match k:
                # Google HDR+ specific attributes
                case (
                    "{http://ns.google.com/photos/1.0/camera/}hdrp_makernote"
                    | "{http://ns.google.com/photos/1.0/camera/}shot_log_data"
                    | "{http://ns.adobe.com/xap/1.0/g/img/}image"
                ):
                    res["attributes"][k] = chew(base64.b64decode(v))

    if elem.text and len(elem.text.strip()):
        res["text"] = elem.text

        # text special handling
        if elem.tag == "{http://ns.adobe.com/xap/1.0/g/img/}image":
            # adobe adds images as base64 for some reason
            res["text"] = chew(base64.b64decode(res["text"]))
        elif (
            # Android keybox XMLs embed the keys as PEM
            elem.tag in ("PrivateKey", "Certificate") and res.get("attributes", {}).get("format") == "pem"
        ):
            res["text"] = chew(res["text"].strip().encode("utf-8"))

    children = list(elem)
    # recurse
    if len(children):
        res["children"] = [_xml_to_dict(child) for child in children]

    return res


# top level for _xml_to_dict
def xml_to_dict(string, fail=False):
    while len(string):
        try:
            return _xml_to_dict(ET.fromstring(string))
        except ET.ParseError as e:
            if fail:
                raise e

            # remove trailing shit until it works
            string = string[:-1]

    # string was cut until it was empty
    return {}


# read only one XML document from a buf with other stuff trailing it
def read_xml(buf, chunk_size=4096):
    parser = ET.XMLPullParser(events=("start", "end"))
    content = b""
    root_seen = False
    root = None
    bak = buf.backup()

    try:
        while True:
            chunk = buf.read(
                min(
                    buf.unit if buf.unit is not None else 2**64,
                    buf.available(),
                    chunk_size,
                )
            )
            if not chunk or len(chunk) == 0:
                break

            for i in range(len(chunk)):
                b = chunk[i : i + 1]
                content += b
                parser.feed(b)

                for event, elem in parser.read_events():
                    if event == "start" and not root_seen:
                        root_seen = True
                        root = elem
                    elif event == "end" and elem is root:
                        break
    finally:
        # undo seeking if anything fails
        buf.restore(bak)

    try:
        # decode xml and do the seeking again
        xml = xml_to_dict(content, True)
        buf.skip(len(content))
        return xml
    except Exception:
        raise ValueError("No complete XML document found")


# read usual uleb128
def read_varint(buf):
    i = 0
    o = 0
    c = 0x80
    while c & 0x80:
        c = buf.read(1)[0]
        i |= (c & 0x7f) << o
        o += 7

    return i


# read Google Protobufs
def read_protobuf(buf, length, escape=False, decode={}):
    buf.pushunit()
    buf.setunit(length)

    entries = {}
    while buf.unit > 0:
        entry_id = read_varint(buf)

        entry_type = entry_id & 0b111
        entry_id >>= 3

        match entry_type:
            case 0:
                value = read_varint(buf)
            case 1:
                value = buf.ru64l()
            case 2:
                value_length = read_varint(buf)
                value = buf.read(value_length)
            case 5:
                value = buf.ru32l()
            case _:
                break

        # handle the renaming and special decode logic
        if entry_id in decode:
            if isinstance(decode[entry_id], dict):
                # bytes are actually another Protobuf
                value = read_protobuf(Buf(value), len(value), escape, decode[entry_id])
            else:
                match decode[entry_id]:
                    case "utf-8":
                        # bytes are actually UTF-8 string
                        value = value.decode(decode[entry_id])
                    case "float":
                        # bytes are actually floats
                        if isinstance(value, int):
                            value = value.to_bytes(4, "little")

                        value = struct.unpack("<" + "f" * (len(value) >> 2), value)
                        if len(value) == 1:
                            value = value[0]
                    case "double":
                        # bytes are actually doubles
                        if isinstance(value, int):
                            value = value.to_bytes(8, "little")

                        value = struct.unpack("<" + "d" * (len(value) >> 3), value)
                        if len(value) == 1:
                            value = value[0]
                    case "s32":
                        # bytes are actually a signed int
                        if value >> 31:
                            value = (value ^ 0xffffffff) + 1
                    case "s64":
                        # bytes are actually a signed long
                        if value >> 63:
                            value = (value ^ 0xffffffffffffffff) + 1
                    case "u8":
                        # bytes are actually u8s
                        value = [int.from_bytes(value[i : i + 1], "little") for i in range(0, len(value))]
                    case "u16":
                        # bytes are actually u16s
                        value = [int.from_bytes(value[i : i + 2], "little") for i in range(0, len(value))]
                    case "u32":
                        # bytes are actually u32s
                        value = [int.from_bytes(value[i : i + 4], "little") for i in range(0, len(value), 4)]
                    case "u64":
                        # bytes are actually u64s
                        value = [int.from_bytes(value[i : i + 8], "little") for i in range(0, len(value), 8)]
                    case "i8":
                        # bytes are actually i8s
                        value = [int.from_bytes(value[i : i + 1], "little", signed=True) for i in range(0, len(value))]
                    case "i16":
                        # bytes are actually i16s
                        value = [int.from_bytes(value[i : i + 2], "little", signed=True) for i in range(0, len(value))]
                    case "i32":
                        # bytes are actually i32s
                        value = [int.from_bytes(value[i : i + 4], "little", signed=True) for i in range(0, len(value), 4)]
                    case "i64":
                        # bytes are actually i64s
                        value = [int.from_bytes(value[i : i + 8], "little", signed=True) for i in range(0, len(value), 8)]
                    case _:
                        # unknown decode type, shouldn't happen
                        if escape:
                            value = value.hex()
        elif escape and isinstance(value, bytes):
            # escape bytes so it can be in a json object
            value = value.hex()

        if entry_id in decode.get("keys", {}):
            # rename entry id to something more readable
            entry_id = decode["keys"][entry_id]

        if entry_id in entries:
            # make an entry a list if it appears more than once
            if not isinstance(entries[entry_id], list):
                entries[entry_id] = [entries[entry_id]]

            entries[entry_id].append(value)
        else:
            entries[entry_id] = value

    buf.skipunit()
    buf.popunit()

    return entries


# safely convert a blob to a UUID or as hex if it's not 16 bytes
def to_uuid(blob):
    try:
        return str(uuid.UUID(bytes=blob))
    except ValueError:
        return blob.hex()


# safely convert ISO container date to isoformat and handle overflow
def mp4_time_to_iso(mp4_time):
    mp4_epoch = datetime(1904, 1, 1, tzinfo=timezone.utc)
    try:
        dt = mp4_epoch + timedelta(seconds=mp4_time)
        return dt.isoformat()
    except OverflowError:
        # don't panic, just return fallback stringified value
        return "??? - " + str(mp4_time)


# stream deflate compressed data from src to dst
def stream_deflate(src, dst, compressed_size, chunk_size=1 << 24, revert=False):
    remaining = compressed_size
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

    while remaining > 0:
        chunk = src.read(min(chunk_size, remaining))
        if len(chunk) == 0:
            break

        dst.write(decompressor.decompress(chunk))
        remaining -= len(chunk)

    flushed = decompressor.flush()
    if flushed:
        dst.write(flushed)

    if revert:
        src.seek(src.tell() - len(decompressor.unused_data))


# stream bzip2 compressed data from src to dst
def stream_bzip2(src, dst, compressed_size, chunk_size=1 << 24):
    remaining = compressed_size
    decompressor = bz2.BZ2Decompressor()

    while remaining > 0:
        chunk = src.read(min(chunk_size, remaining))
        dst.write(decompressor.decompress(chunk))
        remaining -= len(chunk)

    src.seek(-len(decompressor.unused_data), 1)


# stream compressed data from src to dst, decoded by the passed decompressor
def stream_generic(decompressor, src, dst, compressed_size, chunk_size=1 << 24):
    remaining = compressed_size

    while remaining > 0:
        chunk = src.read(min(chunk_size, remaining))
        dst.write(decompressor.decompress(chunk))
        remaining -= len(chunk)

    src.seek(-len(decompressor.unused_data), 1)


# stream zlib compressed data from src to dst
def stream_zlib(src, dst, compressed_size, chunk_size=1 << 24, revert=False):
    remaining = compressed_size
    decompressor = zlib.decompressobj()

    while remaining > 0:
        chunk = src.read(min(chunk_size, remaining))
        dst.write(decompressor.decompress(chunk))
        remaining -= len(chunk)

    flushed = decompressor.flush()
    if flushed:
        dst.write(flushed)

    if revert:
        src.seek(src.tell() - len(decompressor.unused_data))


# stream xz compressed data from src to dst
def stream_xz(src, dst, compressed_size, chunk_size=1 << 24):
    remaining = compressed_size
    decompressor = lzma.LZMADecompressor()

    while remaining > 0:
        chunk = src.read(min(chunk_size, remaining))
        dst.write(decompressor.decompress(chunk))
        remaining -= len(chunk)

    src.seek(-len(decompressor.unused_data), 1)


# read a DER encoded OID
def read_oid(buf, limit=-1):
    oid = []
    c = buf.ru8()
    oid.append(c // 40)
    oid.append(c % 40)

    i = 0
    while buf.unit > 0 and limit != 0:
        c = buf.ru8()
        i <<= 7
        i |= c & 0x7f

        if not c & 0x80:
            oid.append(i)
            i = 0

        limit -= 1

    return lookup_oid(oid)


# read DER encoded data
def read_der(buf):
    data = {}

    # read tag and extract flags
    tag = buf.ru8()
    constructed = bool((tag >> 5) & 0x01)

    # read long tag
    if tag & 0x0f == 0x0f:
        c = 0x80
        while c & 0x80:
            c = buf.ru8()
            tag <<= 7
            tag |= c & 0x7f

    # read length
    length = buf.ru8()
    if length & 0x80:
        # read long length
        length = int.from_bytes(buf.read(length & 0x7f), "big")

    buf.pushunit()
    buf.setunit(length)

    data["type"] = None
    data["length"] = length

    # process tag type
    match tag:
        case 0x01:
            data["type"] = "BOOLEAN"
            data["value"] = bool(buf.ru8())
        case 0x02 | 0x0a:
            data["type"] = ["INTEGER", "ENUMERATED"][tag >> 3]
            data["value"] = int.from_bytes(buf.readunit(), "big", signed=True)
        case 0x03:
            data["type"] = "BIT STRING"
            skip = buf.ru8()
            bit_length = length * 8 - skip

            if skip % 8 == 0:
                # guess whether a BIT STRING that has a 8 bit aligned length actually contains nested DER
                nested = True
                with buf:
                    try:
                        # read the tag
                        if buf.ru8() & 0x0f == 0x0f:
                            c = 0x80
                            while c & 0x80:
                                c = buf.ru8()

                        # read the length
                        length = buf.ru8()
                        if length & 0x80:
                            length = int.from_bytes(buf.read(length & 0x7f), "big")

                        # check the length
                        assert buf.unit == length
                    except Exception:
                        # no nested DER :(
                        nested = False

                if nested:
                    # read nested DER
                    with buf.subunit():
                        data["value"] = read_der(buf)
                else:
                    # nah, just hex
                    data["value"] = hex(int.from_bytes(buf.readunit()))[2:].zfill((bit_length + 7) // 8)
            else:
                # unaligned, save as bits
                data["value"] = hex(int.from_bytes(buf.readunit()) >> skip)[2:].zfill((bit_length + 7) // 8)
        case 0x04:
            data["type"] = "OCTET STRING"

            nested = True
            with buf:
                try:
                    # once again try to detect nested DER
                    if buf.ru8() & 0x0f == 0x0f:
                        c = 0x80
                        while c & 0x80:
                            c = buf.ru8()

                    length = buf.ru8()
                    if length & 0x80:
                        length = int.from_bytes(buf.read(length & 0x7f), "big")

                    assert buf.unit == length
                except Exception:
                    nested = False

            if nested:
                # you know the drill
                with buf.subunit():
                    data["value"] = read_der(buf)
            else:
                data["value"] = buf.readunit().hex()
        case 0x05:
            data["type"] = "NULL"
            data["value"] = None
        case 0x06:
            data["type"] = "OBJECT IDENTIFIER"
            data["value"] = read_oid(buf)
        case 0x0c:
            data["type"] = "UTF8String"
            data["value"] = buf.readunit().decode("utf-8")
        case 0x10 | 0x11 | 0x30 | 0x31:
            data["type"] = ["SEQUENCE", "SET"][tag & 0x01]
        case 0x13 | 0x14 | 0x16:
            # many funny names for ASCII for some reason
            data["type"] = {
                0x13: "PrintableString",
                0x14: "T61String",
                0x16: "IA5String",
            }[tag]

            data["value"] = buf.readunit().decode("ascii")
        case 0x17:
            data["type"] = "UTCTime"

            dt = datetime.strptime(buf.readunit().decode("ascii")[:-1], "%y%m%d%H%M%S")

            # years are sometimes broken for some fucking reason
            if dt.year < 1950:
                dt = dt.replace(year=dt.year + 100)

            data["value"] = dt.isoformat()
        case 0x18:
            data["type"] = "GeneralizedTime"

            time_string = buf.readunit().decode("ascii")[:-1]
            if "." in time_string:
                # time can be more precise
                main_time, fraction = time_string.split(".", 1)
                fraction = (fraction + "000000")[:6]
                data["value"] = (
                    datetime
                    .strptime(main_time, "%Y%m%d%H%M%S")
                    .replace(microsecond=int(fraction))
                    .isoformat(timespec="microseconds")
                    + "Z"
                )
            else:
                data["value"] = datetime.strptime(time_string, "%Y%m%d%H%M%S").isoformat()
        case 0x1e:
            data["type"] = "BMPString"
            data["value"] = buf.readunit().decode("utf-16be")
        case _:
            data["type"] = f"UNKNOWN ({hex(tag)})"

    if tag >= 0x80 and tag <= 0xbe:
        # X509 specific tags
        data["type"] = f"X509 [{tag & 0x0f}]"

        if not constructed:
            # read content of the tag
            content = buf.readunit()

            if tag & 0x0f in (0x02, 0x06):
                # some are text
                data["value"] = content.decode("latin-1")
            else:
                # some aren't
                data["value"] = content.hex()

    if constructed:
        # read nested DER entries if the tag is constructed
        data["value"] = []
        while buf.unit > 0:
            data["value"].append(read_der(buf))

    if (
        data["type"] == "SEQUENCE"
        and "value" in data
        and len(data["value"]) == 2
        and data["value"][0]["type"] == "OBJECT IDENTIFIER"
        and data["value"][1]["type"] == "OCTET STRING"
        and data["value"][0]["value"]["raw"] == "1.3.6.1.4.1.11129.2.1.30"
    ):
        # Android Google specific attestation field, which contains information about the device
        data["value"][1]["parsed"] = read_cbor(Buf(bytes.fromhex(data["value"][1]["value"])))

    buf.skipunit()
    buf.popunit()

    return data


# lookup OID in the database
def lookup_oid(oid):
    data = {}
    data["raw"] = ".".join([str(x) for x in oid])

    tree = []
    # start at root
    root = OIDS
    # walk OID database to collect names
    for i in oid:
        if i in root:
            tree.append(root[i]["name"])
            root = root[i]["children"]
        else:
            # no more leaves
            tree.append("?")
            root = {}

    data["tree"] = tree
    if tree[-1] != "?":
        # if the OID path ends in a known name, add it
        data["name"] = tree[-1]

    return data


# do zlib decompression for PDF files since Adobe is fucking insane
def zlib_decompress(content):
    try:
        # please just work
        return zlib.decompress(content)
    except Exception:
        try:
            # okay maybe now?
            return zlib.decompressobj().decompress(content)
        except Exception:
            decomp = zlib.decompressobj(zlib.MAX_WBITS | 32)

            # a fuck it
            data = b""
            for c in content:
                # WHAT THE FUCK ADOBE
                try:
                    data += decomp.decompress(bytes([c]))
                except Exception:
                    pass

            return data


# stuff that actually belongs to Buf but is here to prevent circular import stuff
def decode(*args, **kwargs):
    return _decode(*args, **kwargs)


# lookup name in a dict or present a fallback string
def unraw(i, width, choices, short=False):
    if short:
        # short form, just a string
        return choices.get(i, f"Unknown (0x{hex(i)[2:].zfill(width * 2)})")
    else:
        # long form that includes raw value
        return {"raw": i, "name": choices.get(i, "Unknown")}


# read big integer for PGP
def read_pgp_mpi(buf):
    bit_length = buf.ru16()
    return int.from_bytes(buf.read((bit_length + 7) // 8), "big") & ((1 << bit_length) - 1)


# read PGP hashed/unhashed subpacket
def read_pgp_subpacket(buf):
    packet = {}

    length = buf.ru8()
    if length >= 192 and length < 255:
        length = ((length - 192) << 8) + buf.ru8() + 192
    elif length == 255:
        length = buf.ru32()

    buf.pushunit()
    buf.setunit(length)

    packet["length"] = length

    typ = buf.ru8()
    packet["type"] = None

    data = {}
    packet["data"] = data

    match typ & 0x7f:
        case 0x02:
            packet["type"] = "Signature Creation Time"
            data["time"] = datetime.fromtimestamp(buf.ru32(), timezone.utc).isoformat()
        case 0x03:
            packet["type"] = "Signature Expiration Time"
            data["expiration-offset"] = buf.ru32()
        case 0x04:
            packet["type"] = "Expiration Time"
            data["expiration-offset"] = buf.ru32()
        case 0x05:
            packet["type"] = "Trust Signature"
            data["depth"] = buf.ru8()
            data["trust"] = buf.ru8()
        case 0x09:
            packet["type"] = "Key Expiration Time"
            data["expiration-offset"] = buf.ru32()
        case 0x0b:
            packet["type"] = "Preferred Symmetric Algorithms"

            data["algorithms"] = []
            while buf.unit > 0:
                data["algorithms"].append(unraw(buf.ru8(), 1, PGP_CIPHERS, True))
        case 0x10:
            packet["type"] = "Issuer"
            data["key-id"] = buf.rh(8)
        case 0x14:
            packet["type"] = "Notation Data"
            data["flags"] = {
                "raw": buf.ph(4),
                "human-readable": bool(buf.ru32l() & 0x80),
            }

            name_length = buf.ru16()
            value_length = buf.ru16()

            data["name"] = buf.rs(name_length)

            if data["flags"]["human-readable"]:
                data["value"] = buf.rs(value_length)
            else:
                data["value"] = buf.rh(value_length)
        case 0x15:
            packet["type"] = "Preferred Hash Algorithms"

            data["algorithms"] = []
            while buf.unit > 0:
                data["algorithms"].append(unraw(buf.ru8(), 1, PGP_HASHES, True))
        case 0x16:
            packet["type"] = "Preferred Compression Algorithms"

            data["algorithms"] = []
            while buf.unit > 0:
                data["algorithms"].append(unraw(buf.ru8(), 1, {0: "Uncompressed", 1: "ZIP", 2: "ZLIB", 3: "BZip2"}, True))
        case 0x17:
            packet["type"] = "Key Server Preferences"
            flags = buf.read(buf.unit)
            data["flags"] = {"raw": flags.hex(), "no-modify": bool(flags[0] & 0x80)}
        case 0x18:
            packet["type"] = "Preferred Key Server"
            data["uri"] = buf.readunit().decode("utf-8")
        case 0x19:
            packet["type"] = "Primary User ID"
            data["is-primary-user-id"] = bool(buf.ru8())
        case 0x1a:
            packet["type"] = "Policy URI"
            data["uri"] = buf.readunit().decode("utf-8")
        case 0x1b:
            packet["type"] = "Key Flags"
            data["flags"] = unpack_flags(
                buf.ru8(),
                (
                    (0, "can-certify-user-id"),
                    (1, "can-sign-data"),
                    (2, "can-encrypt-communication"),
                    (3, "can-encrypt-storage"),
                    (4, "key-is-split"),
                    (5, "can-authenticate"),
                    (6, "key-is-shared"),
                ),
            )
        case 0x1c:
            packet["type"] = "Signer's User ID"
            data["fingerprint"] = buf.rs(buf.unit)
        case 0x1d:
            packet["type"] = "Reason for Revocation"
            packet["reason"] = unraw(
                buf.ru8(),
                1,
                {
                    0: "No reason specified",
                    1: "Key is superseded",
                    2: "Key material has been compromised",
                    3: "Key is retired and no longer used",
                    32: "User ID information is no longer valid",
                },
                True,
            )
            packet["reason-message"] = buf.readunit().decode("utf-8")
        case 0x1e:
            packet["type"] = "Features"

            data["flags"] = unpack_flags(int.from_bytes(buf.read(buf.unit), "little"), ((0, "seipd-v1"), (3, "seipd-v2")))
        case 0x20:
            packet["type"] = "Embedded Signature"
            data["embedded-packet"] = _read_pgp(buf, fake=(2, buf.unit))
        case 0x21:
            packet["type"] = "Issuer Fingerprint"

            data["version"] = buf.ru8()
            match data["version"]:
                case 4 | 6:
                    data["fingerprint"] = buf.rh(buf.unit)
                case _:
                    packet["unknown"] = True
        case 0x22:
            packet["type"] = "Preferred AEAD Algorithms"

            data["algorithms"] = []
            while buf.unit > 0:
                data["algorithms"].append(unraw(buf.ru8(), 1, PGP_AEADS, True))
        case _:
            if typ & 0x7f >= 100:
                packet["type"] = f"Private (0x{hex(typ)[2:].zfill(2)})"
                packet["content"] = buf.readunit().hex()
            else:
                packet["type"] = f"Unknown (0x{hex(typ)[2:].zfill(2)})"
                packet["unknown"] = True

    buf.skipunit()
    buf.popunit()

    return packet


def _read_pgp(buf, fake=None):
    packet = {}

    if fake is None:
        tag = buf.ru8()
        if tag & 0b01000000:
            tag = tag & 0b00111111

            length = buf.ru8()
            if length >= 192 and length < 255:
                length = ((length - 192) << 8) + buf.ru8() + 192
            elif length == 255:
                length = buf.ru32()
        else:
            packet["old"] = True
            length_type = tag & 0b00000011
            tag = (tag & 0b00111100) >> 2

            match length_type:
                case 0:
                    length = buf.ru8()
                case 1:
                    length = buf.ru16()
                case 2:
                    length = buf.ru32()
                case 3:
                    length = buf.unit
    else:
        tag, length = fake

    buf.pushunit()
    buf.setunit(length)

    packet["length"] = length

    data = {}
    packet["tag"] = None
    packet["data"] = data
    match tag:
        case 0x01:
            packet["tag"] = "Public Key Encrypted Session Key"
            data["version"] = buf.ru8()

            algorithm = None
            match data["version"]:
                case 3:
                    data["key-id"] = buf.rh(8)

                    algorithm = buf.ru8()
                    data["public-key-algorithm"] = unraw(algorithm, 1, PGP_PUBLIC_KEYS, True)
                case 6:
                    buf.pasunit(buf.ru8())

                    data["key-version"] = buf.ru8()
                    data["key-id"] = buf.rh({4: 20, 6: 32}.get(data["key-version"], buf.unit))

                    buf.sapunit()

                    algorithm = buf.ru8()
                    data["public-key-algorithm"] = unraw(algorithm, 1, PGP_PUBLIC_KEYS, True)
                case _:
                    packet["unknown"] = True

            match algorithm:
                case 0x01 | 0x02:
                    data["session-key"] = {"c": read_pgp_mpi(buf)}
                case 0x19 | 0x1a:
                    data["session-key"] = {}
                    data["session-key"]["public-key"] = buf.rh(32 if algorithm == 0x19 else 56)

                    buf.pasunit(buf.ru8())

                    if data["version"] == 3:
                        data["session-key"]["algorithm"] = unraw(buf.ru8(), 1, PGP_CIPHERS, True)

                    data["session-key"]["key"] = buf.rh(buf.unit)

                    buf.sapunit()
                case _:
                    data["session-key"] = {"raw": buf.rh(buf.unit), "unknown": True}
        case 0x02:
            packet["tag"] = "Signature"
            data["version"] = buf.ru8()

            algorithm = None
            match data["version"]:
                case 3:
                    buf.skip(1)
                    data["type"] = unraw(buf.ru8(), 1, PGP_SIGNATURE_TYPES, True)
                    data["created-at"] = datetime.fromtimestamp(buf.ru32(), timezone.utc).isoformat()

                    data["key-id"] = buf.rh(8)

                    algorithm = buf.ru8()
                    data["public-key-algorithm"] = unraw(algorithm, 1, PGP_PUBLIC_KEYS, True)

                    data["hash-algorithm"] = unraw(buf.ru8(), 1, PGP_HASHES, True)
                    data["hash-prefix"] = buf.rh(2)
                case 4 | 6:
                    data["type"] = unraw(buf.ru8(), 1, PGP_SIGNATURE_TYPES, True)

                    algorithm = buf.ru8()
                    data["public-key-algorithm"] = unraw(algorithm, 1, PGP_PUBLIC_KEYS, True)

                    data["hash-algorithm"] = unraw(buf.ru8(), 1, PGP_HASHES, True)

                    buf.pushunit()
                    buf.setunit(buf.ru16())

                    data["hashed-subpackets"] = []
                    while buf.unit > 0:
                        data["hashed-subpackets"].append(read_pgp_subpacket(buf))

                    buf.skipunit()
                    buf.popunit()

                    buf.pushunit()
                    buf.setunit(buf.ru16())

                    data["unhashed-subpackets"] = []
                    while buf.unit > 0:
                        data["unhashed-subpackets"].append(read_pgp_subpacket(buf))

                    buf.skipunit()
                    buf.popunit()

                    data["hash-prefix"] = buf.rh(2)

                    if data["version"] == 6:
                        data["salt"] = buf.rh(buf.ru8())
                case _:
                    packet["unknown"] = True
            match algorithm:
                case 0x01 | 0x02 | 0x03:
                    data["signature"] = {"c": read_pgp_mpi(buf)}
                case 0x11 | 0x13 | 0x16:
                    data["signature"] = {"r": read_pgp_mpi(buf), "s": read_pgp_mpi(buf)}
                case 0x1b:
                    data["signature"] = {"rs": buf.rh(64)}
                case 0x1c:
                    data["signature"] = {"rs": buf.rh(117)}
                case _:
                    data["signature"] = {"unknown": True}
        case 0x03:
            packet["tag"] = "Symmetric Key Encrypted Session Key"
            data["version"] = buf.ru8()

            match data["version"]:
                case 4:
                    data["algorithm"] = unraw(buf.ru8(), 1, PGP_S2K_TYPES, True)

                    match data["algorithm"]["raw"]:
                        case 0:
                            data["hash-algorithm"] = unraw(buf.ru8(), 1, PGP_HASHES, True)
                        case 1:
                            data["hash-algorithm"] = unraw(buf.ru8(), 1, PGP_HASHES, True)
                            data["salt"] = buf.rh(8)
                        case 3:
                            data["hash-algorithm"] = unraw(buf.ru8(), 1, PGP_HASHES, True)
                            data["salt"] = buf.rh(8)
                            c = buf.ru8()
                            data["count"] = (16 + (c & 0x0f)) << ((c >> 4) + 6)
                        case 4:
                            data["salt"] = buf.rh(16)
                            data["t"] = buf.ru8()
                            data["p"] = buf.ru8()
                            c = buf.ru8()
                            data["memory"] = ((16 + (c & 0x0f)) << ((c >> 4) + 6)) * 1024
                        case _:
                            packet["unknown"] = True
                case _:
                    packet["unknown"] = True
        case 0x04:
            packet["tag"] = "One-pass Signature"
            data["version"] = buf.ru8()

            match data["version"]:
                case 3:
                    data["type"] = unraw(buf.ru8(), 1, PGP_SIGNATURE_TYPES, True)
                    data["hash-algorithm"] = unraw(buf.ru8(), 1, PGP_HASHES, True)
                    data["public-key-algorithm"] = unraw(buf.ru8(), 1, PGP_PUBLIC_KEYS, True)
                    data["key-id"] = buf.rh(8)
                    data["nested"] = buf.ru8() == 0
                case _:
                    packet["unknown"] = True
        case 0x05 | 0x06 | 0x07 | 0x0e:
            packet["tag"] = {
                0x05: "Secret Key",
                0x06: "Public Key",
                0x07: "Secret Subkey",
                0x0e: "Public Subkey",
            }[tag]
            data["version"] = buf.ru8()

            secret = {0x05: True, 0x06: False, 0x07: True, 0x0e: False}[tag]

            algorithm = None
            match data["version"]:
                case 3:
                    data["created-at"] = datetime.fromtimestamp(buf.ru32(), timezone.utc).isoformat()
                    data["expiry-days"] = buf.ru16()
                    algorithm = buf.ru8()

                    data["algorithm"] = unraw(algorithm, 1, PGP_PUBLIC_KEYS, True)
                case 4:
                    data["created-at"] = datetime.fromtimestamp(buf.ru32(), timezone.utc).isoformat()
                    algorithm = buf.ru8()

                    data["algorithm"] = unraw(algorithm, 1, PGP_PUBLIC_KEYS, True)
                case 6:
                    data["created-at"] = datetime.fromtimestamp(buf.ru32(), timezone.utc).isoformat()
                    algorithm = buf.ru8()

                    data["algorithm"] = unraw(algorithm, 1, PGP_PUBLIC_KEYS, True)
                    data["key-length"] = buf.ru32()
                case _:
                    packet["unknown"] = True

            match algorithm:
                case 0x01 | 0x02 | 0x03:
                    data["key"] = {"n": read_pgp_mpi(buf), "e": read_pgp_mpi(buf)}
                case 0x10:
                    data["key"] = {
                        "p": read_pgp_mpi(buf),
                        "g": read_pgp_mpi(buf),
                        "y": read_pgp_mpi(buf),
                    }
                case 0x11:
                    data["key"] = {
                        "p": read_pgp_mpi(buf),
                        "q": read_pgp_mpi(buf),
                        "g": read_pgp_mpi(buf),
                        "y": read_pgp_mpi(buf),
                    }
                case 0x12:
                    data["key"] = {
                        "oid": read_oid(buf, buf.ru8() - 1),
                        "point": read_pgp_mpi(buf),
                    }

                    length = buf.ru8()
                    buf.skip(1)
                    data["key"]["kdf-hash-function"] = unraw(buf.ru8(), 1, PGP_HASHES, True)
                    data["key"]["kdf-cipher"] = unraw(buf.ru8(), 1, PGP_CIPHERS, True)

                    if length > 3:
                        data["key"]["sender"] = buf.rs(32)
                        data["key"]["fingerprint"] = buf.rh(length - 35)
                case 0x13 | 0x16:
                    data["key"] = {
                        "oid": read_oid(buf, buf.ru8() - 1),
                        "point": read_pgp_mpi(buf),
                    }
                case 0x19:
                    data["key"] = {"point": buf.rh(32)}
                case 0x1a:
                    data["key"] = {"point": buf.rh(56)}
                case 0x1b:
                    data["key"] = {"point": buf.rh(32)}
                case 0x1c:
                    data["key"] = {"point": buf.rh(57)}
                case _:
                    packet["unknown"] = True

            if secret:
                s2k_usage = buf.ru8()
                data["s2k-usage"] = unraw(s2k_usage, 1, {0: "Unencrypted", 253: "AEAD", 254: "CFB", 255: "MalleableCFB"}, True)
        case 0x08:
            packet["tag"] = "Compressed Data"

            method = buf.ru8()
            data["method"] = unraw(method, 1, {0: "Uncompressed", 1: "ZIP", 2: "ZLIB", 3: "BZip2"}, True)

            content = buf.readunit()
            match method:
                case 0:
                    pass
                case 1:
                    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                    content = decompressor.decompress(content) + decompressor.flush()
                case 2:
                    content = zlib.decompress(content)
                case 3:
                    content = bz2.decompress(content)
                case _:
                    content = None

            if content is not None:
                cbuf = Buf(content)

                data["content"] = []
                while cbuf.available() > 0:
                    data["content"].append(read_pgp(cbuf))
            else:
                data["unknown"] = True
        case 0x09:
            packet["tag"] = "Symetrically Encrypted Data"
        case 0x0a:
            packet["tag"] = "Marker"
            data["valid"] = buf.unit == 3 and buf.peek(3) == b"PGP"

            if not data["valid"]:
                with buf.subunit():
                    data["blob"] = chew(buf, blob_mode=True)
        case 0x0b:
            packet["tag"] = "Literal Data"
            data["format"] = buf.read(1).decode("latin-1")
            data["date"] = datetime.fromtimestamp(buf.ru32(), timezone.utc).isoformat()

            match data["format"]:
                case "t" | "b":
                    data["filename"] = buf.rs(buf.ru8())
                    data["content"] = buf.rs(buf.unit)
                case "\x00":
                    content = buf.read(min(buf.unit, buf.available()))

                    if content.startswith(b'{"body"'):
                        i = 0
                        while content[i] != 0x0a:
                            i += 1

                        data["content"] = {}
                        data["content"]["json"] = json.loads(content[:i].replace(b"\x1f", b"").decode("utf-8"))
                        data["content"]["signature"] = read_pgp(Buf(content[i + 1 :]))
                    else:
                        data["content"] = content.hex()
                case _:
                    packet["unknown"] = True
        case 0x0d:
            packet["tag"] = "User ID"
            data["user-id"] = buf.rs(buf.unit)
        case 0x12:
            packet["tag"] = "Symetrically Encrypted and Integrity Protected Data"
            data["version"] = buf.ru8()

            match data["version"]:
                case 0x01:
                    data["encrypted-length"] = buf.unit
                    buf.skipunit()
                case 0x02:
                    data["algorithm"] = unraw(buf.ru8(), 1, PGP_CIPHERS, True)
                    data["aead"] = unraw(buf.ru8(), 1, PGP_AEADS, True)
                    data["chunk-size"] = 1 << (buf.ru8() + 6)
                    data["salt"] = buf.rh(32)

                    data["encrypted-length"] = buf.unit
                    buf.skipunit()
                case _:
                    packet["unknown"] = True
        case _:
            packet["tag"] = f"Unknown (0x{hex(tag)[2:].zfill(2)})"
            packet["unknown"] = True

    buf.skipunit()
    buf.popunit()

    return packet


def read_pgp(buf):
    buf.pushunit()
    buf.setunit(buf.available() if buf.unit is None else buf.unit)

    data = _read_pgp(buf)

    buf.popunit()

    return data


def read_cbor(buf):
    cmd = buf.ru8()
    major, minor = cmd >> 5, cmd & 0x1f

    if minor == 24:
        minor = buf.ru8()
    elif minor == 25:
        if major == 7:
            minor = buf.rf16()
        else:
            minor = buf.ru16()
    elif minor == 26:
        if major == 7:
            minor = buf.rf32()
        else:
            minor = buf.ru32()
    elif minor == 27:
        if major == 7:
            minor = buf.rf64()
        else:
            minor = buf.ru64()
    elif minor == 31:
        if major == 7:
            raise ValueError("CBOR indefinite length end outside of indefinite length context")
        else:
            minor = None
    elif minor > 27:
        raise ValueError(f"Malformed CBOR: {(major, minor)}")

    match major:
        case 0:
            value = minor
        case 1:
            value = -1 - minor
        case 2:
            if minor is None:
                value = b""

                while True:
                    if buf.pu8() == 0xff:
                        buf.skip(1)
                        break

                    value += read_cbor(buf)

                value = value.hex()
            else:
                value = buf.rh(minor)

            try:
                buf2 = Buf(bytes.fromhex(value))
                data = read_cbor(buf2)
                assert buf2.available() == 0
                value = data
            except Exception:
                data = chew(bytes.fromhex(value))
                if data["type"] not in ("unknown", "empty", "error"):
                    value = data
        case 3:
            if minor is None:
                value = b""

                while True:
                    if buf.pu8() == 0xff:
                        buf.skip(1)
                        break

                    value += read_cbor(buf)

                value = decode(value)
            else:
                value = buf.rs(minor)
        case 4:
            value = []

            if minor is None:
                while True:
                    if buf.pu8() == 0xff:
                        buf.skip(1)
                        break

                    value.append(read_cbor(buf))
            else:
                for i in range(0, minor):
                    value.append(read_cbor(buf))
        case 5:
            value = {}

            if minor is None:
                while True:
                    if buf.pu8() == 0xff:
                        buf.skip(1)
                        break

                    k, v = read_cbor(buf), read_cbor(buf)
                    value[k] = v
            else:
                for i in range(0, minor):
                    k, v = read_cbor(buf), read_cbor(buf)
                    value[k] = v
        case 6:
            value = (minor, read_cbor(buf))
        case 7:
            value = minor
        case _:
            raise ValueError(f"Unknown CBOR major {major}")

    return value


def _demangle(name, top=None):
    modifiers = []
    while name[0] in "PK":
        modifiers.append(name[0])
        name = name[1:]

    for k, v in CXX_OPERATORS.items():
        if name.startswith(k):
            return v, name[len(k) :]

    if name[0] in "vbcahstijlmxyfdew" or name[:2] == "Dn":
        typ = ""
        if "K" in modifiers:
            typ += "const "

        typ += {
            "v": "void",
            "b": "bool",
            "c": "char",
            "a": "signed char",
            "h": "unsigned char",
            "s": "short",
            "t": "unsigned short",
            "i": "int",
            "j": "unsigned int",
            "l": "long",
            "m": "unsigned long",
            "x": "long long",
            "y": "unsigned long long",
            "f": "float",
            "d": "double",
            "e": "long double",
            "w": "wchar_t",
            "D": "std::nullptr_t",
        }[name[0]]

        if "P":
            typ += " *"

        if name[0] == "D":
            name = name[1:]
        name = name[1:]

        return typ, name
    elif name[0] == "N":
        name = name[1:]
        parts = []
        while name[0] != "E":
            part, name = _demangle(name, parts)
            parts.append(part)
        name = name[1:]
        return "::".join(parts), name
    elif name[:2] in ("C0", "C1", "C2", "D0", "D1", "D2"):
        return ("~" if name[0] == "D" else "") + top[-1] + "()", name[2:]
    elif name[0] == "L":
        name = name[1:]
        typ = name[0]
        name = name[1:]

        if typ == "b":
            return ["false", "true"][int(name[0])], name[1:]
        elif typ in "0123456789":
            length = typ
            while name[0] in "0123456789":
                length += name[0]
                name = name[1:]

            length = int(length)
            return name[:length], name[length:]

        raise ValueError(f"Unknown literal type '{typ}'")
    elif name[:2] == "S_":
        name = name[2:]
        return "::".join(top), name
    elif name[0] == "I":
        name = name[1:]
        parts = []
        while name[0] != "E":
            part, name = _demangle(name)
            parts.append(part)
        name = name[1:]
        return "<" + ", ".join(parts) + ">", name
    elif name[0] in "0123456789":
        length = ""
        while name[0] in "0123456789":
            length += name[0]
            name = name[1:]

        if length == "":
            print(name)

        length = int(length)
        res = name[:length]
        name = name[length:]

        if res.startswith("_$"):
            res = res[1:]

        return res, name

    else:
        raise ValueError()


def demangle(name):
    old_name = name

    assert name[:2] == "_Z"
    res = None

    name = name[2:]

    try:
        res, name = _demangle(name)
    except Exception:
        return old_name

    res = res.replace("$LT$", "<")
    res = res.replace("$GT$", ">")
    res = res.replace("$LP$", "(")
    res = res.replace("$RP$", ")")
    res = res.replace("$BP$", "*")
    res = res.replace("$RF$", "&")
    res = res.replace("$C$", ",")
    res = res.replace("..", "::")

    for i in range(0, 128):
        res = res.replace(f"$u{hex(i)[2:].zfill(2)}$", chr(i))

    return res


def read_bencode(buf, blob_mode=False):
    c = buf.read(1)

    if c == b"i":
        n = b""
        while buf.peek(1) != b"e":
            n += buf.read(1)

        buf.read(1)

        return int(n)
    elif c == b"l":
        elems = []
        while buf.peek(1) != b"e":
            elems.append(read_bencode(buf))

        buf.read(1)
        return elems
    elif c == b"d":
        elems = {}
        while buf.peek(1) != b"e":
            key = read_bencode(buf)

            match key:
                case "pieces":
                    elems[key] = read_bencode(buf, True)
                case "creation date":
                    elems[key] = datetime.fromtimestamp(read_bencode(buf), timezone.utc).isoformat()
                case _:
                    elems[key] = read_bencode(buf)

        buf.read(1)
        return elems
    elif c in b"0123456789":
        n = c
        while buf.peek(1) != b":":
            n += buf.read(1)

        buf.read(1)

        value = buf.read(int(n))
        if blob_mode:
            return chew(value, blob_mode=True)
        else:
            return value.decode("utf-8")


def read_nbt(buf, has_name=True, tag=None, depth=1):
    if has_name:
        tag = buf.ru8()
        name = buf.rs(buf.ru16())

    match tag:
        case 0x01:
            value = buf.ri8()
        case 0x02:
            value = buf.ri16()
        case 0x03:
            value = buf.ri32()
        case 0x04:
            value = buf.ri64()
        case 0x05:
            value = buf.rf32()
        case 0x06:
            value = buf.rf64()
        case 0x07:
            value = [buf.ri8() for i in range(0, buf.ru32())]
        case 0x08:
            value = buf.rs(buf.ru16())
        case 0x09:
            tag2 = buf.ru8()

            value = []
            for i in range(0, buf.ru32()):
                value.append(read_nbt(buf, False, tag2, depth=depth + 1))

        case 0x0a:
            value = {}
            while buf.pu8() != 0:
                key, value2 = read_nbt(buf, depth=depth + 1)
                value[key] = value2

            buf.skip(1)
        case 0x0b:
            value = [buf.ri32() for i in range(0, buf.ru32())]
        case 0x0c:
            value = [buf.ri64() for i in range(0, buf.ru32())]
        case _:
            if has_name:
                raise ValueError(f"Unknown tag 0x{hex(tag)[2:].zfill(2)} with name '{name}'")
            else:
                raise ValueError(f"Unknown tag 0x{hex(tag)[2:].zfill(2)}")

    if has_name:
        return name, value
    else:
        return value


def filetime_to_date(ts):
    return (datetime(1601, 1, 1) + timedelta(microseconds=ts / 10)).isoformat() + "Z"


def unix_to_date(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


NULL = object()


def _read_marshal(buf, version, refs=None):
    if refs is None:
        refs = []

    type_byte = buf.ru8()
    flag_ref = bool(type_byte & 0x80)
    typ = chr(type_byte & 0x7f)

    ref_idx = None
    if flag_ref:
        ref_idx = len(refs)
        refs.append(None)

    def set_ref(val):
        if ref_idx is not None:
            refs[ref_idx] = val
        return val

    match typ:
        case "\x00" | "0":
            return NULL
        case "N":
            return set_ref(None)
        case "F":
            return set_ref(False)
        case "T":
            return set_ref(True)
        case "S":
            return set_ref(StopIteration)
        case ".":
            return set_ref(...)
        case "i":
            return set_ref(buf.ri32l())
        case "I":
            return set_ref(buf.ri64l())
        case "f":
            length = buf.ru8()
            s = buf.rs(length)
            return set_ref(float(s))
        case "g":
            return set_ref(buf.rf64l())
        case "x":
            len_r = buf.ru8()
            r_s = buf.rs(len_r)
            len_i = buf.ru8()
            i_s = buf.rs(len_i)
            return set_ref(complex(float(r_s), float(i_s)))
        case "y":
            r = buf.rf64l()
            i = buf.rf64l()
            return set_ref(complex(r, i))
        case "l":
            n = buf.ri32l()
            val = 0
            for i in range(abs(n)):
                digit = buf.ru16l()
                val += digit << (15 * i)
            if n < 0:
                val = -val
            return set_ref(val)
        case "s" | "t":
            return set_ref(buf.read(buf.ru32l()))
        case "u" | "a" | "A":
            return set_ref(buf.rs(buf.ru32l()))
        case "z" | "Z":
            return set_ref(buf.rs(buf.ru8()))
        case "(":
            items = []
            set_ref(items)
            for _ in range(buf.ru32l()):
                items.append(_read_marshal(buf, version, refs))
            res = tuple(items)
            set_ref(res)
            return res
        case ")":
            items = []
            set_ref(items)
            for _ in range(buf.ru8()):
                items.append(_read_marshal(buf, version, refs))
            res = tuple(items)
            set_ref(res)
            return res
        case "[":
            items = []
            set_ref(items)
            for _ in range(buf.ru32l()):
                items.append(_read_marshal(buf, version, refs))
            return items
        case "{":
            obj = {}
            set_ref(obj)
            while True:
                key = _read_marshal(buf, version, refs)
                if key is NULL:
                    break
                val = _read_marshal(buf, version, refs)
                obj[key] = val
            return obj
        case "<":
            items = set()
            set_ref(items)
            for _ in range(buf.ru32l()):
                items.add(_read_marshal(buf, version, refs))
            return items
        case ">":
            items = []
            set_ref(items)
            for _ in range(buf.ru32l()):
                items.append(_read_marshal(buf, version, refs))
            res = frozenset(items)
            set_ref(res)
            return res
        case "r":
            idx = buf.ru32l()
            return refs[idx]
        case "c":
            obj = {}
            set_ref(obj)

            if version < 3130:  # Python 2.x
                obj["co_argcount"] = buf.ru32l()
                obj["co_nlocals"] = buf.ru32l()
                obj["co_stacksize"] = buf.ru32l()
                obj["co_flags"] = buf.ru32l()
                obj["co_code"] = _read_marshal(buf, version, refs)
                obj["co_consts"] = _read_marshal(buf, version, refs)
                obj["co_names"] = _read_marshal(buf, version, refs)
                obj["co_varnames"] = _read_marshal(buf, version, refs)
                obj["co_freevars"] = _read_marshal(buf, version, refs)
                obj["co_cellvars"] = _read_marshal(buf, version, refs)
                obj["co_filename"] = _read_marshal(buf, version, refs)
                obj["co_name"] = _read_marshal(buf, version, refs)
                obj["co_firstlineno"] = buf.ru32l()
                obj["co_lnotab"] = _read_marshal(buf, version, refs)
            elif version < 3400:  # Python 3.0 - 3.7
                obj["co_argcount"] = buf.ru32l()
                obj["co_kwonlyargcount"] = buf.ru32l()
                obj["co_nlocals"] = buf.ru32l()
                obj["co_stacksize"] = buf.ru32l()
                obj["co_flags"] = buf.ru32l()
                obj["co_code"] = _read_marshal(buf, version, refs)
                obj["co_consts"] = _read_marshal(buf, version, refs)
                obj["co_names"] = _read_marshal(buf, version, refs)
                obj["co_varnames"] = _read_marshal(buf, version, refs)
                obj["co_freevars"] = _read_marshal(buf, version, refs)
                obj["co_cellvars"] = _read_marshal(buf, version, refs)
                obj["co_filename"] = _read_marshal(buf, version, refs)
                obj["co_name"] = _read_marshal(buf, version, refs)
                obj["co_firstlineno"] = buf.ru32l()
                obj["co_lnotab"] = _read_marshal(buf, version, refs)
            elif version < 3450:  # Python 3.8 - 3.10
                obj["co_argcount"] = buf.ru32l()
                obj["co_posonlyargcount"] = buf.ru32l()
                obj["co_kwonlyargcount"] = buf.ru32l()
                obj["co_nlocals"] = buf.ru32l()
                obj["co_stacksize"] = buf.ru32l()
                obj["co_flags"] = buf.ru32l()
                obj["co_code"] = _read_marshal(buf, version, refs)
                obj["co_consts"] = _read_marshal(buf, version, refs)
                obj["co_names"] = _read_marshal(buf, version, refs)
                obj["co_varnames"] = _read_marshal(buf, version, refs)
                obj["co_freevars"] = _read_marshal(buf, version, refs)
                obj["co_cellvars"] = _read_marshal(buf, version, refs)
                obj["co_filename"] = _read_marshal(buf, version, refs)
                obj["co_name"] = _read_marshal(buf, version, refs)
                obj["co_firstlineno"] = buf.ru32l()
                obj["co_linetable" if version >= 3430 else "co_lnotab"] = _read_marshal(buf, version, refs)
            else:  # Python 3.11 - 3.14+
                obj["co_argcount"] = buf.ru32l()
                obj["co_posonlyargcount"] = buf.ru32l()
                obj["co_kwonlyargcount"] = buf.ru32l()
                obj["co_stacksize"] = buf.ru32l()
                obj["co_flags"] = buf.ru32l()
                obj["co_code"] = _read_marshal(buf, version, refs)
                obj["co_consts"] = _read_marshal(buf, version, refs)
                obj["co_names"] = _read_marshal(buf, version, refs)
                obj["co_localsplusnames"] = _read_marshal(buf, version, refs)
                obj["co_localspluskinds"] = _read_marshal(buf, version, refs)
                obj["co_filename"] = _read_marshal(buf, version, refs)
                obj["co_name"] = _read_marshal(buf, version, refs)
                obj["co_qualname"] = _read_marshal(buf, version, refs)
                obj["co_firstlineno"] = buf.ru32l()
                obj["co_linetable"] = _read_marshal(buf, version, refs)
                obj["co_exceptiontable"] = _read_marshal(buf, version, refs)

            return obj

        case _:
            raise ValueError(f"Unknown marshal type character '{typ}' (0x{ord(typ):02x})")


def _clean_marshal(o):
    if isinstance(o, list):
        return [_clean_marshal(x) for x in o]
    elif isinstance(o, tuple):
        return [_clean_marshal(x) for x in o]
    elif isinstance(o, dict):
        if "co_code" in o:
            pass

        return {x: _clean_marshal(y) for x, y in o.items()}
    elif isinstance(o, set):
        return [_clean_marshal(x) for x in o]
    elif isinstance(o, frozenset):
        return [_clean_marshal(x) for x in o]
    elif isinstance(o, bytes):
        return o.hex()
    else:
        return o


def read_marshal(*args, **kwargs):
    return _clean_marshal(_read_marshal(*args, **kwargs))


def tempfd():
    return tempfile.TemporaryFile()


def strip_url(url):
    if match := re.match(r"^(/wp-content/.+?/[^/]+)-\d+x\d+(\.[A-Za-z0-9]+)$", url.path):
        url = url._replace(path="".join(match.groups()))

    if url.netloc == "static.wixstatic.com":
        url = url._replace(path="/".join(url.path.split()[:3]))

    return url


def unpack_flags(val, names):
    flags = {"raw": val, "names": []}

    for k, v in names:
        if flags["raw"] & (1 << k):
            flags["names"].append(v)

    return flags


def memcpy_snappy(data, offset, length):
    start = len(data) - offset

    if offset >= length:
        data.extend(data[start : start + length])
    else:
        for i in range(0, length):
            data.append(data[start])
            start += 1


def unpack_snappy(blob):
    buf = Buf(blob)
    buf.ruleb()

    data = bytearray()
    while buf.available() > 0:
        op = buf.ru8()
        typ = op & 0x03

        match typ:
            case 0b00:
                length = op >> 2
                if length >= 60:
                    length = int.from_bytes(buf.read(length - 59), "little")

                if debug:
                    print("lit", op, length)

                data += buf.read(length + 1)
            case 0b01:
                length = ((op >> 2) & 0x07) + 4
                offset = ((op >> 5) << 8) | buf.ru8()

                if debug:
                    print("copy-1", op, length, offset)

                memcpy_snappy(data, offset, length)
            case 0b10 | 0b11:
                length = (op >> 2) + 1
                offset = buf.ru16l() if typ == 0b10 else buf.ru32l()

                if debug:
                    print("copy-2" if typ == 0b10 else "copy-4", op, length, offset)

                memcpy_snappy(data, offset, length)

    return bytes(data)


def expand_ranges(s: Any, lower: int, upper: int) -> list[int]:
    parts = cast(str, s).split(",")

    ranges: list[int] = []
    for part in parts:
        if "-" in part:
            a, b = part.split("-")

            if a != "":
                lower = int(a)
            if b != "":
                upper = int(b)

            ranges += range(lower, upper + 1)
        else:
            ranges.append(int(part))

    return sorted(list(set(ranges)))
