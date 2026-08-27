from . import chew
from .. import module, utils, constants, secrets, ruminant_types
from ..buf import Buf

import tempfile
import datetime
import base64
import zlib
import ipaddress
from typing import Any, cast


@module.register
class ZipModule(module.RuminantModule):
    desc = "ZIP files.\nThis includes file formats that use ZIP files as a container like e.g. DOCX or JAR files."

    CRC_TABLE = [0] * 256
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = (c >> 1) ^ 0xedb88320
            else:
                c >>= 1
        CRC_TABLE[i] = c

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"\x50\x4b\x03\x04"

    def to_timestamp(self, dos_date, dos_time):
        return datetime.datetime(
            ((dos_date >> 9) & 0x7f) + 1980,
            (dos_date >> 5) & 0x0f,
            dos_date & 0x1f,
            dos_time >> 11,
            (dos_time >> 5) & 0x3f,
            (dos_time & 0x1f) * 2,
        ).isoformat()

    def read_single_signature(self):
        signature = {}
        self.buf.pasunit(self.buf.ru32l())

        signature["algorithm"] = utils.unraw(
            self.buf.ru32l(),
            4,
            constants.APK_SIGNATURE_ALGORITHMS,
            True,
        )
        signature["signature"] = self.buf.rh(self.buf.ru32l())

        self.buf.sapunit()
        return signature

    def read_signature_sequence(self):
        signatures = []

        self.buf.pasunit(self.buf.ru32l())

        while self.buf.hasunit():
            signatures.append(self.read_single_signature())

        self.buf.sapunit()
        return signatures

    def read_attribute(self, small=False):
        entry = {}
        entry["length"] = self.buf.ru64l() if not small else self.buf.ru32l()
        entry["type"] = None
        entry["payload"] = {}

        self.buf.pasunit(entry["length"])

        typ = self.buf.ru32l()
        match typ:
            case 0x7109871a | 0xf05368c0:
                v3 = typ == 0xf05368c0
                entry["type"] = f"APK signature scheme {'v3' if v3 else 'v2'}"

                entry["payload"]["signers"] = []
                self.buf.pasunit(self.buf.ru32l())

                while self.buf.hasunit():
                    signer = {}
                    self.buf.pasunit(self.buf.ru32l())

                    signer["signed-data"] = {}
                    self.buf.pasunit(self.buf.ru32l())

                    signer["signed-data"]["digests"] = []
                    self.buf.pasunit(self.buf.ru32l())

                    while self.buf.hasunit():
                        digest = {}
                        self.buf.pasunit(self.buf.ru32l())

                        digest["algorithm"] = utils.unraw(
                            self.buf.ru32l(),
                            4,
                            constants.APK_SIGNATURE_ALGORITHMS,
                            True,
                        )

                        digest["digest"] = self.buf.rh(self.buf.ru32l())

                        self.buf.sapunit()
                        signer["signed-data"]["digests"].append(digest)

                    # digests
                    self.buf.sapunit()

                    signer["signed-data"]["certificates"] = []
                    self.buf.pasunit(self.buf.ru32l())
                    while self.buf.hasunit():
                        signer["signed-data"]["certificates"].append(utils.read_der(Buf(self.buf.read(self.buf.ru32l()))))

                    # certificates
                    self.buf.sapunit()

                    if v3:
                        signer["signed-data"]["min-sdk"] = self.buf.ru32l()
                        signer["signed-data"]["max-sdk"] = self.buf.ru32l()

                    signer["signed-data"]["additional-attributes"] = []
                    self.buf.pasunit(self.buf.ru32l())

                    while self.buf.hasunit():
                        attribute = {}
                        self.buf.pasunit(self.buf.ru32l())

                        key = self.buf.ru32l()
                        attribute["key"] = None
                        attribute["value"] = {}

                        match key:
                            case 0xbeeff00d:
                                attribute["key"] = "Stripping Protection"
                                attribute["value"]["signed-with-version"] = self.buf.ru32l()
                            case _:
                                attribute["key"] = f"Unknown (0x{hex(key)[2:].zfill(8)})"
                                attribute["value"]["hex"] = self.buf.rh(self.buf.unit)

                        self.buf.sapunit()
                        signer["signed-data"]["additional-attributes"].append(attribute)

                    # additional attributes
                    self.buf.sapunit()

                    # signed data
                    self.buf.sapunit()

                    if v3:
                        signer["min-sdk"] = self.buf.ru32l()
                        signer["max-sdk"] = self.buf.ru32l()

                    signer["signatures"] = self.read_signature_sequence()

                    signer["public-key"] = utils.read_der(Buf(self.buf.read(self.buf.ru32l())))

                    # signer
                    self.buf.sapunit()
                    entry["payload"]["signers"].append(signer)

                self.buf.sapunit()
            case 0x42726577:
                entry["type"] = "Padding"
                with self.buf.subunit():
                    entry["payload"]["blob"] = chew(self.buf)
            case 0x504b4453:
                entry["type"] = "Dependency Info Block"
                with self.buf.subunit():
                    entry["payload"]["blob"] = chew(self.buf, blob_mode=True)
            case 0x6dff800d:
                entry["type"] = "Source Stamp Block"
                entry["payload"]["size"] = self.buf.ru32l()
                self.buf.pasunit(entry["payload"]["size"])

                entry["payload"]["entries"] = []
                while self.buf.hasunit():
                    ntry = {}
                    ntry["size"] = self.buf.ru32l()
                    ntry["type"] = "Unknown"
                    ntry["payload"] = {}

                    self.buf.pasunit(ntry["size"])

                    match len(entry["payload"]["entries"]):
                        case 0:
                            ntry["type"] = "Certificate"
                            ntry["payload"] = utils.read_der(self.buf)
                        case 1:
                            ntry["type"] = "Multiple Signatures"
                            ntry["payload"]["signatures"] = []

                            while self.buf.hasunit():
                                sig = {}
                                sig["size"] = self.buf.ru32l()

                                self.buf.pasunit(sig["size"])

                                sig["id"] = self.buf.ru32l()
                                sig["signatures"] = self.read_signature_sequence()

                                self.buf.sapunit()
                                ntry["payload"]["signatures"].append(sig)
                        case 2:
                            ntry["type"] = "Attributes"
                            ntry["payload"]["size"] = self.buf.ru32l()

                            self.buf.pasunit(ntry["payload"]["size"])

                            ntry["payload"]["entries"] = []
                            while self.buf.hasunit():
                                ntry["payload"]["entries"].append(self.read_attribute(True))

                            self.buf.sapunit()
                        case 3:
                            ntry["type"] = "Single Signature"
                            ntry["payload"] = self.read_single_signature()
                        case _:
                            with self.buf.subunit():
                                ntry["payload"] = chew(self.buf, blob_mode=True)

                    self.buf.sapunit()
                    entry["payload"]["entries"].append(ntry)

                self.buf.sapunit()
            case 0xe43c5946:
                entry["type"] = "Build Time"
                entry["payload"]["time"] = utils.unix_to_date(self.buf.ru64l())
            case _:
                entry["type"] = f"Unknown (0x{hex(typ)[2:].zfill(8)})"

                with self.buf.subunit():
                    entry["payload"]["blob"] = chew(self.buf, blob_mode=True)

        self.buf.sapunit()
        return entry

    def crc32_update(self, crc, byte):
        return (self.CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >> 8)) & 0xffffffff

    def kdf(self, passwd):
        passwd = passwd.encode("utf-8")

        K0 = 305419896
        K1 = 591751049
        K2 = 878082192

        for b in passwd:
            K0 = self.crc32_update(K0, b)
            K1 = (K1 + (K0 & 0xff)) & 0xffffffff
            K1 = (K1 * 134775813 + 1) & 0xffffffff
            K2 = self.crc32_update(K2, (K1 >> 24) & 0xff)

        return K0, K1, K2

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "zip"

        self.buf.search(b"\x50\x4b\x05\x06")

        self.buf.skip(4)
        meta["eocd"] = {}
        meta["eocd"]["disc-count"] = self.buf.ru16l()
        meta["eocd"]["central-directory-first-disk"] = self.buf.ru16l()
        meta["eocd"]["central-directory-local-count"] = self.buf.ru16l()
        meta["eocd"]["central-directory-global-count"] = self.buf.ru16l()
        meta["eocd"]["central-directory-size"] = self.buf.ru32l()
        meta["eocd"]["central-directory-offset"] = self.buf.ru32l()
        meta["eocd"]["comment"] = self.buf.rs(self.buf.ru16l())
        eof = self.buf.tell()

        self.buf.seek(meta["eocd"]["central-directory-offset"])

        meta["key"] = None
        meta["files"] = []
        while self.buf.pu32() == 0x504b0102:
            self.buf.skip(4)

            file: dict = {}
            file["meta"] = {}
            temp = self.buf.ru16l()
            file["meta"]["version-producer"] = {
                "platform": utils.unraw(
                    temp >> 8,
                    1,
                    {
                        0x00: "MS-DOS / FAT",
                        0x03: "Unix",
                        0x0a: "Windows NTFS",
                        0x0b: "MVS",
                        0x0f: "Mac OS",
                        0x19: "macOS (Unix)",
                    },
                    True,
                ),
                "pkzip-version": f"{(temp & 0xff) // 10}.{(temp & 0xff) % 10}",
            }
            temp = self.buf.ru16l()
            file["meta"]["version-needed"] = f"{(temp & 0xff) // 10}.{(temp & 0xff) % 10}"
            file["meta"]["general-flags"] = utils.unpack_flags(
                self.buf.ru16l(),
                (
                    (0, "encrypted"),
                    (1, "compression option 1"),
                    (2, "compression option 2"),
                    (3, "data-descriptor-present"),
                    (4, "enhanced deflation"),
                    (5, "compressed patched data"),
                    (6, "strong encryption"),
                    (8, "utf8"),
                    (9, "local header values masked"),
                ),
            )
            file["meta"]["compression-method"] = utils.unraw(self.buf.ru16l(), 2, constants.ZIP_COMPRESSION_ALGORITHMS, True)
            file["meta"]["modification-time"] = self.buf.ru16l()
            file["meta"]["modification-date"] = self.buf.ru16l()
            file["meta"]["modification-timestamp"] = self.to_timestamp(
                file["meta"]["modification-date"], file["meta"]["modification-time"]
            )
            file["meta"]["crc32"] = self.buf.rh(4)
            file["meta"]["compressed-size"] = self.buf.ru32l()
            file["uncompressed-size"] = self.buf.ru32l()
            filename_length = self.buf.ru16l()
            extra_field_length = self.buf.ru16l()
            comment_length = self.buf.ru16l()
            file["meta"]["start-disk"] = self.buf.ru16l()
            file["meta"]["internal-attributes"] = utils.unpack_flags(self.buf.ru16l(), ((0, "text file"),))
            file["meta"]["external-attributes"] = {
                "dos-attributes": self.buf.ru16l(),
            }
            match file["meta"]["version-producer"]["platform"]:
                case "Unix" | "macOS (Unix)":
                    st_mode = self.buf.ru16l()
                    file["meta"]["external-attributes"]["st-mode"] = {
                        "type": utils.unraw(
                            st_mode >> 12,
                            1,
                            {
                                0x08: "file",
                                0x04: "directory",
                                0x0a: "symlink",
                                0x02: "char device",
                                0x06: "block device",
                                0x01: "FIFO",
                                0x0c: "socket",
                            },
                            True,
                        ),
                        "flags": utils.unpack_flags(
                            st_mode & 0x0fff,
                            (
                                (0, "other-execute"),
                                (1, "other-write"),
                                (2, "other-read"),
                                (3, "group-execute"),
                                (4, "group-write"),
                                (5, "group-read"),
                                (6, "user-execute"),
                                (7, "user-write"),
                                (8, "user-read"),
                                (9, "sticky"),
                                (10, "set-gid"),
                                (11, "set-uid"),
                            ),
                        ),
                    }
                case "MS-DOS / FAT" | "Windows NTFS":
                    file["meta"]["external-attributes"]["st-mode"] = utils.unpack_flags(
                        self.buf.ru16l(),
                        (
                            (0, "read-only"),
                            (1, "hidden"),
                            (2, "system"),
                            (3, "volume label"),
                            (4, "directory"),
                            (5, "archive"),
                            (6, "device"),
                        ),
                    )
                case _:
                    file["meta"]["external-attributes"]["platform-attributes"] = self.buf.ru16l()

            file["offset"] = self.buf.ru32l()
            file["filename"] = self.buf.rs(filename_length)

            self.buf.pasunit(extra_field_length)

            file["meta"]["extra-field"] = []
            while self.buf.hasunit():
                entry: dict = {}
                typ = self.buf.ru16l()
                entry["type"] = None
                entry["length"] = self.buf.ru16l()
                payload: dict = {}
                entry["payload"] = payload

                self.buf.pasunit(entry["length"])
                match typ:
                    case 0x000a:
                        entry["type"] = "NTFS"
                        payload["reserved"] = self.buf.ru32l()

                        payload["entries"] = []
                        while self.buf.hasunit():
                            tag: dict = {}
                            tag["type"] = utils.unraw(self.buf.ru16l(), 2, {0x0001: "File Times"}, True)
                            tag["length"] = self.buf.ru16l()
                            tag["payload"] = {}

                            self.buf.pasunit(tag["length"])

                            match tag["type"]:
                                case "File Times":
                                    tag["payload"]["modification-time"] = utils.filetime_to_date(self.buf.ru64l())
                                    tag["payload"]["access-time"] = utils.filetime_to_date(self.buf.ru64l())
                                    tag["payload"]["creation-time"] = utils.filetime_to_date(self.buf.ru64l())
                                case _:
                                    tag["unknown"] = True

                            self.buf.sapunit()
                            payload["entries"].append(tag)
                    case 0x5455:
                        entry["type"] = "Extended Timestamp"
                        flags = self.buf.ru8()
                        if flags & 0x01 and self.buf.hasunit():
                            payload["mtime"] = utils.unix_to_date(self.buf.ru32l())
                        if flags & 0x02 and self.buf.hasunit():
                            payload["ctime"] = utils.unix_to_date(self.buf.ru32l())
                        if flags & 0x04 and self.buf.hasunit():
                            payload["atime"] = utils.unix_to_date(self.buf.ru32l())
                    case 0x7875:
                        entry["type"] = "Unicode Path"
                        payload["version"] = self.buf.ru8()
                        payload["uid"] = int.from_bytes(self.buf.read(self.buf.ru8()), "little")
                        payload["gid"] = int.from_bytes(self.buf.read(self.buf.ru8()), "little")
                    case 0x9901:
                        entry["type"] = "AES Extra Data Field"
                        payload["version"] = self.buf.ru16l()
                        payload["vendor"] = self.buf.rs(2)
                        payload["cipher"] = utils.unraw(
                            self.buf.ru8(),
                            2,
                            {
                                0x01: "AES-128",
                                0x02: "AES-192",
                                0x03: "AES-256",
                            },
                            True,
                        )
                        payload["compression-mode"] = utils.unraw(
                            self.buf.ru16l(),
                            2,
                            constants.ZIP_COMPRESSION_ALGORITHMS,
                            True,
                        )
                    case 0xcafe:
                        entry["type"] = "JAR indicator"
                    case _:
                        entry["type"] = f"Unknown (0x{hex(typ)[2:].zfill(4)})"
                        payload = self.buf.rh(self.buf.unit)
                        entry["unknown"] = True

                self.buf.sapunit()
                file["meta"]["extra-field"].append(entry)

            self.buf.sapunit()

            file["meta"]["comment"] = self.buf.rs(comment_length)

            if file["uncompressed-size"] > 0:
                with self.buf:
                    self.buf.seek(file["offset"])
                    assert self.buf.ru32() == 0x504b0304, "broken ZIP file"
                    self.buf.skip(22)
                    self.buf.skip(self.buf.ru16l() + self.buf.ru16l())

                    if file["meta"]["general-flags"]["raw"] & 0x0041:
                        if meta["key"] is None:
                            key_data: dict[str, Any] = {}
                            meta["key"] = key_data
                            key_data["name"] = self.buf.ph(12)
                            key_data["found"] = secrets.get(key_data["name"]) is not None

                        key = secrets.get(meta["key"]["name"])
                        if isinstance(key, str):
                            key = self.kdf(key)
                            secrets.set(meta["key"]["name"], key)

                        if key is not None:
                            file["password-header"] = ""
                            tfd = tempfile.TemporaryFile()

                            ikey: list[int] = list(cast(bytes, key))
                            for i in range(0, file["meta"]["compressed-size"]):
                                c = self.buf.ru8()
                                temp = (ikey[2] & 0xffff) | 2
                                k = ((temp * (temp ^ 1)) >> 8) & 0xff
                                c ^= k

                                if i >= 12:
                                    tfd.write(bytes([c]))
                                else:
                                    file["password-header"] += hex(c)[2:].zfill(2)

                                ikey[0] = self.crc32_update(ikey[0], c)
                                ikey[1] = (ikey[1] + (ikey[0] & 0xff)) & 0xffffffff
                                ikey[1] = (ikey[1] * 134775813 + 1) & 0xffffffff
                                ikey[2] = self.crc32_update(ikey[2], (ikey[1] >> 24) & 0xff)

                            tfd.seek(0)
                            fd = Buf(tfd)

                            match file["meta"]["compression-method"]:
                                case "Uncompressed":
                                    file["data"] = chew(fd)

                                case "Deflate":
                                    fd2 = tempfile.TemporaryFile()
                                    utils.stream_deflate(fd, fd2, fd.available())
                                    fd2.seek(0)

                                    file["data"] = chew(fd2)
                        else:
                            with self.buf.sub(file["meta"]["compressed-size"]):
                                file["encrypted-data"] = chew(self.buf, blob_mode=True)
                    else:
                        match file["meta"]["compression-method"]:
                            case "Uncompressed":
                                with self.buf.sub(file["uncompressed-size"]):
                                    file["data"] = chew(self.buf)

                            case "Deflate":
                                with self.buf.sub(file["meta"]["compressed-size"]):
                                    tfd = tempfile.TemporaryFile()
                                    utils.stream_deflate(self.buf, tfd, self.buf.available())
                                    tfd.seek(0)

                                    file["data"] = chew(tfd)

            meta["files"].append(file)

        if meta["eocd"]["central-directory-offset"] > 16:
            self.buf.seek(meta["eocd"]["central-directory-offset"] - 16)
            if self.buf.available() >= 16 and self.buf.read(16) == b"APK Sig Block 42":
                meta["apk-signature"] = {}

                self.buf.seek(meta["eocd"]["central-directory-offset"] - 24)
                meta["apk-signature"]["trailer-length"] = self.buf.ru64l()
                self.buf.seek(meta["eocd"]["central-directory-offset"] - 8 - meta["apk-signature"]["trailer-length"])

                self.buf.pasunit(meta["apk-signature"]["trailer-length"] - 16)

                meta["apk-signature"]["header-length"] = self.buf.ru64l()

                meta["apk-signature"]["entries"] = []
                while self.buf.hasunit():
                    meta["apk-signature"]["entries"].append(self.read_attribute())

                self.buf.sapunit()

        self.buf.seek(eof)

        if meta["key"] is None:
            del meta["key"]

        return meta


@module.register
class RIFFModule(module.RuminantModule):
    desc = "RIFF files.\nThis includes file types like WebP, WAV, AVI or DjVu."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) in (b"RIFF", b"AT&T")

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = {b"RIFF": "riff", b"AT&T": "djvu"}[self.buf.peek(4)]

        if meta["type"] == "djvu":
            self.buf.skip(4)
            self.le = False
        else:
            self.le = True

        self.strh_type = None
        meta["data"] = self.read_chunk()

        return meta

    def read_chunk(self):
        chunk = {}

        typ = self.buf.rs(4)
        chunk["type"] = typ
        chunk["offset"] = self.buf.tell() - 4
        length = self.buf.ru32l() if self.le else self.buf.ru32()
        chunk["length"] = length

        self.buf.pushunit()
        self.buf.setunit(((length + 1) >> 1) << 1)

        chunk["data"] = {}
        match typ:
            case "VP8 ":
                tag = self.buf.ru24()
                chunk["data"]["keyframe"] = bool(tag & 0x800000)
                chunk["data"]["version"] = (tag >> 20) & 0x07
                chunk["data"]["show-frame"] = bool(tag & 0x80000)
                chunk["data"]["partition-size"] = tag & 0x7ffff
                chunk["data"]["start-code"] = self.buf.rh(3)
                chunk["data"]["width"] = self.buf.ru16l() & 0x3fff
                chunk["data"]["height"] = self.buf.ru16l() & 0x3fff
            case "VP8L":
                chunk["data"]["signature"] = self.buf.rh(1)
                tag = self.buf.ru32l()
                for field in ("width", "height"):
                    i = 1
                    for j in range(0, 14):
                        i += (tag & 1) << j
                        tag >>= 1

                    chunk["data"][field] = i

                chunk["data"]["has-alpha"] = bool(tag & 1)
                chunk["data"]["version"] = ((tag >> 1) & 1) | (((tag >> 2) & 1) << 1) | (((tag >> 3) & 1) << 2)
            case "ANIM":
                chunk["data"]["background-color"] = {
                    "red": self.buf.ru8(),
                    "green": self.buf.ru8(),
                    "blue": self.buf.ru8(),
                    "alpha": self.buf.ru8(),
                }
                chunk["data"]["loop-count"] = self.buf.ru16l()
            case "ANMF":
                chunk["data"]["frame-x"] = self.buf.ru24l()
                chunk["data"]["frame-y"] = self.buf.ru24l()
                chunk["data"]["frame-width"] = self.buf.ru24l() + 1
                chunk["data"]["frame-height"] = self.buf.ru24l() + 1
                chunk["data"]["frame-duration"] = self.buf.ru24l()

                tag = self.buf.ru8()
                chunk["data"]["reserved"] = tag >> 2
                chunk["data"]["alpha-blend"] = not bool(tag & 2)
                chunk["data"]["dispose"] = bool(tag & 1)
            case "ALPH":
                tag = self.buf.ru8()
                chunk["data"]["reserved"] = tag >> 6
                chunk["data"]["preprocessing"] = (tag >> 4) & 0x03
                chunk["data"]["filtering-method"] = (tag >> 2) & 0x03
                chunk["data"]["compression-method"] = tag & 0x03
            case "VP8X":
                tag = self.buf.ru32()
                chunk["data"]["reserved1"] = tag >> 30
                chunk["data"]["has-icc-profile"] = bool(tag & (1 << 29))
                chunk["data"]["has-alpha"] = bool(tag & (1 << 28))
                chunk["data"]["has-exif"] = bool(tag & (1 << 27))
                chunk["data"]["has-xmp"] = bool(tag & (1 << 26))
                chunk["data"]["has-animation"] = bool(tag & (1 << 25))
                chunk["data"]["reserved2"] = tag & 0x1ffffff
                chunk["data"]["width"] = self.buf.ru24l() + 1
                chunk["data"]["height"] = self.buf.ru24l() + 1
            case "fmt ":
                chunk["data"]["format"] = self.buf.ru16l()
                chunk["data"]["channel-count"] = self.buf.ru16l()
                chunk["data"]["sample-rate"] = self.buf.ru32l()
                chunk["data"]["byte-rate"] = self.buf.ru32l()
                chunk["data"]["block-align"] = self.buf.ru16l()
                chunk["data"]["bits-per-sample"] = self.buf.ru16l()
            case "ICCP":
                with self.buf.subunit():
                    chunk["data"]["color-profile"] = chew(self.buf)
            case "avih":
                chunk["data"]["microseconds-per-frame"] = self.buf.ru32l()
                chunk["data"]["max-bytes-per-second"] = self.buf.ru32l()
                chunk["data"]["padding-granularity"] = self.buf.ru32l()
                chunk["data"]["flags"] = self.buf.rh(4)
                chunk["data"]["frame-count"] = self.buf.ru32l()
                chunk["data"]["initial-frames"] = self.buf.ru32l()
                chunk["data"]["stream-count"] = self.buf.ru32l()
                chunk["data"]["buffer-size"] = self.buf.ru32l()
                chunk["data"]["width"] = self.buf.ru32l()
                chunk["data"]["height"] = self.buf.ru32l()
                chunk["data"]["reserved"] = self.buf.rh(16)

                chunk["data"]["derived"] = {}
                chunk["data"]["derived"]["fps"] = 1000000 / chunk["data"]["microseconds-per-frame"]
                chunk["data"]["derived"]["duration-in-seconds"] = (
                    chunk["data"]["frame-count"] * chunk["data"]["microseconds-per-frame"] / 1000000
                )
            case "strh":
                self.strh_type = self.buf.rs(4)
                chunk["data"]["type"] = self.strh_type
                chunk["data"]["handler"] = self.buf.rs(4)
                chunk["data"]["flags"] = self.buf.rh(4)
                chunk["data"]["priority"] = self.buf.ru16l()

                language = self.buf.ru16l()
                chunk["data"]["language"] = {
                    "raw": language,
                    "name": constants.MICROSOFT_LCIDS.get(language, "Unknown"),
                }

                chunk["data"]["initial-frames"] = self.buf.ru32l()
                chunk["data"]["scale"] = self.buf.ru32l()
                chunk["data"]["rate"] = self.buf.ru32l()
                chunk["data"]["start"] = self.buf.ru32l()
                chunk["data"]["length"] = self.buf.ru32l()
                chunk["data"]["buffer-size"] = self.buf.ru32l()
                chunk["data"]["quality"] = self.buf.ri32l()
                chunk["data"]["sample-size"] = self.buf.ru32l()
                chunk["data"]["frame-left"] = self.buf.ru16l()
                chunk["data"]["frame-top"] = self.buf.ru16l()
                chunk["data"]["frame-right"] = self.buf.ru16l()
                chunk["data"]["frame-bottom"] = self.buf.ru16l()
            case "strf":
                match self.strh_type:
                    case "vids":
                        chunk["data"]["header-size"] = self.buf.ru32l()
                        chunk["data"]["width"] = self.buf.ru32l()
                        chunk["data"]["height"] = self.buf.ru32l()
                        chunk["data"]["plane-count"] = self.buf.ru16l()
                        chunk["data"]["bits-per-pixel"] = self.buf.ru16l()
                        chunk["data"]["compression-method"] = self.buf.rs(4)
                        chunk["data"]["image-size"] = self.buf.ru32l()
                        chunk["data"]["horizontal-resolution"] = self.buf.ru32l()
                        chunk["data"]["vertical-resolution"] = self.buf.ru32l()
                        chunk["data"]["used-color-count"] = self.buf.ru32l()
                        chunk["data"]["important-color-count"] = self.buf.ru32l()
                    case "auds":
                        format_tag = self.buf.ru16l()
                        chunk["data"]["format"] = {
                            "raw": format_tag,
                            "name": {
                                0x0001: "PCM",
                                0x0050: "MPEG",
                                0x0055: "MP3",
                                0x2000: "AC-3",
                                0x00ff: "AAC",
                                0x0161: "WMA",
                                0x2001: "DTS",
                                0xf1ac: "FLAC",
                            }.get(format_tag, "Unknown"),
                        }

                        chunk["data"]["channel-count"] = self.buf.ru16l()
                        chunk["data"]["sample-rate"] = self.buf.ru32l()
                        chunk["data"]["average-bytes-per-second"] = self.buf.ru32l()
                        chunk["data"]["block-alignment"] = self.buf.ru16l()
                        chunk["data"]["bits-per-sample"] = self.buf.ru16l()

                        codec_data_size = self.buf.ru16l()
                        chunk["data"]["codec-data-size"] = codec_data_size
                    case _:
                        chunk["data"]["unknown-type"] = True

                self.strh_type = None
            case "vprp":
                chunk["data"]["format"] = self.buf.rs(4)

                standard = self.buf.ru32l()
                chunk["data"]["standard"] = {
                    "raw": standard,
                    "name": {0: "NTSC", 1: "PAL", 2: "SECAM"}.get(standard, "Unknown"),
                }

                chunk["data"]["vertical-refresh-rate"] = self.buf.ru32l()
                chunk["data"]["horizontal-total"] = self.buf.ru32l()
                chunk["data"]["vertical-total"] = self.buf.ru32l()

                y, x = self.buf.ru16l(), self.buf.ru16l()
                chunk["data"]["aspect-ratio"] = f"{x}:{y}"

                chunk["data"]["width"] = self.buf.ru32l()
                chunk["data"]["height"] = self.buf.ru32l()

                field_count = self.buf.ru32l()
                chunk["data"]["field-count"] = field_count

                chunk["data"]["fields"] = []
                for i in range(0, field_count):
                    field = {}
                    field["compressed-width"] = self.buf.ru32l()
                    field["compressed-height"] = self.buf.ru32l()
                    field["valid-width"] = self.buf.ru32l()
                    field["valid-height"] = self.buf.ru32l()
                    field["valid-x-offset"] = self.buf.ru32l()
                    field["valid-y-offset"] = self.buf.ru32l()

                    chunk["data"]["fields"].append(field)
            case "INFO":
                chunk["data"]["width"] = self.buf.ru16()
                chunk["data"]["height"] = self.buf.ru16()
                chunk["data"]["minor-version"] = self.buf.ru8()
                chunk["data"]["major-version"] = self.buf.ru8()
                chunk["data"]["dpi"] = self.buf.ru16()
                chunk["data"]["gamma"] = self.buf.ru8() / 10

                flags = self.buf.ru8()
                chunk["data"]["flags"] = {
                    "raw": flags,
                    "rotation": {
                        1: "0 degrees",
                        6: "90 degrees counter clockwise",
                        2: "180 degrees",
                        5: "90 degrees clockwise",
                    }.get(flags & 0x07, f"Unknown ({flags & 0x07})"),
                }
            case "INCL":
                chunk["data"]["id"] = utils.decode(self.buf.readunit()).rstrip("\x00")
            case "fact":
                chunk["data"]["sample-count"] = self.buf.ru32l()
            case "cue ":
                chunk["data"]["cues"] = []

                for i in range(0, self.buf.ru32l()):
                    cue = {}
                    cue["id"] = self.buf.ru32l()
                    cue["position"] = self.buf.ru32l()
                    cue["data-chunk-id"] = self.buf.rs(4)
                    cue["chunk-start"] = self.buf.ru32l()
                    cue["block-start"] = self.buf.ru32l()
                    cue["sample-offset"] = self.buf.ru32l()

                    chunk["data"]["cues"].append(cue)
            case "labl":
                chunk["data"]["cue-id"] = self.buf.ru32l()
                chunk["data"]["label"] = self.buf.rzs()
            case "bext":
                chunk["data"]["description"] = self.buf.rs(256)
                chunk["data"]["originator"] = self.buf.rs(32)
                chunk["data"]["originator-ref"] = self.buf.rs(32)
                chunk["data"]["originator-date"] = self.buf.rs(10)
                chunk["data"]["originator-time"] = self.buf.rs(8)
                chunk["data"]["time-reference"] = self.buf.ru64l()
                chunk["data"]["version"] = self.buf.ru16l()

                if sum(self.buf.peek(64)):
                    chunk["data"]["umid"] = self.buf.rh(64)
                else:
                    self.buf.skip(64)

                if sum(self.buf.peek(190)):
                    chunk["data"]["reserved"] = self.buf.rh(190)
                else:
                    self.buf.skip(190)

                chunk["data"]["coding-history"] = utils.decode(self.buf.readunit()).rstrip("\x00")
            case "iXML" | "_PMX":
                chunk["data"]["xml"] = utils.xml_to_dict(self.buf.readunit())
            case "ID3 ":
                with self.buf.subunit():
                    chunk["data"]["id3-tag"] = chew(self.buf)
            case "SNDM":
                chunk["data"]["entries"] = []

                while self.buf.unit >= 12:
                    entry = {}
                    length = self.buf.ru32()
                    entry["key"] = self.buf.rs(4)
                    self.buf.skip(4)
                    entry["value"] = self.buf.rs(length - 12)

                    chunk["data"]["entries"].append(entry)
            case "PAD " | "FLLR" | "filr" | "regn":
                content = self.buf.readunit()

                chunk["data"]["non-zero"] = bool(sum(content))

                if chunk["data"]["non-zero"]:
                    chunk["data"]["data"] = chew(content)
            case "EXIF":
                with self.buf.subunit():
                    chunk["data"]["exif"] = chew(self.buf)
            case "XMP " | "XMP":
                with self.buf.subunit():
                    chunk["data"]["xmp"] = utils.xml_to_dict(self.buf.readunit())
            case "ICMT" | "ISFT" | "INAM" | "IART" | "ICRD" | "IARL" | "ILNG" | "IMED" | "ISRC" | "ISRF" | "ITCH" | "strn":
                chunk["data"]["text"] = utils.decode(self.buf.readunit()).rstrip("\x00")
            case "RIFF" | "LIST" | "FORM":
                chunk["data"]["type"] = self.buf.rs(4)

                if chunk["data"]["type"] != "movi":
                    chunk["data"]["chunks"] = []

                    while self.buf.unit:
                        list_chunk = self.read_chunk()
                        chunk["data"]["chunks"].append(list_chunk)
            case "data" | "JUNK" | "idx1" | "indx" | "ix00" | "ix01":
                pass
            case _:
                chunk["data"]["unknown"] = True

                with self.buf.subunit():
                    chunk["data"]["blob"] = chew(self.buf)

        self.buf.skipunit()
        self.buf.popunit()

        return chunk


@module.register
class TarModule(module.RuminantModule):
    desc = "TAR files or more specifically USTAR files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(262)[257:] == b"ustar"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "tar"

        meta["name"] = self.buf.rs(100).rstrip(" ").rstrip("\x00")
        meta["mode"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["owner-uid"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["owner-gid"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")

        file_length = self.buf.rs(12).rstrip(" ").rstrip("\x00")
        meta["size"] = file_length

        meta["modification-date"] = utils.unix_to_date(int(self.buf.rs(12).rstrip(" ").rstrip("\x00"), 8))
        meta["checksum"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["file-type"] = utils.unraw(
            self.buf.ru8(),
            1,
            {
                0: "Normal file",
                ord("0"): "Normal file",
                ord("1"): "Hard link",
                ord("2"): "Soft link",
                ord("3"): "Character special",
                ord("4"): "Block special",
                ord("5"): "Directory",
                ord("6"): "FIFO",
                ord("7"): "Contiguous file",
                ord("g"): "Global pax header",
                ord("x"): "Local pax header",
            },
        )

        meta["link-name"] = self.buf.rs(100).rstrip(" ").rstrip("\x00")

        self.buf.skip(6)

        meta["ustar-version"] = self.buf.rs(2).rstrip(" ").rstrip("\x00")
        meta["owner-user-name"] = self.buf.rs(32).rstrip(" ").rstrip("\x00")
        meta["owner-group-name"] = self.buf.rs(32).rstrip(" ").rstrip("\x00")
        meta["device-major"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["device-minor"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["name"] = self.buf.rs(155).rstrip(" ").rstrip("\x00") + meta["name"]

        self.buf.skip(12)

        file_length = int(file_length, 8)

        if file_length > 0:
            self.buf.pushunit()
            self.buf.setunit(file_length)

            with self.buf.subunit():
                if meta["file-type"]["raw"] == ord("x"):
                    meta["data"] = self.buf.readunit().decode("utf-8")
                else:
                    meta["data"] = chew(self.buf)

            self.buf.skipunit()
            self.buf.popunit()

            if file_length % 512:
                self.buf.skip(512 - (file_length % 512))

        return meta


@module.register
class ArModule(module.RuminantModule):
    desc = "Unix ar files like the ones produced for static libraries."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(8) == b"!<arch>\n"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "ar"

        self.buf.skip(8)
        meta["files"] = []
        while self.buf.available() >= 58:
            file = {}
            file["name"] = self.buf.rs(16).rstrip(" ")
            file["modification-time"] = utils.unix_to_date(int("0" + self.buf.rs(12).rstrip(" ")))
            file["owner-id"] = int("0" + self.buf.rs(6).rstrip(" "))
            file["group-id"] = int("0" + self.buf.rs(6).rstrip(" "))
            file["mode"] = self.buf.rs(8).rstrip(" ")
            file["size"] = int("0" + self.buf.rs(10).rstrip(" "))
            self.buf.skip(2)

            if self.buf.tell() % 2 != 0:
                self.buf.skip(1)

            self.buf.pasunit(file["size"])
            with self.buf.subunit():
                file["content"] = chew(self.buf)
            self.buf.sapunit()

            meta["files"].append(file)

        return meta


@module.register
class CpioModule(module.RuminantModule):
    desc = "ASCII cpio files like the ones used for the Linux initramfs."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(6) in (b"070701", b"070702")

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "cpio"

        meta["files"] = []
        while self.buf.available() >= 110 and self.buf.peek(6) == b"070701":
            file = {}
            self.buf.skip(6)
            file["inode"] = int(self.buf.rs(8), 16)
            file["mode"] = self.buf.rs(8)
            file["user-id"] = int(self.buf.rs(8), 16)
            file["group-id"] = int(self.buf.rs(8), 16)
            file["link-count"] = int(self.buf.rs(8), 16)
            file["modification-time"] = utils.unix_to_date(int(self.buf.rs(8), 16))
            file["size"] = int(self.buf.rs(8), 16)
            file["device-major"] = int(self.buf.rs(8), 16)
            file["device-minor"] = int(self.buf.rs(8), 16)
            file["special-device-major"] = int(self.buf.rs(8), 16)
            file["special-device-minor"] = int(self.buf.rs(8), 16)
            file["name-size"] = int(self.buf.rs(8), 16)
            file["crc"] = self.buf.rs(8)

            file["name"] = self.buf.rs(file["name-size"])
            while self.buf.tell() % 4 != 0:
                self.buf.skip(1)

            if file["size"] > 0:
                self.buf.pasunit(file["size"])
                with self.buf.subunit():
                    file["content"] = chew(self.buf)
                self.buf.sapunit()

                while self.buf.tell() % 4 != 0:
                    self.buf.skip(1)

            meta["files"].append(file)

        return meta


@module.register
class HttpFramedModule(module.RuminantModule):
    desc = "HTTP framed streams like mjpeg."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(7) == b"--FRAME"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "http-frame"
        self.buf.rl()
        self.buf.rl()
        self.buf.rl()

        return meta


@module.register
class JmodModule(module.RuminantModule):
    desc = "Java .jmod files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"\x4a\x4d\x01\x00"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "jmod"

        self.buf.skip(4)
        with self.buf.sub(self.buf.available()):
            meta["content"] = chew(self.buf)

        return meta


class Span(object):
    def __init__(self) -> None:
        self.ranges: list[list[int]] = []

    def add(self, address: int, length: int) -> None:
        self.ranges.append([address, address + length])

        self._fix()

    def _fix(self) -> None:
        new_ranges: list[list[int]] = []
        ranges = sorted(self.ranges, key=lambda x: x[0])

        for r in ranges:
            new_ranges.append(r)

            if len(new_ranges) >= 2 and new_ranges[-2][1] == new_ranges[-1][0]:
                new_ranges[-2][1] = new_ranges[-1][1]
                new_ranges.pop()

        self.ranges = new_ranges


@module.register
class Uf2Module(module.RuminantModule):
    desc = "UF2 files (e.g. for RP2040)."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(8) == b"UF2\nWQ]\x9e"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "uf2"

        meta["blocks"] = []
        while self.buf.peek(4) == b"UF2\n":
            block: dict = {}
            self.buf.pasunit(512)

            block["offset"] = self.buf.tell()
            self.buf.skip(4)
            block["second-magic-correct"] = self.buf.ru32l() == 0x9e5d5157
            block["flags"] = utils.unpack_flags(
                self.buf.ru32l(),
                (
                    (0, "not-flash"),
                    (12, "file-container"),
                    (13, "family-id-present"),
                    (14, "md5-present"),
                    (15, "extension-tags-present"),
                ),
            )
            block["address"] = f"0x{hex(self.buf.ru32l())[2:].zfill(8)}"
            block["bytes-used"] = self.buf.ru32l()
            block["block-number"] = self.buf.ru32l()
            block["total-block-number"] = self.buf.ru32l()

            if "family-id-present" in block["flags"]["names"]:
                block["family-id"] = utils.unraw(self.buf.ru32l(), 4, constants.UF2_FAMILY_IDS, True)
            elif "file-container" in block["flags"]["names"]:
                block["file-size"] = self.buf.ru32l()
            else:
                block["unused"] = self.buf.ru32l()

            self.buf.pasunit(476)

            if "extension-tags-present" in block["flags"]["names"]:
                self.buf.skip(block["bytes-used"])
                if block["bytes-used"] % 4:
                    self.buf.skip(4 - (block["bytes-used"] % 4))

                block["extension-tags"] = []
                while self.buf.hasunit():
                    tag: dict = {}

                    tag["size"] = self.buf.ru8()
                    if tag["size"] == 0 and self.buf.pu24l() == 0:
                        break

                    tag["type"] = utils.unraw(
                        self.buf.ru24l(),
                        3,
                        {0x9957e3: "RP2350 Errata E10 abs block"},
                        True,
                    )

                    self.buf.pasunit(tag["size"] - 4)

                    tag["payload"] = {}
                    match tag["type"]:
                        case "RP2350 Errata E10 abs block":
                            pass
                        case _:
                            tag["payload"]["raw"] = self.buf.rh(self.buf.unit)
                            tag["unknown"] = True

                    self.buf.sapunit()
                    block["extension-tags"].append(tag)

            self.buf.sapunit()
            block["third-magic-correct"] = self.buf.ru32l() == 0x0ab16f30

            self.buf.sapunit()
            meta["blocks"].append(block)

        families = set()
        for block in meta["blocks"]:
            families.add(block.get("family-id", "Generic"))

        meta["families"] = list(families)

        spans = {}
        for block in meta["blocks"]:
            family_id = block.get("family-id", "Generic")

            if family_id not in spans:
                spans[family_id] = Span()

            spans[family_id].add(int(block["address"][2:], 16), block["bytes-used"])

        with self.buf:
            data: dict = {}

            for k, v in spans.items():
                data[k] = {}
                for span in v.ranges:
                    tspan = tuple(span)

                    data[k][tspan] = bytearray(tspan[1] - tspan[0])

            for block in meta["blocks"]:
                family_id = block.get("family-id", "Generic")
                bspan: tuple | None = None
                for r in spans[family_id].ranges:
                    if int(block["address"][2:], 16) >= r[0]:
                        bspan = tuple(r)
                        break

                assert bspan is not None

                self.buf.seek(block["offset"] + 32)
                buf = data[family_id][bspan]
                base = int(block["address"][2:], 16) - bspan[0]
                for i in range(0, block["bytes-used"]):
                    buf[base + i] = self.buf.ru8()

        meta["ranges"] = {}
        for k, v in data.items():
            meta["ranges"][k] = {}

            for k2, v2 in v.items():
                meta["ranges"][k][f"0x{hex(k2[0])[2:].zfill(8)}-0x{hex(k2[1])[2:].zfill(8)}"] = chew(Buf(v2), blob_mode=True)

        return meta


@module.register
class DvdMpegSequenceModule(module.RuminantModule):
    dev = True
    desc = "DVD MPEG sequence files (the .VOB ones)."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.pu32() == 0x000001ba

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "mpeg-sequence"

        meta["packs"] = []
        while self.buf.pu32() == 0x000001ba:
            pack = {}

            self.buf.pasunit(2048)
            self.buf.skip(4)

            pack["pack-header-indicator"] = self.buf.rb(2)
            pack["scr"] = self.buf.rb(46)
            pack["mux-rate"] = self.buf.rb(22)
            pack["marker1"] = self.buf.rb(1)
            pack["marker2"] = self.buf.rb(1)
            pack["reserved"] = self.buf.rb(5)
            pack["stuffing-length"] = self.buf.rb(3)
            pack["stuffing"] = self.buf.rh(pack["stuffing-length"])

            i = pack["scr"]
            pack["scr"] = (((i >> 43) & 7) << 30 | ((i >> 27) & 0x7fff) << 15 | ((i >> 11) & 0x7fff)) * 300 + (
                (i >> 1) & 0x01ff
            )

            self.buf.sapunit()
            meta["packs"].append(pack)

        return meta


@module.register
class GrubModuleModule(module.RuminantModule):
    desc = "GRUB 2 module files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"mimg"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "grub-module"

        self.buf.skip(4)
        meta["data"] = {}
        meta["data"]["padding"] = self.buf.ru32l()
        meta["data"]["offset"] = self.buf.ru64l()
        meta["data"]["size"] = self.buf.ru64l()
        meta["data"]["modules"] = []

        self.buf.pasunit(meta["data"]["size"] - 24)
        self.buf.skip(meta["data"]["offset"] - 24)

        while self.buf.hasunit():
            module = {}
            module["type"] = utils.unraw(
                self.buf.ru32l(),
                4,
                {
                    0x00000000: "ELF",
                    0x00000001: "MEMDISK",
                    0x00000002: "CONFIG",
                    0x00000003: "PREFIX",
                    0x00000004: "PUBKEY",
                    0x00000005: "DTB",
                    0x00000006: "DISABLE_SHIM_LOCK",
                },
            )
            module["length"] = self.buf.ru32l()

            self.buf.pasunit(module["length"] - 8)

            match module["type"]["raw"]:
                case 0 | 1:
                    with self.buf.subunit():
                        module["data"] = chew(self.buf)
                case 3:
                    module["data"] = self.buf.rs(self.buf.unit)
                case _:
                    module["unknown"] = True
                    with self.buf.subunit():
                        module["data"] = chew(self.buf, blob_mode=True)

            self.buf.sapunit()

            meta["data"]["modules"].append(module)

        self.buf.sapunit()

        return meta


@module.register
class AndroidBackupModule(module.RuminantModule):
    desc = "Android Backup files produced by adb backup."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(15) == b"ANDROID BACKUP\n"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "android-backup"
        self.buf.skip(15)
        meta["version"] = int(self.buf.rl().decode("utf-8"))
        meta["compressed"] = int(self.buf.rl().decode("utf-8")) == 1
        meta["encryption"] = self.buf.rl().decode("utf-8")

        if meta["encryption"] == "AES-256":
            meta["encryption-parameters"] = {}
            meta["encryption-parameters"]["salt"] = bytes.fromhex(self.buf.rl().decode("utf-8")).hex()
            meta["encryption-parameters"]["checksum-salt"] = bytes.fromhex(self.buf.rl().decode("utf-8")).hex()
            meta["encryption-parameters"]["pbkdf2-rounds"] = int(self.buf.rl().decode("utf-8"))
            meta["encryption-parameters"]["iv"] = bytes.fromhex(self.buf.rl().decode("utf-8")).hex()
            meta["encryption-parameters"]["master-key"] = base64.b64decode(self.buf.rl()).hex()
        else:
            fd = utils.tempfd()
            d = zlib.decompressobj(wbits=15)

            offset = 0
            while True:
                try:
                    block = self.buf.read(1 << 24, free=True)
                    offset += len(block)
                    assert len(block) > 0
                except Exception:
                    break

                fd.write(d.decompress(block))

            self.buf.seek(offset - len(d.unused_data))

            fd.seek(0)
            meta["data"] = chew(fd)

        return meta


@module.register
class CabinetModule(module.RuminantModule):
    desc = "Microsoft cabinet files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"MSCF"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "cab"

        self.buf.skip(4)

        meta["header"] = {}
        meta["header"]["reserved1"] = self.buf.ru32l()
        meta["header"]["total-size"] = self.buf.ru32l()
        meta["header"]["reserved2"] = self.buf.ru32l()
        meta["header"]["cffile-offset"] = self.buf.ru32l()
        meta["header"]["reserved3"] = self.buf.ru32l()
        temp = self.buf.ru8()
        meta["header"]["version"] = f"{self.buf.ru8()}.{temp}"
        meta["header"]["folder-count"] = self.buf.ru16l()
        meta["header"]["file-count"] = self.buf.ru16l()
        meta["header"]["flags"] = utils.unpack_flags(
            self.buf.ru16l(),
            ((1, "PREV_CABINET"), (2, "NEXT_CABINET"), (3, "RESERVE_PRESENT")),
        )
        meta["header"]["set-id"] = self.buf.ru16l()
        meta["header"]["set-offset"] = self.buf.ru16l()

        meta["header"]["reserve-size"] = 0
        meta["header"]["folder-reserve-size"] = 0
        meta["header"]["data-reserve-size"] = 0
        if "RESERVE_PRESENT" in meta["header"]["flags"]["names"]:
            meta["header"]["reserve-size"] = self.buf.ru16l()
            meta["header"]["folder-reserve-size"] = self.buf.ru8()
            meta["header"]["data-reserve-size"] = self.buf.ru8()
            meta["header"]["reserved"] = self.buf.rh(meta["header"]["data-reserve-size"])

        if "PREV_CABINET" in meta["header"]["flags"]["names"]:
            meta["header"]["previous-cabinet"] = self.buf.rzs()
            meta["header"]["previous-disk"] = self.buf.rzs()

        if "NEXT_CABINET" in meta["header"]["flags"]["names"]:
            meta["header"]["next-cabinet"] = self.buf.rzs()
            meta["header"]["next-disk"] = self.buf.rzs()

        fds: list = []
        meta["folders"] = []
        for i in range(0, meta["header"]["folder-count"]):
            folder: dict = {}
            folder["data-offset"] = self.buf.ru32l()
            folder["data-count"] = self.buf.ru16l()
            folder["compression"] = utils.unraw(
                self.buf.ru16l(),
                2,
                {0x0000: "None", 0x0001: "MSZIP", 0x0002: "Quantum", 0x0003: "LZX"},
                True,
            )

            if "RESERVE_PRESENT" in meta["header"]["flags"]["names"]:
                folder["reserve"] = self.buf.rh(meta["header"]["folder-reserve-size"])

            folder["compressed-size"] = 0
            folder["uncompressed-size"] = 0
            folder["data-segments"] = []
            with self.buf:
                self.buf.seek(folder["data-offset"])

                fd = utils.tempfd()
                for j in range(folder["data-count"]):
                    segment = {}
                    segment["checksum"] = self.buf.ru32l()
                    segment["compressed-size"] = self.buf.ru16l()
                    segment["uncompressed-size"] = self.buf.ru16l()

                    folder["compressed-size"] += segment["compressed-size"]
                    folder["uncompressed-size"] += segment["uncompressed-size"]

                    if "RESERVE_PRESENT" in meta["header"]["flags"]["names"]:
                        segment["reserve"] = self.buf.rh(meta["header"]["data-reserve-size"])

                    fd.write(self.buf.read(segment["compressed-size"]))

                    folder["data-segments"].append(segment)

                fd = Buf(fd)
                try:
                    match folder["compression"]:
                        case "MSZIP":
                            fd.seek(0)
                            fd2 = utils.tempfd()

                            while fd.available() > 0:
                                assert fd.read(2) == b"CK", "invalid MSZIP chunk padding"
                                utils.stream_deflate(fd, fd2, fd.available(), revert=True)

                            fd.close()
                            fd = Buf(fd2)
                        case _:
                            raise ValueError()
                except (AssertionError, ValueError):
                    folder["unknown"] = True
                    fd = None

                if fd:
                    fd.seek(0)
                    with fd:
                        folder["data"] = chew(fd, blob_mode=True)

                fds.append(fd)

            meta["folders"].append(folder)

        self.buf.seek(meta["header"]["cffile-offset"])
        meta["files"] = []
        for i in range(0, meta["header"]["file-count"]):
            file: dict = {}
            file["uncompressed-size"] = self.buf.ru32l()
            file["uncompressed-folder-offset"] = self.buf.ru32l()
            file["folder-index"] = self.buf.ru16l()
            date = self.buf.ru16l()
            tme = self.buf.ru16l()
            file["date"] = datetime.datetime(
                (date >> 9) + 1980,
                (date >> 5) & 0x0f,
                date & 0x1f,
                tme >> 11,
                (tme >> 5) & 0x3f,
                (tme & 0x0f) << 1,
            ).isoformat()
            file["attribs"] = utils.unpack_flags(
                self.buf.ru16l(),
                (
                    (1, "read-only"),
                    (2, "hidden"),
                    (3, "system"),
                    (6, "archive"),
                    (7, "executable"),
                    (8, "UTF name"),
                ),
            )
            if "UTF name" in file["attribs"]["names"]:
                name = b""
                while self.buf.pu16l():
                    name += self.buf.read(2)

                self.buf.skip(2)

                file["name"] = name.decode("utf-16le")
            else:
                file["name"] = self.buf.rzs()

            fd = fds[file["folder-index"]]
            if fd:
                fd.seek(file["uncompressed-folder-offset"])

                with fd.sub(file["uncompressed-size"]):
                    file["data"] = chew(fd)

            meta["files"].append(file)

        for fd in fds:
            if fd:
                fd.close()

        self.buf.seek(meta["header"]["total-size"])

        return meta


@module.register
class IwaModule(module.RuminantModule):
    desc = "IWA files."
    priority = 2

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if ctx["walk"]:
            return False

        with buf:
            if buf.available() < 4:
                return False

            while True:
                if buf.available() == 0:
                    return True

                if buf.available() < 4:
                    return False

                if buf.ru8() not in (0x00, 0x01, 0xfe):
                    return False

                length = buf.ru24l()
                if length == 0:
                    return False

                if buf.available() < length:
                    return False

                buf.skip(length)

    def clean(self, obj):
        match obj.__class__.__name__:
            case "dict":
                for k, v in obj.items():
                    obj[k] = self.clean(v)

                return obj
            case "list":
                for i in range(0, len(obj)):
                    obj[i] = self.clean(obj[i])

                return obj
            case "bytes":
                try:
                    return self.clean(utils.read_protobuf(Buf(obj), len(obj)))
                except Exception:
                    return obj.hex()
            case _:
                return obj

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "iwa"

        data = []
        while self.buf.available() > 0:
            temp = self.buf.read(1)
            data.append(temp + self.buf.read(self.buf.ru24l()))

        bufs = []
        for blob in data:
            match blob[0]:
                case 0x00:
                    bufs.append(utils.unpack_snappy(blob[1:]))
                case 0x01:
                    bufs.append(blob[1:])
                case 0xfe:
                    pass
                case _:
                    raise NotImplementedError()

        meta["data"] = []

        for buf in bufs:
            buf = Buf(buf)
            protobuf = utils.read_protobuf(buf, buf.ruleb(), decode=constants.IWORK_PROTO)

            with buf.sub(buf.available()):
                content = chew(buf)

            meta["data"].append({"protobuf": protobuf, "content": content})

        self.clean(meta["data"])

        return meta


@module.register
class PcapNgModule(module.RuminantModule):
    desc = "pcapng files as produced by Wireshark."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"\x0a\x0d\x0d\x0a"

    def register_detectors(self):
        self.detectors = {}

        def register(protocol, ports):
            def inner(f):
                if protocol not in self.detectors:
                    self.detectors[protocol] = []

                self.detectors[protocol].append({"ports": ports, "func": f})

                return f

            return inner

        def dns_read_name(base, unit):
            length = self.buf.ru8()
            if length == 0:
                return None

            if length & 0xc0 == 0xc0:
                length = ((length & 0x3f) << 8) + self.buf.ru8()
                with self.buf:
                    self.buf.seek(base)
                    self.buf.setunit(unit)

                    self.buf.skip(length)

                    return dns_read_name(base, unit)
            else:
                this_part = self.buf.rs(length)
                next_part = dns_read_name(base, unit)

                if next_part is not None:
                    this_part = this_part + "." + next_part

                return this_part

        @register("udp", [53])
        def decode_dns():
            base, length = self.buf.tell(), self.buf.unit

            packet = {}
            packet["type"] = "DNS"
            packet["transaction-id"] = self.buf.ru16()
            packet["direction"] = ["question", "reply"][self.buf.rb(1)]
            packet["opcode"] = utils.unraw(self.buf.rb(4), 1, {0x00: "QUERY", 0x01: "IQUERY", 0x02: "STATUS"}, True)
            packet["authoriative-answer"] = bool(self.buf.rb(1))
            packet["truncation"] = bool(self.buf.rb(1))
            packet["recursion-desired"] = bool(self.buf.rb(1))
            packet["recursion-available"] = bool(self.buf.rb(1))
            packet["zero"] = self.buf.rb(1)
            packet["authentic-data"] = bool(self.buf.rb(1))
            packet["checking-disabled"] = bool(self.buf.rb(1))
            packet["rcode"] = utils.unraw(
                self.buf.rb(4),
                1,
                {
                    0x00: "NoError",
                    0x01: "FormErr",
                    0x02: "ServFail",
                    0x03: "NXDomain",
                    0x04: "NotImp",
                    0x05: "Refused",
                    0x06: "YXDomain",
                    0x07: "YXRRSet",
                    0x08: "NXRRSet",
                    0x09: "NotAuth",
                    0x0a: "NotZone",
                    0x0b: "DSOTYPENI",
                },
                True,
            )
            packet["question-count"] = self.buf.ru16()
            packet["answer-count"] = self.buf.ru16()
            packet["authority-rr-count"] = self.buf.ru16()
            packet["additional-rr-count"] = self.buf.ru16()

            packet["questions"] = []
            for i in range(0, packet["question-count"]):
                record = {}
                record["name"] = dns_read_name(base, length)

                record["type"] = utils.unraw(self.buf.ru16(), 2, constants.DNS_RECORD_TYPES, True)
                record["class"] = utils.unraw(
                    self.buf.ru16(),
                    2,
                    {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                    True,
                )
                packet["questions"].append(record)

            packet["answers"] = []
            packet["authority-rrs"] = []
            packet["additional-rrs"] = []
            for i in range(0, 3):
                for j in range(
                    0,
                    [
                        packet["answer-count"],
                        packet["authority-rr-count"],
                        packet["additional-rr-count"],
                    ][i],
                ):
                    record = {}
                    record["name"] = dns_read_name(base, length)

                    record["type"] = utils.unraw(self.buf.ru16(), 2, constants.DNS_RECORD_TYPES, True)

                    match record["type"]:
                        case "A":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["ip"] = ".".join([str(self.buf.ru8()) for k in range(0, 4)])

                            self.buf.sapunit()
                        case "OPT":
                            record["udp-payload-size"] = self.buf.ru16()
                            record["extended-rcode"] = self.buf.ru8()
                            record["edns0-version"] = self.buf.ru8()
                            record["flags"] = utils.unpack_flags(self.buf.ru16(), ((15, "DO"),))

                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["options"] = []
                            while self.buf.hasunit():
                                opt = {}
                                opt["code"] = utils.unraw(
                                    self.buf.ru16(),
                                    2,
                                    {0x000a: "COOKIE", 0x000f: "Extended DNS Error"},
                                    True,
                                )
                                opt["length"] = self.buf.ru16()
                                opt["data"] = {}

                                self.buf.pasunit(opt["length"])

                                match opt["code"]:
                                    case "COOKIE":
                                        opt["data"]["cookie"] = self.buf.rh(self.buf.unit)
                                    case "Extended DNS Error":
                                        opt["data"]["info-code"] = utils.unraw(
                                            self.buf.ru16(),
                                            2,
                                            {
                                                0x0000: "Other Error",
                                                0x0001: "Unsupported DNSKEY Algorithm",
                                                0x0002: "Unsupported DS Digest Type",
                                                0x0003: "Stale Answer",
                                                0x0004: "Forged Answer",
                                                0x0005: "Indeterminate",
                                                0x0006: "DNSSEC Bogus",
                                                0x0007: "Signature Expired",
                                                0x0008: "Signature Not Yet Valid",
                                                0x0009: "DNSKEY Missing",
                                                0x000a: "RRSIGs Missing",
                                                0x000b: "No Zone Key Bit Set",
                                                0x000c: "NSEC Missing",
                                                0x000d: "Cached Error",
                                                0x000e: "Not Ready",
                                                0x000f: "Blocked",
                                                0x0010: "Censored",
                                                0x0011: "Filtered",
                                                0x0012: "Prohibited",
                                                0x0013: "Stale NXDOMAIN Answer",
                                                0x0014: "Not Authoritative",
                                                0x0015: "Not Supported",
                                                0x0016: "No Reachable Authority",
                                                0x0017: "Network Error",
                                                0x0018: "Invalid Data",
                                                0x0019: "Signature Expired Before Valid",
                                                0x001a: "Too Early",
                                                0x001b: "Unsupported NSEC3 Iterations",
                                            },
                                            True,
                                        )
                                        opt["data"]["extra-text"] = self.buf.rs(self.buf.unit)
                                    case _:
                                        opt["data"]["payload"] = self.buf.rh(self.buf.unit)

                                self.buf.sapunit()

                                record["rdata"]["options"].append(opt)

                            self.buf.sapunit()
                        case "SOA":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["mname"] = dns_read_name(base, length)
                            record["rdata"]["rname"] = dns_read_name(base, length)
                            record["rdata"]["serial"] = self.buf.ru32()
                            record["rdata"]["retry"] = self.buf.ru32()
                            record["rdata"]["expire"] = self.buf.ru32()
                            record["rdata"]["minimum"] = self.buf.ru32()

                            self.buf.sapunit()
                        case "AAAA":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["address"] = ipaddress.IPv6Address(self.buf.read(16)).compressed

                            self.buf.sapunit()
                        case "MX":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["preference"] = self.buf.ru16()
                            record["rdata"]["exchange"] = dns_read_name(base, length)

                            self.buf.sapunit()
                        case "TXT":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["content"] = self.buf.rs(self.buf.ru8())

                            self.buf.sapunit()
                        case "CAA":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["flags"] = utils.unpack_flags(self.buf.ru8(), ((0, "issuer-critical"),))
                            record["rdata"]["tag"] = self.buf.rs(self.buf.ru8())
                            record["rdata"]["value"] = self.buf.rs(self.buf.unit)

                            self.buf.sapunit()
                        case "DNSKEY":
                            # https://datatracker.ietf.org/doc/html/rfc4034
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            key_tag = 0
                            with self.buf:
                                for j in range(0, self.buf.unit):
                                    key_tag += self.buf.ru8() if j % 2 else self.buf.ru8() << 8

                                key_tag = ((key_tag & 0xffff) + (key_tag >> 16)) & 0xffff

                            record["rdata"] = {}
                            temp = self.buf.ru16()
                            record["rdata"]["flags"] = utils.unpack_flags(
                                temp,
                                (
                                    (0, "key-signing-key"),
                                    (7, "zone-key"),
                                    (15, "secure-entry-point"),
                                ),
                            )
                            if "key-signing-key" in record["rdata"]["flags"]["names"]:
                                record["rdata"]["flags"]["key-signing-key"] = temp & 0b1111111001111110

                            record["rdata"]["protocol"] = self.buf.ru8()
                            match record["rdata"]["protocol"]:
                                case 3:
                                    record["rdata"]["algorithm"] = utils.unraw(
                                        self.buf.ru8(),
                                        1,
                                        constants.DNSSEC_ALGORITHMS,
                                        True,
                                    )
                                    record["rdata"]["key-tag"] = key_tag
                                    record["rdata"]["key"] = self.buf.rh(self.buf.unit)
                                case _:
                                    record["rdata"]["rest"] = self.buf.rh(self.buf.unit)
                                    record["unknown"] = True

                            self.buf.sapunit()
                        case "RRSIG":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["type-covered"] = utils.unraw(self.buf.ru16(), 2, constants.DNS_RECORD_TYPES, True)
                            record["rdata"]["algorithm"] = utils.unraw(self.buf.ru8(), 1, constants.DNSSEC_ALGORITHMS, True)
                            record["rdata"]["labels"] = self.buf.ru8()
                            record["rdata"]["original-ttl"] = self.buf.ru32()
                            record["rdata"]["signature-expiration"] = utils.unix_to_date(self.buf.ru32())
                            record["rdata"]["signature-inception"] = utils.unix_to_date(self.buf.ru32())
                            record["rdata"]["key-tag"] = self.buf.ru16()
                            record["rdata"]["signers-name"] = dns_read_name(base, length)
                            record["rdata"]["signature"] = self.buf.rh(self.buf.unit)

                            self.buf.sapunit()
                        case "HTTPS":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["priority"] = self.buf.ru16()
                            record["rdata"]["target-name"] = dns_read_name(base, length)

                            record["rdata"]["params"] = []
                            while self.buf.hasunit():
                                param = {}
                                param["key"] = utils.unraw(
                                    self.buf.ru16(),
                                    2,
                                    {
                                        0x0000: "mandatory",
                                        0x0001: "alpn",
                                        0x0002: "no-default-alpn",
                                        0x0003: "port",
                                        0x0004: "ipv4hint",
                                        0x0005: "ech",
                                        0x0006: "ipv6hint",
                                    },
                                    True,
                                )
                                param["length"] = self.buf.ru16()

                                self.buf.pasunit(param["length"])

                                match param["key"]:
                                    case "alpn":
                                        param["value"] = []
                                        while self.buf.hasunit():
                                            param["value"].append(self.buf.rs(self.buf.ru8()))
                                    case _:
                                        param["value"] = self.buf.rh(param["length"])
                                        param["unknown"] = True

                                self.buf.sapunit()

                                record["rdata"]["params"].append(param)

                            self.buf.sapunit()
                        case "NS":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["nsdname"] = dns_read_name(base, length)

                            self.buf.sapunit()
                        case "SSHFP":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["algorithm"] = utils.unraw(
                                self.buf.ru8(),
                                1,
                                {0x00: "reserved", 0x01: "RSA", 0x02: "DSS"},
                                True,
                            )
                            record["rdata"]["fingerprint-type"] = utils.unraw(
                                self.buf.ru8(),
                                1,
                                {0x00: "reserved", 0x01: "SHA-1"},
                                True,
                            )
                            record["rdata"]["fingerprint"] = self.buf.rh(self.buf.unit)

                            self.buf.sapunit()
                        case "OPENPGPKEY":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            with self.buf.subunit():
                                record["rdata"]["key"] = chew(self.buf)

                            self.buf.sapunit()
                        case "SRV":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["priority"] = self.buf.ru16()
                            record["rdata"]["weight"] = self.buf.ru16()
                            record["rdata"]["port"] = self.buf.ru16()
                            record["rdata"]["target"] = dns_read_name(base, length)

                            self.buf.sapunit()
                        case "DS":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["key-tag"] = self.buf.ru16()
                            record["rdata"]["algorithm"] = utils.unraw(self.buf.ru8(), 1, constants.DNSSEC_ALGORITHMS, True)
                            record["rdata"]["digest-type"] = utils.unraw(self.buf.ru8(), 1, constants.DNSSEC_DIGESTS, True)
                            record["rdata"]["digest"] = self.buf.rh(self.buf.unit)

                            self.buf.sapunit()
                        case "NSEC3":
                            record["class"] = utils.unraw(
                                self.buf.ru16(),
                                2,
                                {0x0001: "Internet", 0x00fe: "NONE", 0x00ff: "ANY"},
                                True,
                            )
                            record["ttl"] = self.buf.ru32()
                            record["rdata-length"] = self.buf.ru16()

                            self.buf.pasunit(record["rdata-length"])

                            record["rdata"] = {}
                            record["rdata"]["hash-algorithm"] = utils.unraw(self.buf.ru8(), 1, constants.DNSSEC_DIGESTS, True)
                            record["rdata"]["flags"] = utils.unpack_flags(self.buf.ru8(), ((0, "opt-out"),))
                            record["rdata"]["iterations"] = self.buf.ru16()
                            record["rdata"]["salt-length"] = self.buf.ru8()
                            record["rdata"]["salt"] = self.buf.rh(record["rdata"]["salt-length"])
                            record["rdata"]["hash-length"] = self.buf.ru8()
                            record["rdata"]["next-hashed-owner-name"] = self.buf.rh(record["rdata"]["hash-length"])

                            record["rdata"]["type-bitmaps"] = []
                            while self.buf.hasunit():
                                bitmap = {}
                                bitmap["window"] = self.buf.ru8()
                                bitmap["bitmap-length"] = self.buf.ru8()
                                bitmap["bitmap"] = self.buf.rh(bitmap["bitmap-length"])

                                record["rdata"]["type-bitmaps"].append(bitmap)

                            record["rdata"]["types"] = []
                            for entry in record["rdata"]["type-bitmaps"]:
                                bits = int(
                                    entry["bitmap"] + "00" * (32 - entry["bitmap-length"]),
                                    16,
                                )

                                for offset in range(0, 256):
                                    if bits & (1 << (255 - offset)):
                                        record["rdata"]["types"].append(
                                            utils.unraw(
                                                (entry["window"] << 8) | offset,
                                                2,
                                                constants.DNS_RECORD_TYPES,
                                                True,
                                            )
                                        )

                            self.buf.sapunit()
                        case _:
                            record["header"] = self.buf.rh(6)
                            record["rdata-length"] = self.buf.ru16()
                            record["rdata"] = self.buf.rh(record["rdata-length"])
                            record["unknown"] = True

                    packet[["answers", "authority-rrs", "additional-rrs"][i]].append(record)

            return packet

    def read_options(self, ctx):
        if self.buf.unit <= 4:
            return []

        opts = []
        while True:
            if self.buf.pu32() == 0:
                self.buf.skip(4)
                return opts

            opt = {}
            opt["type"] = utils.unraw(
                self.buf.ru16l() if self.little else self.buf.ru16(),
                2,
                {
                    "Section Header": {
                        0x0002: "Hardware",
                        0x0003: "OS",
                        0x0004: "User application",
                    },
                    "Interface Description": {
                        0x0002: "Interface",
                        0x0003: "Description",
                        0x0009: "Timestamp resolution",
                        0x000b: "Filter",
                        0x000c: "OS",
                    },
                    "Interface Statistics": {
                        0x0001: "Writer",
                        0x0002: "Start time",
                        0x0003: "End time",
                        0x0004: "Interface received",
                        0x0005: "Interface dropped",
                    },
                }.get(ctx, {}),
                True,
            )
            opt["length"] = self.buf.ru16l() if self.little else self.buf.ru16()

            self.buf.pasunit(opt["length"])

            match ctx, opt["type"]:
                case (
                    ("Section Header", "Hardware" | "OS" | "User application")
                    | (
                        "Interface Description",
                        "Interface" | "Description" | "OS",
                    )
                    | ("Interface Statistics", "Writer")
                ):
                    opt["data"] = self.buf.rs(self.buf.unit)
                case "Interface Description", "Timestamp resolution":
                    temp = self.buf.ru8()
                    opt["data"] = {
                        "base": 2 if temp & 0x80 else 10,
                        "exponent": -(temp & 0x7f),
                        "value": (2 if temp & 0x80 else 10) ** -(temp & 0x7f),
                    }
                case "Interface Description", "Filter":
                    opt["data"] = {
                        "code": self.buf.ru8(),
                        "filter": self.buf.rs(self.buf.unit),
                    }
                case (
                    "Interface Statistics",
                    "Start time" | "End time" | "Interface received" | "Interface dropped",
                ):
                    opt["data"] = self.buf.ru32l() if self.little else self.buf.ru32()
                case _:
                    opt["data"] = self.buf.rh(self.buf.unit)
                    opt["unknown"] = True

            self.buf.sapunit()
            if self.buf.tell() % 4 != 0:
                self.buf.skip(4 - self.buf.tell() % 4)

            opts.append(opt)

    def read_ipv4(self):
        packet = {}
        packet["version"] = self.buf.rb(4)
        packet["header-length"] = self.buf.rb(4) * 4
        self.buf.pasunit(packet["header-length"] - 1)

        packet["dscp"] = self.buf.rb(6)
        packet["ecn"] = self.buf.rb(2)
        packet["total-length"] = self.buf.ru16()
        packet["identification"] = self.buf.ru16()
        packet["reserved"] = self.buf.rb(1)
        packet["dont-fragment"] = bool(self.buf.rb(1))
        packet["more-fragments"] = bool(self.buf.rb(1))
        packet["fragment-offset"] = self.buf.rb(13)
        packet["ttl"] = self.buf.ru8()
        protocol = self.buf.ru8()
        packet["protocol"] = utils.unraw(
            protocol,
            1,
            {
                0x01: "ICMP",
                0x02: "IGMP",
                0x06: "TCP",
                0x11: "UDP",
                0x29: "ENCAP",
                0x59: "OSPF",
                0x84: "SCTP",
            },
            True,
        )
        packet["checksum"] = self.buf.ru16()
        packet["source-address"] = ".".join([str(self.buf.ru8()) for i in range(0, 4)])
        packet["destination-address"] = ".".join([str(self.buf.ru8()) for i in range(0, 4)])
        packet["options"] = self.buf.rh(self.buf.unit)

        self.buf.sapunit()

        self.buf.pasunit(packet["total-length"] - packet["header-length"])

        if packet["more-fragments"] or packet["fragment-offset"] != 0:
            packet["raw-payload"] = self.buf.rh(self.buf.unit)
            packet["reassembled-in"] = None

            identifier = (
                "IPv4 "
                + packet["source-address"]
                + " "
                + packet["destination-address"]
                + " "
                + packet["protocol"]
                + " "
                + str(packet["identification"])
            )

            if identifier not in self.reassemble:
                self.reassemble[identifier] = []

            self.reassemble[identifier].append({
                "packet": packet,
                "payload": bytes.fromhex(packet["raw-payload"]),
                "offset": packet["fragment-offset"] * 8,
                "length": packet["total-length"] - packet["header-length"],
                "final": not packet["more-fragments"],
                "id": self.id - 1,
                "protocol": protocol,
            })

            self.try_reassemble(identifier)
        else:
            match packet["protocol"]:
                case "UDP":
                    packet["payload"] = self.read_udp()
                case "TCP":
                    packet["payload"] = self.read_tcp()
                case "ICMP":
                    packet["payload"] = self.read_icmp()
                case "IGMP":
                    packet["payload"] = self.read_igmp()
                case _:
                    packet["raw-payload"] = self.buf.rh(self.buf.unit)
                    packet["unknown"] = True

        self.buf.sapunit()

        return packet

    def read_udp(self):
        packet = {}
        packet["source-port"] = self.buf.ru16()
        packet["destination-port"] = self.buf.ru16()
        packet["length"] = self.buf.ru16()

        self.buf.pasunit(packet["length"] - 6)

        packet["checksum"] = self.buf.ru16()

        detectors = []
        for detector in self.detectors["udp"]:
            if packet["destination-port"] in detector["ports"]:
                detectors.insert(0, detector["func"])
            else:
                detectors.append(detector["func"])

        found = False
        for func in detectors:
            backup = self.buf.backup()

            try:
                packet["payload"] = func()
                assert self.buf.unit == 0
                found = True
                break
            except Exception:
                self.buf.restore(backup)

        if not found:
            packet["payload"] = self.buf.rh(self.buf.unit)

        self.buf.sapunit()

        return packet

    def read_tcp(self):
        packet = {}
        packet["source-port"] = self.buf.ru16()
        packet["destination-port"] = self.buf.ru16()
        packet["sequence-number"] = self.buf.ru32()
        packet["acknowledgement-number"] = self.buf.ru32()
        packet["data-offset"] = self.buf.rb(4)
        packet["reserved"] = self.buf.rb(4)

        self.buf.pasunit(packet["data-offset"] * 4 - 13)

        packet["flags"] = utils.unpack_flags(
            self.buf.rb(8),
            (
                (0, "fin"),
                (1, "syn"),
                (2, "rst"),
                (3, "psh"),
                (4, "ack"),
                (5, "urg"),
                (6, "ece"),
                (7, "cwr"),
            ),
        )

        packet["window"] = self.buf.ru16()
        packet["checksum"] = self.buf.ru16()
        packet["urgent-pointer"] = self.buf.ru16()

        packet["options"] = []
        while self.buf.hasunit():
            opt = {}
            opt["type"] = utils.unraw(
                self.buf.ru8(),
                1,
                {
                    0x00: "End of list",
                    0x01: "No operation",
                    0x02: "Maximum segment size",
                    0x03: "Window scale",
                    0x04: "Selective Acknowledgement permitted",
                    0x05: "Selective ACKnowledgement (SACK)",
                    0x08: "Timestamp and echo of previous timestamp",
                },
                True,
            )

            match opt["type"]:
                case "No operation" | "End of list":
                    pass
                case "Maximum segment size":
                    self.buf.skip(1)
                    opt["segment-size"] = self.buf.ru16()
                case "Window scale":
                    self.buf.skip(1)
                    opt["window-scale"] = self.buf.ru8()
                case "Selective Acknowledgement permitted":
                    self.buf.skip(1)
                case "Selective ACKnowledgement (SACK)":
                    opt["ranges"] = [
                        {"start": self.buf.ru32(), "end": self.buf.ru32()} for i in range(0, (self.buf.ru8() - 2) // 8)
                    ]
                case "Timestamp and echo of previous timestamp":
                    self.buf.skip(1)
                    opt["tsval"] = self.buf.ru32()
                    opt["tsecr"] = self.buf.ru32()
                case _:
                    self.buf.skip(self.buf.unit)

            packet["options"].append(opt)

        self.buf.sapunit()

        packet["payload"] = self.buf.rh(self.buf.unit)

        return packet

    def read_icmp(self):
        packet = {}
        packet["type"] = utils.unraw(
            self.buf.ru8(),
            1,
            {0x00: "Echo Reply", 0x03: "Destination Unreachable", 0x08: "Echo Request"},
            True,
        )
        packet["code"] = utils.unraw(
            self.buf.ru8(),
            1,
            {
                "Echo Request": {0x00: "Echo Request"},
                "Destination Unreachable": {
                    0x00: "Destination network unreachable",
                    0x01: "Destination host unreachable",
                    0x02: "Destination protocol unreachable",
                    0x03: "Destination port unreachable",
                    0x04: "Fragmentation required, and DF flag set",
                    0x05: "Source route failed",
                    0x06: "Destination network unknown",
                    0x07: "Destination host unknown",
                    0x08: "Source host isolated",
                    0x09: "Network administratively prohibited",
                    0x0a: "Host administratively prohibited",
                    0x0b: "Network unreachable for ToS",
                    0x0c: "Host unreachable for ToS",
                    0x0d: "Communication administratively prohibited",
                    0x0e: "Host Precedence Violation",
                    0x0f: "Precedence cutoff in effect",
                },
                "Echo Reply": {0x00: "Echo Reply"},
            }.get(packet["type"], {}),
            True,
        )
        packet["checksum"] = self.buf.ru16()

        match packet["type"], packet["code"]:
            case ("Echo Request", "Echo Request") | ("Echo Reply", "Echo Reply"):
                packet["identifier"] = self.buf.ru16()
                packet["sequence-number"] = self.buf.ru16()
                packet["payload"] = self.buf.rh(self.buf.unit)
            case "Destination Unreachable", _:
                packet["unused"] = self.buf.ru8()
                packet["length"] = self.buf.ru8()
                packet["next-hop-mtu"] = self.buf.ru16()
                packet["ip-header"] = self.buf.rh(self.buf.unit)
            case _, _:
                packet["rest"] = self.buf.ru32()
                packet["payload"] = self.buf.rh(self.buf.unit)
                packet["unknown"] = True

        return packet

    def read_ipv6(self):
        packet = {}
        packet["version"] = self.buf.rb(4)
        packet["traffic-class"] = self.buf.rb(8)
        packet["flow-label"] = self.buf.rb(20)
        packet["payload-length"] = self.buf.ru16()

        self.buf.pasunit(packet["payload-length"] - 6 + 40)

        packet["next-header"] = self.buf.ru8()
        packet["hop-limit"] = self.buf.ru8()
        packet["source-address"] = ipaddress.IPv6Address(self.buf.read(16)).compressed
        packet["destination-address"] = ipaddress.IPv6Address(self.buf.read(16)).compressed

        next_type = packet["next-header"]
        packet["headers"] = []
        should_break = False
        while not should_break:
            hdr = {}
            hdr["type"] = utils.unraw(
                next_type,
                1,
                {
                    0x00: "Hop-by-Hop",
                    0x01: "ICMP",
                    0x02: "IGMP",
                    0x06: "TCP",
                    0x11: "UDP",
                    0x29: "ENCAP",
                    0x3a: "ICMPv6",
                    0x59: "OSPF",
                    0x84: "SCTP",
                },
                True,
            )

            match hdr["type"]:
                case "ICMPv6":
                    hdr["payload"] = self.read_icmpv6()
                    should_break = True
                case "UDP":
                    hdr["payload"] = self.read_udp()
                    should_break = True
                case "TCP":
                    hdr["payload"] = self.read_tcp()
                    should_break = True
                case "ICMP":
                    hdr["payload"] = self.read_icmp()
                    should_break = True
                case "Hop-by-Hop":
                    next_type = self.buf.ru8()
                    hdr["next-header"] = next_type
                    hdr["length"] = self.buf.ru8()
                    self.buf.pasunit(hdr["length"] * 8 + 6)

                    hdr["options"] = []
                    while self.buf.hasunit():
                        opt = {}
                        typ = self.buf.ru8()
                        opt["type"] = {
                            "name": utils.unraw(
                                typ & 0x1f,
                                1,
                                {0x00: "Pad1", 0x01: "PadN", 0x05: "Router Alert"},
                                True,
                            ),
                            "action": [
                                "skip",
                                "discard",
                                "discard-icmp",
                                "discard-icmp-multicast",
                            ][typ >> 6],
                            "may-change": bool(typ & 0x20),
                        }

                        if typ & 0x1f != 0:
                            opt["length"] = self.buf.ru8()

                            self.buf.pasunit(opt["length"])

                            match opt["type"]["name"]:
                                case "Router Alert":
                                    opt["protocol"] = utils.unraw(
                                        self.buf.ru16(),
                                        2,
                                        {
                                            0x00: "MLD",
                                            0x01: "RSVP",
                                            0x02: "Active Networks",
                                        },
                                        True,
                                    )
                                case "PadN":
                                    pass
                                case _:
                                    opt["payload"] = self.buf.rh(self.buf.unit)
                                    opt["unknown"] = True

                            self.buf.sapunit()

                        hdr["options"].append(opt)

                    self.buf.sapunit()
                case _:
                    hdr["unknown"] = True
                    should_break = True

            packet["headers"].append(hdr)

        self.buf.sapunit()

        return packet

    def read_icmpv6(self):
        packet = {}
        packet["type"] = utils.unraw(
            self.buf.ru8(),
            1,
            {
                0x01: "Destination unreachable",
                0x80: "Echo Request",
                0x81: "Echo Reply",
                0x85: "Router Solicitation",
                0x86: "Router Advertisement",
                0x87: "Neighbor Solicitation",
                0x88: "Neighbor Advertisement",
                0x8f: "Multicast Listener Reports v2",
            },
            True,
        )
        packet["code"] = utils.unraw(
            self.buf.ru8(),
            1,
            {
                "Destination unreachable": {0x01: "Host unreachable error"},
                "Echo Request": {0x00: "Echo Request"},
                "Echo Reply": {0x00: "Echo Reply"},
                "Router Solicitation": {0x00: "Router Solicitation"},
                "Router Advertisement": {0x00: "Router Advertisement"},
                "Neighbor Solicitation": {0x00: "Neighbor Solicitation"},
                "Neighbor Advertisement": {0x00: "Neighbor Advertisement"},
                "Multicast Listener Reports v2": {0x00: "Multicast Listener Reports v2"},
            }.get(packet["type"], {}),
            True,
        )
        packet["checksum"] = self.buf.ru16()

        match packet["type"], packet["code"]:
            case ("Echo Request", "Echo Request") | ("Echo Reply", "Echo Reply"):
                packet["identifier"] = self.buf.ru16()
                packet["sequence-number"] = self.buf.ru16()
                packet["payload"] = self.buf.rh(self.buf.unit)
            case "Neighbor Solicitation", "Neighbor Solicitation":
                packet["reserved"] = self.buf.ru32()
                packet["target-address"] = ipaddress.IPv6Address(self.buf.read(16)).compressed
            case "Neighbor Advertisement", "Neighbor Advertisement":
                packet["router"] = bool(self.buf.rb(1))
                packet["solicited"] = bool(self.buf.rb(1))
                packet["override"] = bool(self.buf.rb(1))
                packet["reserved"] = self.buf.rb(29)
                packet["target-address"] = ipaddress.IPv6Address(self.buf.read(16)).compressed
            case "Router Advertisement", "Router Advertisement":
                packet["hop-limit"] = self.buf.ru8()
                packet["managed-address-configuration"] = bool(self.buf.rb(1))
                packet["other-configuration"] = bool(self.buf.rb(1))
                packet["reserved"] = self.buf.rb(6)
                packet["router-lifetime"] = self.buf.ru16()
                packet["reachable-time"] = self.buf.ru32()
                packet["retrans-time"] = self.buf.ru32()
            case "Multicast Listener Reports v2", "Multicast Listener Reports v2":
                packet["extension"] = bool(self.buf.rb(1))
                packet["reserved"] = self.buf.rb(15)
                packet["multicast-address-count"] = self.buf.ru16()

                packet["multicast-addresses"] = []
                for i in range(0, packet["multicast-address-count"]):
                    mcast = {}
                    mcast["type"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {
                            0x01: "MODE_IS_INCLUDE",
                            0x02: "MODE_IS_EXCLUDE",
                            0x03: "CHANGE_TO_INCLUDE_MODE",
                            0x04: "CHANGE_TO_EXCLUDE_MODE",
                        },
                        True,
                    )
                    mcast["auxiliar-data-length"] = self.buf.ru8()
                    mcast["source-count"] = self.buf.ru16()
                    mcast["multicast-address"] = ipaddress.IPv6Address(self.buf.read(16)).compressed
                    mcast["sources"] = [
                        ipaddress.IPv6Address(self.buf.read(16)).compressed for j in range(0, mcast["source-count"])
                    ]
                    mcast["auxiliar-data"] = self.buf.rh(mcast["auxiliar-data-length"])

                    packet["multicast-addresses"].append(mcast)
            case "Destination unreachable", _:
                packet["unused"] = self.buf.ru8()
                packet["length"] = self.buf.ru8()
                packet["next-hop-mtu"] = self.buf.ru16()
                packet["ip-header"] = self.buf.rh(self.buf.unit)
            case "Router Solicitation", "Router Solicitation":
                packet["reserved"] = self.buf.ru32()
            case _, _:
                packet["payload"] = self.buf.rh(self.buf.unit)
                packet["unknown"] = True

        if (packet["type"], packet["code"]) in (
            ("Neighbor Solicitation", "Neighbor Solicitation"),
            ("Neighbor Advertisement", "Neighbor Advertisement"),
            ("Router Advertisement", "Router Advertisement"),
            ("Router Solicitation", "Router Solicitation"),
        ):
            packet["options"] = []

            while self.buf.hasunit():
                opt = {}
                opt["type"] = utils.unraw(
                    self.buf.ru8(),
                    1,
                    {
                        0x01: "Source Link-Layer Address",
                        0x02: "Target Link-Layer Address",
                        0x03: "Prefix Information",
                        0x04: "Redirected Header",
                        0x05: "MTU",
                        0x07: "Advertisement Interval",
                        0x0e: "Nonce",
                        0x19: "Recursive DNS Server",
                    },
                    True,
                )
                opt["length"] = self.buf.ru8()

                self.buf.pasunit(opt["length"] * 8 - 2)

                match opt["type"]:
                    case "Source Link-Layer Address" | "Target Link-Layer Address":
                        opt["link-layer-address"] = self.buf.rh(self.buf.unit)
                    case "Prefix Information":
                        opt["prefix-length"] = self.buf.ru8()
                        opt["on-link"] = bool(self.buf.rb(1))
                        opt["autonomous-address-configuration"] = bool(self.buf.rb(1))
                        opt["reserved1"] = self.buf.rb(6)
                        opt["valid-lifetime"] = self.buf.ru32()
                        opt["preferred-lifetime"] = self.buf.ru32()
                        opt["reserved2"] = self.buf.ru32()
                        opt["prefix"] = ipaddress.IPv6Address(self.buf.read(16)).compressed
                    case "Advertisement Interval":
                        opt["reserved"] = self.buf.ru16()
                        opt["advertisement-interval"] = self.buf.ru32()
                    case "Recursive DNS Server":
                        opt["reserved"] = self.buf.ru16()
                        opt["lifetime"] = self.buf.ru32()

                        opt["addresses"] = []
                        while self.buf.unit >= 16:
                            opt["addresses"].append(ipaddress.IPv6Address(self.buf.read(16)).compressed)
                    case "Nonce":
                        opt["nonce"] = self.buf.rh(self.buf.unit)
                    case _:
                        opt["unknown"] = True

                self.buf.sapunit()
                packet["options"].append(opt)

        return packet

    def read_lldp(self):
        # IEEE/ISO/IEC 8802-1AB
        packet = {}

        packet["values"] = []
        while self.buf.hasunit():
            tlv = {}
            tlv["tag"] = utils.unraw(
                self.buf.rb(7),
                1,
                {
                    0x00: "End",
                    0x01: "Chassis ID",
                    0x02: "Port ID",
                    0x03: "Time To Live",
                    0x04: "Port description",
                    0x05: "System name",
                    0x06: "System description",
                    0x07: "System capabilities",
                    0x08: "Management address",
                },
                True,
            )

            tlv["length"] = self.buf.rb(9)
            self.buf.pasunit(tlv["length"])

            tlv["value"] = {}
            match tlv["tag"]:
                case "End":
                    pass
                case "Chassis ID":
                    tlv["value"]["subtype"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {
                            0x00: "Reserved",
                            0x01: "Chassis component",
                            0x02: "Interface alias",
                            0x03: "Port component",
                            0x04: "MAC address",
                            0x05: "Network address",
                            0x06: "Interface name",
                            0x07: "Locally assigned",
                        },
                        True,
                    )
                    tlv["value"]["id"] = self.buf.rh(self.buf.unit)
                case "Port ID":
                    tlv["value"]["subtype"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {
                            0x00: "Reserved",
                            0x01: "Interface alias",
                            0x02: "Port component",
                            0x03: "MAC address",
                            0x04: "Network address",
                            0x05: "Interface name",
                            0x06: "Agent circuit ID",
                            0x07: "Locally assigned",
                        },
                        True,
                    )
                    tlv["value"]["id"] = self.buf.rh(self.buf.unit)
                case "Time To Live":
                    tlv["value"]["seconds"] = self.buf.ru16()
                case "System capabilities":
                    bits = (
                        (0, "Other"),
                        (1, "Repeater"),
                        (2, "MAC Bridge component"),
                        (3, "802.11 Access Point"),
                        (4, "Router"),
                        (5, "Telephone"),
                        (6, "DOCSIS cable device"),
                        (7, "Station Only"),
                        (8, "C-VLAN component"),
                        (9, "S-VLAN component"),
                        (10, "Two-port MAC Relay component"),
                    )
                    tlv["value"]["capabilities"] = utils.unpack_flags(self.buf.ru16(), bits)
                    tlv["value"]["enabled"] = utils.unpack_flags(self.buf.ru16(), bits)
                case "Management address":
                    tlv["value"]["management-address-length"] = self.buf.ru8()
                    # https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
                    tlv["value"]["management-address-subtype"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {0x01: "IPv4", 0x02: "IPv6", 0x06: "MAC"},
                        True,
                    )

                    self.buf.pasunit(tlv["value"]["management-address-length"] - 1)

                    match tlv["value"]["management-address-subtype"]:
                        case "IPv4":
                            tlv["value"]["management-address"] = ".".join([str(self.buf.ru8()) for i in range(0, 4)])
                        case "IPv6":
                            tlv["value"]["management-address"] = ipaddress.IPv6Address(self.buf.read(16)).compressed
                        case "MAC":
                            tlv["value"]["management-address"] = ":".join([self.buf.rh(1) for i in range(0, 6)])
                        case _:
                            tlv["value"]["management-address"] = self.buf.rh(self.buf.unit)
                            tlv["value"]["unknown"] = True

                    self.buf.sapunit()

                    tlv["value"]["interface-numbering-subtype"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {0x01: "Unknown", 0x02: "ifIndex", 0x03: "system port number"},
                        True,
                    )
                    tlv["value"]["interface-number"] = self.buf.ru32()
                    tlv["value"]["object-id-length"] = self.buf.ru8()

                    self.buf.pasunit(tlv["value"]["object-id-length"])

                    if self.buf.hasunit():
                        tlv["value"]["object-id"] = utils.read_oid(self.buf)
                    self.buf.sapunit()
                case "Port description" | "System name" | "System description":
                    tlv["value"]["string"] = self.buf.rs(self.buf.unit)
                case _:
                    tlv["unknown"] = True

            self.buf.sapunit()
            packet["values"].append(tlv)

        return packet

    def read_arp(self):
        packet = {}
        packet["hardware-type"] = utils.unraw(
            self.buf.ru16(),
            2,
            {
                0x0000: "Reserved",
                0x0001: "Ethernet (10Mb)",
                0x0002: "Experimental Ethernet (3Mb)",
                0x0003: "Amateur Radio AX.25",
                0x0004: "Proteon ProNET Token Ring",
                0x0005: "Chaos",
                0x0006: "IEEE 802 Networks",
                0x0007: "ARCNET",
                0x0008: "Hyperchannel",
                0x0009: "Lanstar",
                0x000A: "Autonet Short Address",
                0x000B: "LocalTalk",
                0x000C: "LocalNet (IBM PCNet or SYTEK LocalNET)",
                0x000D: "Ultra link",
                0x000E: "SMDS",
                0x000F: "Frame Relay",
                0x0010: "Asynchronous Transmission Mode (ATM)",
                0x0011: "HDLC",
                0x0012: "Fibre Channel",
                0x0013: "Asynchronous Transmission Mode (ATM)",
                0x0014: "Serial Line",
                0x0015: "Asynchronous Transmission Mode (ATM)",
                0x0016: "MIL-STD-188-220",
                0x0017: "Metricom",
                0x0018: "IEEE 1394.1995",
                0x0019: "MAPOS",
                0x001A: "Twinaxial",
                0x001B: "EUI-64",
                0x001C: "HIPARP",
                0x001D: "IP and ARP over ISO 7816-3",
                0x001E: "ARPSec",
                0x001F: "IPsec tunnel",
                0x0020: "InfiniBand (TM)",
                0x0021: "TIA-102 Project 25 Common Air Interface (CAI)",
                0x0022: "Wiegand Interface",
                0x0023: "Pure IP",
                0x0024: "HW_EXP1",
                0x0025: "HFI",
                0x0026: "Unified Bus (UB)",
            },
            True,
        )
        packet["protocol-type"] = utils.unraw(self.buf.ru16(), 2, {0x0800: "IPv4", 0x86dd: "IPv6"}, True)
        packet["hardware-length"] = self.buf.ru8()
        packet["protocol-length"] = self.buf.ru8()
        packet["operation"] = utils.unraw(self.buf.ru16(), 2, {0x00: "Reserved", 0x01: "Request", 0x02: "Reply"}, True)

        match packet["operation"]:
            case "Request" | "Reply":
                packet["sender-hardware-address"] = self.buf.rh(packet["hardware-length"])
                packet["sender-protocol-address"] = self.buf.rh(packet["protocol-length"])
                packet["target-hardware-address"] = self.buf.rh(packet["hardware-length"])
                packet["target-protocol-address"] = self.buf.rh(packet["protocol-length"])
            case _:
                packet["unknown"] = True

        return packet

    def read_igmp(self):
        packet = {}
        packet["type"] = utils.unraw(
            self.buf.ru8(),
            1,
            {
                0x11: "Membership Query",
                0x12: "IGMPv1 Membership Report",
                0x16: "IGMPv2 Membership Report",
                0x17: "Leave Group",
                0x22: "IGMPv3 Membership Report",
            },
            True,
        )

        match packet["type"]:
            case "Membership Query":
                packet["maximum-response-time"] = self.buf.ru8()
                packet["checksum"] = self.buf.ru16()
                packet["group-address"] = ".".join([str(self.buf.ru8()) for i in range(0, 4)])

                if self.buf.unit >= 4:
                    packet["reserved"] = self.buf.rb(4)
                    packet["s"] = bool(self.buf.rb(1))
                    packet["qrv"] = self.buf.rb(3)
                    packet["qqic"] = self.buf.ru8()
                    packet["sources-count"] = self.buf.ru16()
                    packet["sources"] = [
                        ".".join([str(self.buf.ru8()) for i in range(0, 4)]) for j in range(0, packet["sources-count"])
                    ]

                packet["aux-data"] = self.buf.rh(self.buf.unit)
            case "IGMPv3 Membership Report":
                packet["reserved1"] = self.buf.ru8()
                packet["checksum"] = self.buf.ru16()
                packet["reserved2"] = self.buf.ru16()
                packet["group-record-count"] = self.buf.ru16()

                packet["group-records"] = []
                for i in range(0, packet["group-record-count"]):
                    record = {}
                    record["type"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {
                            0x01: "MODE_IS_INCLUDE",
                            0x02: "MODE_IS_EXCLUDE",
                            0x03: "CHANGE_TO_INCLUDE_MODE",
                            0x04: "CHANGE_TO_EXCLUDE_MODE",
                            0x05: "ALLOW_NEW_SOURCES",
                            0x06: "BLOCK_OLD_SOURCES",
                        },
                        True,
                    )
                    record["aux-data-length"] = self.buf.ru8()
                    record["sources-count"] = self.buf.ru16()
                    record["multicast-address"] = ".".join([str(self.buf.ru8()) for i in range(0, 4)])
                    record["sources"] = [
                        ".".join([str(self.buf.ru8()) for i in range(0, 4)]) for j in range(0, record["sources-count"])
                    ]
                    packet["aux-data"] = self.buf.rh(record["aux-data-length"])

                    packet["group-records"].append(record)
            case _:
                packet["unknown"] = True

        return packet

    def try_reassemble(self, identifier):
        if identifier not in self.reassemble:
            return

        parts = self.reassemble[identifier]

        found_final = False
        length = 0
        for part in parts:
            found_final |= part["final"]

            if part["final"]:
                length = part["offset"] + part["length"]

        if not found_final:
            return

        span = Span()
        for part in parts:
            span.add(part["offset"], part["length"])

        if not (len(span.ranges) == 1 and span.ranges[0][0] == 0 and span.ranges[0][1] == length):
            return

        packet = bytearray(length)
        for part in parts:
            packet[part["offset"] : part["offset"] + part["length"]] = part["payload"]

        for part in parts:
            part["packet"]["reassembled-in"] = parts[-1]["id"]

        # swap in fake buf with IPv4 header
        buf = self.buf
        self.buf = Buf(
            b"\x45\x00"
            + (len(packet) + 20).to_bytes(2, "big")
            + b"\x00\x00\x00\x00\x00"
            + parts[-1]["protocol"].to_bytes(1, "big")
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + packet
        )
        self.buf.pasunit(self.buf.available())

        parts[-1]["packet"]["payload"] = self.read_ipv4()["payload"]

        self.buf = buf

        del self.reassemble[identifier]

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "pcapng"

        meta["sections"] = []
        self.id: int = 1
        self.reassemble: dict = {}
        self.register_detectors()

        while self.buf.available() > 0:
            interfaces: dict = {}
            section: dict = {}
            section["offset"] = self.buf.tell()

            self.buf.skip(8)
            self.little = self.buf.ru32l() == 0x1a2b3c4d
            self.buf.seek(self.buf.tell() - 8)

            section["header"] = {}
            section["header"]["length"] = self.buf.ru32l() if self.little else self.buf.ru32()
            self.buf.pasunit(section["header"]["length"] - 8)

            section["header"]["little-endian"] = self.buf.ru32l() == 0x1a2b3c4d
            section["header"]["version"] = (
                f"{self.buf.ru16l() if self.little else self.buf.ru16()}.{self.buf.ru16l() if self.little else self.buf.ru16()}"
            )
            size = self.buf.ri64l() if self.little else self.buf.ri64()
            section["header"]["section-length"] = size

            if size == -1:
                size = self.buf.size() - section["offset"]

            section["header"]["options"] = self.read_options("Section Header")

            section["header"]["trailer-length"] = self.buf.ru32l() if self.little else self.buf.ru32()

            self.buf.sapunit()

            # body
            self.buf.pasunit(size - (self.buf.tell() - section["offset"]))

            section["blocks"] = []

            while self.buf.hasunit():
                block = {}
                block["type"] = utils.unraw(
                    self.buf.ru32l() if self.little else self.buf.ru32(),
                    4,
                    {
                        0x00000001: "Interface Description",
                        0x00000005: "Interface Statistics",
                        0x00000006: "Enhanced Packet",
                    },
                    True,
                )
                block["length"] = self.buf.ru32l() if self.little else self.buf.ru32()

                self.buf.pasunit(block["length"] - 8)

                block["data"] = {}
                match block["type"]:
                    case "Interface Description":
                        # https://www.tcpdump.org/linkruminant_types.html
                        block["data"]["link-type"] = utils.unraw(
                            self.buf.ru16l() if self.little else self.buf.ru16(),
                            2,
                            {
                                0x0000: "NULL",
                                0x0001: "ETHERNET",
                                0x0002: "EXP_ETHERNET",
                                0x0003: "AX25",
                                0x0004: "PRONET",
                                0x0005: "CHAOS",
                                0x0006: "IEEE802_5",
                                0x0007: "ARCNET_BSD",
                                0x0008: "SLIP",
                                0x0009: "PPP",
                                0x000a: "FDDI",
                                0x0020: "DLT_REDBACK_SMARTEDGE",
                                0x0032: "PPP_HDLC",
                                0x0033: "PPP_ETHER",
                                0x0063: "SYMANTEC_FIREWALL",
                                0x0064: "ATM_RFC1483",
                                0x0065: "RAW",
                                0x0066: "SLIP_BSDOS",
                                0x0067: "PPP_BSDOS",
                                0x0068: "C_HDLC",
                                0x0069: "IEEE802_11",
                                0x006a: "ATM_CLIP",
                                0x006b: "FRELAY",
                                0x006c: "LOOP",
                                0x006d: "ENC",
                                0x006e: "LANE8023",
                                0x006f: "HIPPI",
                                0x0070: "NETBSD_HDLC",
                                0x0071: "LINUX_SLL",
                                0x0072: "LTALK",
                                0x0073: "DLT_ECONET",
                                0x0074: "DLT_IPFILTER",
                                0x0075: "PFLOG",
                                0x0076: "DLT_CISCO_IOS",
                                0x0077: "IEEE802_11_PRISM",
                                0x0078: "DLT_AIRONET_HEADER",
                                0x007a: "IP_OVER_FC",
                                0x007b: "SUNATM",
                                0x007c: "DLT_RIO",
                                0x007d: "DLT_PCI_EXP",
                                0x007e: "DLT_AURORA",
                                0x007f: "IEEE802_11_RADIOTAP",
                                0x0080: "TZSP",
                                0x0081: "ARCNET_LINUX",
                                0x0082: "JUNIPER_MLPPP",
                                0x0083: "JUNIPER_MLFR",
                                0x0084: "JUNIPER_ES",
                                0x0085: "JUNIPER_GGSN",
                                0x0086: "JUNIPER_MFR",
                                0x0087: "JUNIPER_ATM2",
                                0x0088: "JUNIPER_SERVICES",
                                0x0089: "JUNIPER_ATM1",
                                0x008a: "APPLE_IP_OVER_IEEE1394",
                                0x008b: "MTP2_WITH_PHDR",
                                0x008c: "MTP2",
                                0x008d: "MTP3",
                                0x008e: "SCCP",
                                0x008f: "DOCSIS",
                                0x0090: "LINUX_IRDA",
                                0x0091: "IBM_SP",
                                0x0092: "IBM_SN",
                                0x00a3: "IEEE802_11_AVS",
                                0x00a4: "JUNIPER_MONITOR",
                                0x00a5: "BACNET_MS_TP",
                                0x00a6: "PPP_PPPD",
                                0x00a7: "JUNIPER_PPPOE",
                                0x00a8: "JUNIPER_PPPOE_ATM",
                                0x00a9: "GPRS_LLC",
                                0x00aa: "GPF_T",
                                0x00ab: "GPF_F",
                                0x00ac: "GCOM_T1E1",
                                0x00ad: "GCOM_SERIAL",
                                0x00ae: "JUNIPER_PIC_PEER",
                                0x00af: "ERF_ETH",
                                0x00b0: "ERF_POS",
                                0x00b1: "LINUX_LAPD",
                                0x00b2: "JUNIPER_ETHER",
                                0x00b3: "JUNIPER_PPP",
                                0x00b4: "JUNIPER_FRELAY",
                                0x00b5: "JUNIPER_CHDLC",
                                0x00b6: "MFR",
                                0x00b7: "JUNIPER_VP",
                                0x00b8: "A429",
                                0x00b9: "A653_ICM",
                                0x00ba: "USB_FREEBSD",
                                0x00bb: "BLUETOOTH_HCI_H4",
                                0x00bc: "IEEE802_16_MAC_CPS",
                                0x00bd: "USB_LINUX",
                                0x00be: "CAN20B",
                                0x00bf: "IEEE802_15_4_LINUX",
                                0x00c0: "PPI",
                                0x00c1: "IEEE802_16_MAC_CPS_RADIO",
                                0x00c2: "JUNIPER_ISM",
                                0x00c3: "IEEE802_15_4_WITHFCS",
                                0x00c4: "SITA",
                                0x00c5: "ERF",
                                0x00c6: "RAIF1",
                                0x00c7: "IPMB_KONTRON",
                                0x00c8: "JUNIPER_ST",
                                0x00c9: "BLUETOOTH_HCI_H4_WITH_PHDR",
                                0x00ca: "AX25_KISS",
                                0x00cb: "LAPD",
                                0x00cc: "PPP_WITH_DIR",
                                0x00cd: "C_HDLC_WITH_DIR",
                                0x00ce: "FRELAY_WITH_DIR",
                                0x00cf: "LAPB_WITH_DIR",
                                0x00d1: "I2C_LINUX",
                                0x00d2: "FLEXRAY",
                                0x00d3: "MOST",
                                0x00d4: "LIN",
                                0x00d5: "X2E_SERIAL",
                                0x00d6: "X2E_XORAYA",
                                0x00d7: "IEEE802_15_4_NONASK_PHY",
                                0x00d8: "LINUX_EVDEV",
                                0x00d9: "GSMTAP_UM",
                                0x00da: "GSMTAP_ABIS",
                                0x00db: "MPLS",
                                0x00dc: "USB_LINUX_MMAPPED",
                                0x00dd: "DECT",
                                0x00de: "AOS",
                                0x00df: "WIHART",
                                0x00e0: "FC_2",
                                0x00e1: "FC_2_WITH_FRAME_DELIMS",
                                0x00e2: "IPNET",
                                0x00e3: "CAN_SOCKETCAN",
                                0x00e4: "IPV4",
                                0x00e5: "IPV6",
                                0x00e6: "IEEE802_15_4_NOFCS",
                                0x00e7: "DBUS",
                                0x00e8: "JUNIPER_VS",
                                0x00e9: "JUNIPER_SRX_E2E",
                                0x00ea: "JUNIPER_FIBRECHANNEL",
                                0x00eb: "DVB_CI",
                                0x00ec: "MUX27010",
                                0x00ed: "STANAG_5066_D_PDU",
                                0x00ee: "JUNIPER_ATM_CEMIC",
                                0x00ef: "NFLOG",
                                0x00f0: "NETANALYZER",
                                0x00f1: "NETANALYZER_TRANSPARENT",
                                0x00f2: "IPOIB",
                                0x00f3: "MPEG_2_TS",
                                0x00f4: "NG40",
                                0x00f5: "NFC_LLCP",
                                0x00f6: "PFSYNC",
                                0x00f7: "INFINIBAND",
                                0x00f8: "SCTP",
                                0x00f9: "USBPCAP",
                                0x00fa: "RTAC_SERIAL",
                                0x00fb: "BLUETOOTH_LE_LL",
                                0x00fc: "WIRESHARK_UPPER_PDU",
                                0x00fd: "NETLINK",
                                0x00fe: "BLUETOOTH_LINUX_MONITOR",
                                0x00ff: "BLUETOOTH_BREDR_BB",
                                0x0100: "BLUETOOTH_LE_LL_WITH_PHDR",
                                0x0101: "PROFIBUS_DL",
                                0x0102: "PKTAP",
                                0x0103: "EPON",
                                0x0104: "IPMI_HPM_2",
                                0x0105: "ZWAVE_R1_R2",
                                0x0106: "ZWAVE_R3",
                                0x0107: "WATTSTOPPER_DLM",
                                0x0108: "ISO_14443",
                                0x0109: "RDS",
                                0x010a: "USB_DARWIN",
                                0x010b: "OPENFLOW",
                                0x010c: "SDLC",
                                0x010d: "TI_LLN_SNIFFER",
                                0x010e: "LORATAP",
                                0x010f: "VSOCK",
                                0x0110: "NORDIC_BLE",
                                0x0111: "DOCSIS31_XRA31",
                                0x0112: "ETHERNET_MPACKET",
                                0x0113: "DISPLAYPORT_AUX",
                                0x0114: "LINUX_SLL2",
                                0x0115: "SERCOS_MONITOR",
                                0x0116: "OPENVIZSLA",
                                0x0117: "EBHSCR",
                                0x0118: "VPP_DISPATCH",
                                0x0119: "DSA_TAG_BRCM",
                                0x011a: "DSA_TAG_BRCM_PREPEND",
                                0x011b: "IEEE802_15_4_TAP",
                                0x011c: "DSA_TAG_DSA",
                                0x011d: "DSA_TAG_EDSA",
                                0x011e: "ELEE",
                                0x011f: "Z_WAVE_SERIAL",
                                0x0120: "USB_2_0",
                                0x0121: "ATSC_ALP",
                                0x0122: "ETW",
                                0x0123: "NETANALYZER_NG",
                                0x0124: "ZBOSS_NCP",
                                0x0125: "USB_2_0_LOW_SPEED",
                                0x0126: "USB_2_0_FULL_SPEED",
                                0x0127: "USB_2_0_HIGH_SPEED",
                                0x0128: "AUERSWALD_LOG",
                                0x0129: "ZWAVE_TAP",
                                0x012a: "SILABS_DEBUG_CHANNEL",
                                0x012b: "FIRA_UCI",
                                0x012c: "MDB",
                                0x012d: "DECT_NR",
                                0x012e: "EDK2_MM",
                                0x012f: "DEBUG_ONLY",
                            },
                            True,
                        )
                        block["data"]["reserved"] = self.buf.rh(2)
                        block["data"]["snap-length"] = self.buf.ru32l() if self.little else self.buf.ru32()

                        interfaces[len(interfaces)] = block["data"]["link-type"]
                    case "Enhanced Packet":
                        block["data"]["id"] = self.id
                        self.id += 1

                        block["data"]["interface-id"] = self.buf.ru32l() if self.little else self.buf.ru32()
                        temp = self.buf.ru32l() if self.little else self.buf.ru32()
                        block["data"]["timestamp"] = (temp << 32) | (self.buf.ru32l() if self.little else self.buf.ru32())
                        block["data"]["captured-packet-length"] = self.buf.ru32l() if self.little else self.buf.ru32()
                        block["data"]["original-packet-length"] = self.buf.ru32l() if self.little else self.buf.ru32()

                        self.buf.pasunit(block["data"]["captured-packet-length"])

                        match interfaces[block["data"]["interface-id"]]:
                            case "ETHERNET":
                                block["data"]["packet"] = {}
                                block["data"]["packet"]["destination-mac"] = ":".join([self.buf.rh(1) for i in range(0, 6)])
                                block["data"]["packet"]["source-mac"] = ":".join([self.buf.rh(1) for i in range(0, 6)])

                                temp = self.buf.ru16()

                                if temp <= 1500:
                                    block["data"]["packet"]["length"] = temp
                                    block["data"]["packet"]["destination-service-access-point"] = self.buf.ru8()
                                    block["data"]["packet"]["source-service-access-point"] = self.buf.ru8()
                                    block["data"]["packet"]["ctrl"] = self.buf.ru8()
                                    block["data"]["packet"]["data"] = self.buf.rh(self.buf.unit)
                                else:
                                    block["data"]["packet"]["ethertype"] = utils.unraw(
                                        temp,
                                        2,
                                        {
                                            0x0800: "IPv4",
                                            0x0806: "ARP",
                                            0x86dd: "IPv6",
                                            0x88cc: "LLDP",
                                        },
                                        True,
                                    )

                                    self.buf.pasunit(self.buf.unit if self.buf.unit is not None else 0)

                                    backup = self.buf.backup()
                                    try:
                                        match block["data"]["packet"]["ethertype"]:
                                            case "IPv4":
                                                block["data"]["packet"]["payload"] = self.read_ipv4()
                                            case "IPv6":
                                                block["data"]["packet"]["payload"] = self.read_ipv6()
                                            case "LLDP":
                                                block["data"]["packet"]["payload"] = self.read_lldp()
                                            case "ARP":
                                                block["data"]["packet"]["payload"] = self.read_arp()
                                            case _:
                                                block["data"]["packet"]["payload"] = self.buf.rh(self.buf.unit)

                                                if block["data"]["packet"]["ethertype"] not in (
                                                    "Unknown (0x88e1)",
                                                    "Unknown (0x8912)",
                                                    "Unknown (0x22e3)",
                                                ):
                                                    block["data"]["packet"]["unknown"] = True
                                    except Exception as e:
                                        if module.debug:
                                            raise e
                                        self.buf.restore(backup)
                                        self.buf.sapunit()
                                        block["error"] = True

                                    self.buf.sapunit()
                            case _:
                                block["data"]["packet"] = self.buf.rh(block["data"]["captured-packet-length"])

                        self.buf.sapunit()
                    case "Interface Statistics":
                        block["data"]["interface-id"] = self.buf.ru32l() if self.little else self.buf.ru32()
                        temp = self.buf.ru32l() if self.little else self.buf.ru32()
                        block["data"]["timestamp"] = (temp << 32) | (self.buf.ru32l() if self.little else self.buf.ru32())
                    case _:
                        block["unknown"] = True

                if self.buf.tell() % 4 != 0:
                    self.buf.skip(4 - self.buf.tell() % 4)

                if "unknown" not in block:
                    block["options"] = self.read_options(block["type"])
                    block["trailer-length"] = self.buf.ru32l() if self.little else self.buf.ru32()

                self.buf.sapunit()
                section["blocks"].append(block)

            self.buf.sapunit()

            meta["sections"].append(section)

        return meta


@module.register
class NcsdModule(module.RuminantModule):
    desc = "NCSD Nintendo 3DS Game Card image files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 512:
            return False

        return buf.peek(256 + 4)[256:] == b"NCSD"

    def chew(self) -> ruminant_types.JSON:
        # https://www.3dbrew.org/wiki/NCSD
        meta: dict = {}
        meta["type"] = "ncsd"

        meta["header"] = {}
        meta["header"]["rsa-signature"] = self.buf.rh(256)
        self.buf.skip(4)
        meta["header"]["size"] = self.buf.ru32l()

        self.buf.pasunit(meta["header"]["size"] * 0x200 - 256 - 8)

        meta["header"]["media-id"] = self.buf.ru64l()
        meta["header"]["partition-fs-type"] = utils.unraw(
            self.buf.ru64l(),
            8,
            {
                0x0000000000000000: "None",
                0x0000000000000001: "Normal",
                0x0000000000000003: "FIRM",
                0x0000000000000004: "AGB_FIRM save",
            },
            True,
        )
        meta["header"]["partition-crypt-type"] = list(self.buf.read(8))

        meta["header"]["partitions"] = []
        for i in range(0, 8):
            part = {}
            part["offset"] = self.buf.ru32l() * 0x200
            part["length"] = self.buf.ru32l() * 0x200

            with self.buf:
                self.buf.seek(part["offset"])

                with self.buf.sub(part["length"]):
                    part["blob"] = chew(self.buf)

            meta["header"]["partitions"].append(part)

        meta["header"]["exheader-sha256"] = self.buf.rh(32)
        meta["header"]["additional-header-size"] = self.buf.ru32l()
        meta["header"]["zero-sector-offset"] = self.buf.ru32l()
        meta["header"]["partition-flags"] = {
            "backup-write-wait-time": self.buf.ru8(),
            "reserved1": self.buf.ru16l(),
            "media-card-device-sdk3": utils.unraw(
                self.buf.ru8(),
                1,
                {0x00: "Undefined", 0x01: "NOR Flash", 0x02: "None", 0x03: "BT"},
                True,
            ),
            "media-platform-index": utils.unraw(self.buf.ru8(), 1, {0x01: "CTR"}, True),
            "media-type-index": utils.unraw(
                self.buf.ru8(),
                1,
                {
                    0x00: "Inner Device",
                    0x01: "Card1",
                    0x02: "Card2",
                    0x03: "Extended Device",
                },
                True,
            ),
            "media-unit-size": 0x200 * (2 ** self.buf.ru8()),
            "media-card-device-sdk2": utils.unraw(
                self.buf.ru8(),
                1,
                {0x00: "Undefined", 0x01: "NOR Flash", 0x02: "None", 0x03: "BT"},
                True,
            ),
        }
        meta["header"]["partition-ids"] = [self.buf.ru64l() for i in range(0, 8)]
        meta["header"]["reserved1"] = self.buf.rh(48)
        meta["header"]["writable-address"] = self.buf.ri32l()
        meta["header"]["card-info"] = self.buf.ru32l()
        meta["header"]["reserved2"] = self.buf.rh(248)
        meta["header"]["cardridge-filled-size"] = self.buf.ru32l()
        meta["header"]["reserved3"] = self.buf.rh(12)
        meta["header"]["title-version"] = self.buf.ru16l()
        meta["header"]["card-revision"] = self.buf.ru16l()
        meta["header"]["reserved4"] = self.buf.rh(12)
        meta["header"]["cver-title-id"] = self.buf.ru64l()
        meta["header"]["cver-revision"] = self.buf.ru16l()

        self.buf.pasunit(3286)

        with self.buf.subunit():
            meta["header"]["reserved5"] = chew(self.buf, blob_mode=True)

        self.buf.sapunit()

        meta["header"]["seed"] = self.buf.rh(16)
        meta["header"]["title-key"] = self.buf.rh(16)
        meta["header"]["aes-ccm-mac"] = self.buf.rh(16)
        meta["header"]["aes-ccm-nonce"] = self.buf.rh(12)
        meta["header"]["reserved6"] = self.buf.rh(196)
        meta["header"]["ncch-copy"] = self.buf.rh(256)

        self.buf.sapunit()

        return meta


@module.register
class NcchModule(module.RuminantModule):
    desc = "NCCH Nintendo 3DS files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 512:
            return False

        return buf.peek(256 + 4)[256:] == b"NCCH"

    def read_lz11(self):
        assert self.buf.ru8() == 0x11
        decomp_size = self.buf.ru24l()

        data = bytearray()

        while len(data) < decomp_size:
            op = self.buf.ru8()

            for i in range(7, -1, -1):
                if op & (1 << i):
                    b1 = self.buf.ru8()

                    match b1 >> 4:
                        case 0:
                            b2 = self.buf.ru8()
                            count = ((b1 & 0x0f) << 4) + (b2 >> 4) + 0x11
                            offset = ((b2 & 0x0f) << 8) + self.buf.ru8() + 1
                        case 1:
                            b2 = self.buf.ru8()
                            b3 = self.buf.ru8()
                            count = ((b1 & 0x0f) << 12) + (b2 << 4) + (b3 >> 4) + 0x111
                            offset = ((b3 & 0x0f) << 8) + self.buf.ru8() + 1
                        case _:
                            count = (b1 >> 4) + 1
                            offset = ((b1 & 0x0f) << 8) + self.buf.ru8() + 1

                    for j in range(0, count):
                        data += data[-offset : -offset + 1]
                else:
                    data += self.buf.read(1)

                if not len(data) < decomp_size:
                    break

        return bytes(data)

    def read_exefs(self):
        base = self.buf.tell()

        exefs = {}
        exefs["files"] = []
        for i in range(0, 10):
            f = {}
            f["name"] = self.buf.rs(8)
            f["offset"] = self.buf.ru32l()
            f["size"] = self.buf.ru32l()

            with self.buf:
                self.buf.seek(base + 0x200 + f["offset"])

                with self.buf.sub(f["size"]):
                    match f["name"]:
                        case "logo":
                            f["blob"] = chew(self.read_lz11())
                        case ".code":
                            f["blob"] = chew(self.buf, blob_mode=True)
                        case _:
                            f["blob"] = chew(self.buf)

            exefs["files"].append(f)

        exefs["reserved"] = self.buf.rh(0x20)

        for i in range(0, 10):
            exefs["files"][9 - i]["hash"] = self.buf.rh(32)

        return exefs

    def chew(self) -> ruminant_types.JSON:
        # https://www.3dbrew.org/wiki/NCCH#NCCH_Header
        meta: dict = {}
        meta["type"] = "ncch"

        meta["header"] = {}
        meta["header"]["rsa-signature"] = self.buf.rh(256)
        self.buf.skip(4)
        meta["header"]["size"] = self.buf.ru32l()

        self.buf.pasunit(meta["header"]["size"] * 0x200 - 256 - 8)

        meta["header"]["partition-id"] = self.buf.ru64l()
        meta["header"]["maker-code"] = self.buf.rs(2)
        meta["header"]["version"] = self.buf.ru16l()
        meta["header"]["hash-prefix"] = self.buf.rh(4)
        meta["header"]["program-id"] = self.buf.ru64l()
        meta["header"]["reserved1"] = self.buf.rh(16)
        meta["header"]["logo-region-hash"] = self.buf.rh(32)
        meta["header"]["product-code"] = self.buf.rs(16)
        meta["header"]["extended-header-hash"] = self.buf.rh(32)
        meta["header"]["extended-header-size"] = self.buf.ru32l()
        meta["header"]["reserved2"] = self.buf.rh(4)
        meta["header"]["flags"] = {
            "reserved": self.buf.rh(3),
            "crypto-method": self.buf.ru8(),
            "content-platform": utils.unraw(self.buf.ru8(), 1, {0x01: "CTR", 0x02: "New 3DS/Snake"}, True),
            "content-type": utils.unraw(
                self.buf.rb(6),
                1,
                {
                    0x00: "Unspecified",
                    0x01: "System Update",
                    0x02: "Instruction Manual",
                    0x03: "Download Play Child",
                    0x04: "Trial (Demo)",
                    0x05: "Extended System Update",
                },
                True,
            ),
            "content-form-type": utils.unraw(
                self.buf.rb(2),
                1,
                {
                    0x00: "Not Assigned",
                    0x01: "Simple Content",
                    0x02: "Executable without RomFS",
                    0x03: "Executable",
                },
                True,
            ),
            "content-unit-size": 0x200 * (2 ** self.buf.ru8()),
            "bitmask": utils.unpack_flags(
                self.buf.ru8(),
                (
                    (0, "FixedCryptoKey"),
                    (1, "NoMountRomFs"),
                    (2, "NoCrypto"),
                    (5, "UseNewKeyYGenerator"),
                ),
            ),
        }
        meta["header"]["regions"] = {}
        meta["header"]["regions"]["plain"] = {
            "offset": self.buf.ru32l() * 0x200,
            "size": self.buf.ru32l() * 0x200,
        }
        meta["header"]["regions"]["logo"] = {
            "offset": self.buf.ru32l() * 0x200,
            "size": self.buf.ru32l() * 0x200,
        }
        meta["header"]["regions"]["exefs"] = {
            "offset": self.buf.ru32l() * 0x200,
            "size": self.buf.ru32l() * 0x200,
            "hash-size": self.buf.ru32l() * 0x200,
            "reserved": self.buf.ru32l(),
        }
        meta["header"]["regions"]["romfs"] = {
            "offset": self.buf.ru32l() * 0x200,
            "size": self.buf.ru32l() * 0x200,
            "hash-size": self.buf.ru32l() * 0x200,
            "reserved": self.buf.ru32l(),
        }
        meta["header"]["exefs-superblock-hash"] = self.buf.rh(32)
        meta["header"]["romfs-superblock-hash"] = self.buf.rh(32)

        decrypted = "NoCrypto" in meta["header"]["flags"]["bitmask"]["names"]
        for name, region in meta["header"]["regions"].items():
            with self.buf:
                self.buf.seek(region["offset"])
                with self.buf.sub(region["size"]):
                    region["blob"] = chew(self.buf, blob_mode=True)

                self.buf.seek(region["offset"])

                self.buf.pasunit(region["size"])

                region["parsed"] = {}
                match name:
                    case "plain":
                        region["parsed"]["strings"] = []
                        while self.buf.hasunit():
                            region["parsed"]["strings"].append(self.buf.rzs())

                        while len(region["parsed"]["strings"]) > 0 and region["parsed"]["strings"][-1] == "":
                            region["parsed"]["strings"].pop()
                    case "exefs":
                        if decrypted:
                            region["parsed"] = self.read_exefs()
                    case _:
                        del region["parsed"]

                self.buf.sapunit()

        self.buf.sapunit()

        return meta


@module.register
class SmdhModule(module.RuminantModule):
    desc = "Nintendo 3DS SMDH icon files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"SMDH"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "smdh"

        self.buf.skip(4)
        meta["version"] = self.buf.ru16l()
        meta["reserved1"] = self.buf.ru16l()

        meta["application-structs"] = []
        for i in range(0, 16):
            app = {}
            app["language"] = [
                "Japanese",
                "English",
                "French",  # grr French
                "German",
                "Italian",
                "Spanish",
                "Simplified Chinese",
                "Korean",
                "Dutch",
                "Portuguese",
                "Russian",
                "Traditional Chinese",
                "Unknown",
                "Unknown",
                "Unknown",
                "Unknown",
            ][i]
            app["short-description"] = self.buf.rs(0x80, "utf-16")
            app["long-description"] = self.buf.rs(0x100, "utf-16")
            app["publisher"] = self.buf.rs(0x80, "utf-16")

            meta["application-structs"].append(app)

        meta["application-settings"] = {}
        meta["application-settings"]["ratings"] = {}
        for i in range(0, 16):
            rating = self.buf.ru8()
            name = [
                "CERO (Japan)",
                "ESRB (USA)",
                "Reserved 1",
                "USK (German)",
                "PEGI GEN (Europe)",
                "Reserved 2",
                "PEGI PRT (Portugal)",
                "PEGI BBFC (England)",
                "COB (Australia)",
                "GRB (South Korea)",
                "CGSRR (Taiwan)",
                "Reserved 3",
                "Reserved 4",
                "Reserved 5",
                "Reserved 6",
                "Reserved 7",
            ][i]

            if rating == 0x00:
                continue
            elif rating & 0x80:
                meta["application-settings"]["ratings"][name] = rating - 0x80
            elif rating & 0x40:
                meta["application-settings"]["ratings"][name] = "pending"
            elif rating & 0x20:
                meta["application-settings"]["ratings"][name] = "no restriction"

        meta["application-settings"]["region-lockout"] = utils.unpack_flags(
            self.buf.ru32l(),
            (
                (0, "Japan"),
                (1, "North America"),
                (2, "Europe"),
                (3, "Australia"),
                (4, "China"),
                (5, "Korea"),
                (6, "Taiwan"),
            ),
        )
        meta["application-settings"]["match-maker-id"] = self.buf.ru32l()
        meta["application-settings"]["match-maker-bit-id"] = self.buf.ru64l()
        meta["application-settings"]["flags"] = utils.unpack_flags(
            self.buf.ru32l(),
            (
                (0, "visibility"),
                (1, "auto-boot"),
                (2, "has-3d"),
                (3, "requires-eula"),
                (4, "autosave-on-exit"),
                (5, "has-extended-banner"),
                (6, "region-game-rating-required"),
                (7, "uses-save-data"),
                (8, "record-usage"),
                (9, "disable-sdcard-save-data-backups"),
                (10, "new-3ds-exclusive"),
                (11, "restricted-by-parental-controls"),
            ),
        )
        temp = self.buf.ru8()
        meta["application-settings"]["eula-version"] = f"{self.buf.ru8()}.{temp}"
        meta["application-settings"]["reserved"] = self.buf.ru16l()
        meta["application-settings"]["optimal-animation-default-frame"] = self.buf.rf32()
        meta["application-settings"]["cec-id"] = self.buf.ru32l()
        meta["reserved2"] = self.buf.ru64l()

        self.buf.pasunit(0x1680)

        with self.buf.subunit():
            meta["icon-graphics"] = chew(self.buf, blob_mode=True)

        self.buf.sapunit()

        return meta


@module.register
class DarcModule(module.RuminantModule):
    desc = "Nintendo 3DS DARC archives."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"darc"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "darc"

        self.buf.skip(4)
        assert self.buf.ru16l() == 0xfeff

        meta["header"] = {}
        meta["header"]["length"] = self.buf.ru16l()

        self.buf.pasunit(meta["header"]["length"] - 8)

        meta["header"]["version"] = self.buf.ru32l()
        meta["header"]["file-length"] = self.buf.ru32l()
        meta["header"]["file-table-offset"] = self.buf.ru32l()
        meta["header"]["file-table-length"] = self.buf.ru32l()
        meta["header"]["file-data-offset"] = self.buf.ru32l()

        self.buf.sapunit()

        self.buf.seek(meta["header"]["file-table-offset"])
        self.buf.pasunit(meta["header"]["file-table-length"])

        meta["files"] = []
        todo = None
        while todo is None or todo > 0:
            f = {}
            f["name"] = self.buf.ru32l()
            f["folder"] = bool(f["name"] & 0x01000000)
            f["offset"] = self.buf.ru32l()
            f["length"] = self.buf.ru32l()

            if todo is None:
                todo = f["length"]

            todo -= 1

            meta["files"].append(f)

        self.buf.popunit()

        base = self.buf.tell()
        for f in meta["files"]:
            self.buf.seek(base + (f["name"] & 0x0000ffff))
            f["name"] = self.buf.rwzs()

        m = [[x, None] for x in meta["files"]]
        for i, pair in enumerate(m):
            if pair[0]["folder"]:
                for j in range(i + 1, pair[0]["length"]):
                    m[j][1] = i

        max_offset = meta["header"]["file-data-offset"]
        for pair in m:
            if not pair[0]["folder"]:
                max_offset = max(max_offset, pair[0]["offset"] + pair[0]["length"])

                self.buf.seek(pair[0]["offset"])
                with self.buf.sub(pair[0]["length"]):
                    pair[0]["blob"] = chew(self.buf)

            if pair[1] is None:
                continue

            if "children" not in m[pair[1]][0]:
                m[pair[1]][0]["children"] = []

            m[pair[1]][0]["children"].append(pair[0])

        meta["files"] = m[0][0]

        self.buf.seek(max_offset)
        meta["hmac"] = self.buf.rh(32)

        return meta
