from .. import module, utils, ruminant_types
from ..buf import Buf
from . import chew

import datetime
import tempfile
import zlib
import math
import sys
from typing import TYPE_CHECKING


@module.register
class GzipModule(module.RuminantModule):
    desc = "gzip steams."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(2) == b"\x1f\x8b"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "gzip"

        self.buf.skip(2)

        # while all gzip files use compression mode 8 (Deflate), the format allows others
        compression_method = self.buf.ru8()
        assert compression_method == 8, f"Unknown gzip compression method {compression_method}"
        meta["compression-method"] = utils.unraw(compression_method, 2, {8: "Deflate"})

        flags = self.buf.ru8()
        meta["flags"] = {
            "raw": flags,
            # unused most of the time
            "is-probably-text": bool(flags & 0x01),
            "has-crc": bool(flags & 0x02),
            "has-extra": bool(flags & 0x04),
            "has-name": bool(flags & 0x08),
            "has-comment": bool(flags & 0x10),
            "reserved": flags >> 5,
        }

        meta["time"] = datetime.datetime.utcfromtimestamp(self.buf.ru32l()).isoformat()
        meta["extra-flags"] = utils.unraw(
            self.buf.ru8(),
            2,
            {
                0: "None",
                2: "Best compression (level 9)",
                4: "Fastest compression (level 1)",
            },
        )
        meta["filesystem"] = utils.unraw(
            self.buf.ru8(),
            2,
            {
                0: "FAT",
                1: "Amiga",
                2: "OpenVMS",
                3: "Unix",
                4: "VM/CMS",
                5: "Atari TOS",
                6: "HPFS",
                7: "Macintosh",
                8: "Z-System",
                9: "CP/M",
                # some programs set this for some reason
                10: "TOPS-20",
                11: "NTFS",
                12: "QDOS",
                13: "RISCOS",
                255: "None",
            },
        )

        # has extra?
        if flags & 0x04:
            self.buf.pushunit()
            self.buf.setunit(self.buf.ru16l())

            meta["extra"] = []
            while self.buf.hasunit():
                extra = {}
                extra["type"] = self.buf.rs(2, "latin-1")
                extra["content"] = utils.decode(self.buf.read(self.buf.ru16l()))
                meta["extra"].append(extra)

            self.buf.skipunit()
            self.buf.popunit()

        # has name?
        if flags & 0x08:
            meta["name"] = self.buf.rzs("latin-1")

        # has comment?
        if flags & 0x10:
            meta["comment"] = self.buf.rzs("latin-1")

        # has front crc16?
        # not to be confused with the footer crc
        if flags & 0x02:
            meta["header-crc"] = self.buf.rh(2)

        meta["footer-crc"] = None
        meta["size-mod-2^32"] = None

        # stream to unnamed temporary file
        self.buf.unit = None
        with tempfile.TemporaryFile() as fd:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

            while not decompressor.eof:
                fd.write(decompressor.decompress(self.buf.read(min(1 << 24, self.buf.available()))))

            self.buf.seek(-len(decompressor.unused_data), 1)

            fd.write(decompressor.flush())

            # reset fd and chew it
            fd.seek(0)
            meta["data"] = chew(fd)

        # read footer crc if it exists
        if self.buf.available() >= 4:
            meta["footer-crc"] = self.buf.rh(4)
        # read the lower 32 bits of the original file length if it exists
        if self.buf.available() >= 4:
            meta["size-mod-2^32"] = self.buf.ru32l()

        return meta


@module.register
class Bzip2Module(module.RuminantModule):
    desc = "bzip2 streams."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(2) == b"BZ"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "bzip2"

        with tempfile.TemporaryFile() as fd:
            utils.stream_bzip2(self.buf, fd, self.buf.available())

            # chew decompressed data
            fd.seek(0)
            meta["data"] = chew(fd)

        return meta


@module.register
class ZstdModule(module.RuminantModule):
    desc = "Zstandard streams.\nIdeally, you should install pyzstd or backports.zstd or run Python version 3.14 or higher to allow decompression of the content."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"\x28\xb5\x2f\xfd"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "zstd"

        if TYPE_CHECKING:
            has_zstd = True
            import pyzstd as zstd
        else:
            # try to import zstd library as python doesn't ship it for versions < 3.14
            has_zstd = True
            try:
                import pyzstd as zstd
            except ImportError:
                try:
                    if sys.version_info >= (3, 14):
                        from compression import zstd
                    else:
                        from backports import zstd
                except ImportError:
                    has_zstd = False

        with self.buf:
            self.buf.skip(4)
            meta["header"] = {}
            meta["header"]["flags"] = {"raw": self.buf.ru8(), "names": []}

            meta["header"]["flags"]["names"].append(["FCS_1", "FCS_2", "FCS_4", "FCS_8"][meta["header"]["flags"]["raw"] >> 6])
            if meta["header"]["flags"]["raw"] & (1 << 5):
                meta["header"]["flags"]["names"].append("SINGLE_SEGMENT")
                if "FCS_1" in meta["header"]["flags"]["names"]:
                    meta["header"]["flags"]["names"].remove("FCS_1")
            if meta["header"]["flags"]["raw"] & (1 << 2):
                meta["header"]["flags"]["names"].append("CONTENT_CHECKSUM")
            if meta["header"]["flags"]["raw"] & 0x03:
                meta["header"]["flags"]["names"].append(
                    [None, "DID_1", "DID_2", "DID_4"][meta["header"]["flags"]["raw"] & 0x03]
                )

            if "SINGLE_SEGMENT" not in meta["header"]["flags"]["names"]:
                temp = self.buf.ru8()
                exponent = temp >> 3
                mantissa = temp & 0x03
                meta["header"]["window-size"] = math.ceil(((1 << (exponent + 10)) / 8) * mantissa + (1 << (exponent + 10)))

            if "DID_1" in meta["header"]["flags"]["names"]:
                meta["header"]["dictionary-id"] = self.buf.ru8()
            elif "DID_2" in meta["header"]["flags"]["names"]:
                meta["header"]["dictionary-id"] = self.buf.ru16l()
            elif "DID_4" in meta["header"]["flags"]["names"]:
                meta["header"]["dictionary-id"] = self.buf.ru32l()

            if "FCS_1" in meta["header"]["flags"]["names"]:
                meta["header"]["frame-content-size"] = self.buf.ru8()
            elif "FCS_2" in meta["header"]["flags"]["names"]:
                meta["header"]["frame-content-size"] = self.buf.ru16l()
            elif "FCS_4" in meta["header"]["flags"]["names"]:
                meta["header"]["frame-content-size"] = self.buf.ru32l()
            elif "FCS_8" in meta["header"]["flags"]["names"]:
                meta["header"]["frame-content-size"] = self.buf.ru64l()

            base = self.buf.tell()

        self.buf.seek(base)
        while True:
            header = self.buf.ru24l()
            last = header & 0x01
            typ = (header >> 1) & 0x03
            length = header >> 3

            if typ == 0 or typ == 2:
                self.buf.skip(length)
            else:
                self.buf.skip(1)

            if last:
                break

        if "CONTENT_CHECKSUM" in meta["header"]["flags"]["names"]:
            self.buf.skip(4)

        # now actually try do decompress it
        # otherwise, we just skipped the content and move on
        if has_zstd:
            offset = self.buf.tell()

            with self.buf:
                self.buf.seek(0)

                decompressor = zstd.ZstdDecompressor()
                fd = utils.tempfd()
                utils.stream_generic(decompressor, self.buf, fd, offset)

                fd.seek(0)
                meta["data"] = chew(fd)

        return meta


@module.register
class ZlibModule(module.RuminantModule):
    desc = "zlib streams."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(2) in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "zlib"
        meta["compression-type"] = utils.unraw(
            self.buf.ru16() & 0xff,
            1,
            {0x01: "none", 0x53: "fast", 0x9c: "default", 0xda: "best"},
            True,
        )

        fd = utils.tempfd()
        utils.stream_zlib(self.buf, fd, self.buf.available())
        fd.seek(0)
        meta["data"] = chew(fd)

        return meta


@module.register
class XzModule(module.RuminantModule):
    desc = "xz streams."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(6) == b"\xfd7zXZ\x00"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "xz"

        self.buf.skip(6)

        meta["stream-header"] = {}
        temp = self.buf.ru16()
        meta["stream-header"]["check-type"] = utils.unraw(
            temp & 0x0f,
            2,
            {0x00: "None", 0x01: "CRC-32", 0x04: "CRC-64", 0x0a: "SHA-256"},
            True,
        )
        meta["stream-header"]["flags"] = utils.unpack_flags(temp & 0xfff0, ())
        meta["stream-header"]["crc32"] = {}

        crc32 = self.buf.ru32l()
        meta["stream-header"]["crc32"]["value"] = hex(crc32)[2:].zfill(8)
        actual_crc32 = zlib.crc32(temp.to_bytes(2, "big"))
        meta["stream-header"]["crc32"]["correct"] = crc32 == actual_crc32
        if not meta["stream-header"]["crc32"]["correct"]:
            meta["stream-header"]["crc32"]["actual"] = hex(actual_crc32)[2:].zfill(8)

        self.buf.seek(0)
        fd = utils.tempfd()
        utils.stream_xz(self.buf, fd, self.buf.available())
        fd.seek(0)
        meta["data"] = chew(fd)

        return meta
