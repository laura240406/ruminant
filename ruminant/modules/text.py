from .. import module, utils, ruminant_types
from ..buf import Buf
from . import chew
import json
import base64
import binascii


@module.register
class Utf8Module(module.RuminantModule):
    priority = 1
    desc = "UTF-8 encoded text.\nThis is detected on a best-effort basis and also tries to detect base64, XML or JSON encoding."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        try:
            assert buf.available() > 0 and buf.available() < 1000000
            for i in buf.peek(buf.available()).decode("utf-8"):
                assert ord(i) >= 0x20 or ord(i) in (0x0a, 0x0d, 0x09)

            return True
        except Exception:
            return False

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "text"

        content = self.buf.rs(self.buf.available())

        try:
            assert content.startswith("data:image/")
            sdata = ";".join(content.split(";")[1:]).split(",")
            encoding, data = sdata[0], ",".join(sdata[1:])

            bdata: bytes
            match encoding:
                case "utf8":
                    bdata = data.encode("utf-8")
                case "base64":
                    bdata = base64.b64decode(data, validate=True)
                case _:
                    raise ValueError()

            content = chew(bdata)
            meta["decoder"] = "data-uri"
            meta["encoding"] = encoding
        except Exception:
            try:
                content = utils.xml_to_dict(content, fail=True)
                meta["decoder"] = "xml"
            except Exception:
                try:
                    assert content[0] == "{"
                    content = json.loads(content)
                    meta["decoder"] = "json"
                except Exception:
                    try:
                        blob = None
                        for i in range(0, 4):
                            try:
                                blob = chew(base64.b64decode(content + "=" * i, validate=True))
                                break
                            except binascii.Error:
                                pass

                        assert blob is not None

                        content = blob
                        meta["decoder"] = "base64"
                    except Exception:
                        content = content.split("\n")
                        meta["decoder"] = "lines"

        meta["data"] = content

        return meta


@module.register
class EmptyModule(module.RuminantModule):
    desc = "Empty files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.available() == 0

    def chew(self) -> ruminant_types.JSON:
        return {"type": "empty"}


@module.register
class ZeroesModule(module.RuminantModule):
    priorty = 2
    desc = "Files containing only zero bytes."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        with buf:
            first = True
            s = 0
            while buf.available() > 0:
                s += sum(buf.read(min(buf.available(), 65536 if first else 2**24)))
                first = False
                if s != 0:
                    return False

        return True

    def chew(self) -> ruminant_types.JSON:
        self.buf.skip(self.buf.available())
        return {"type": "zeroes"}


@module.register
class AndroidXmlModule(module.RuminantModule):
    dev = True
    desc = "Android binary XML files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.pu32l() == 0x00080003 and buf.pu64l() >> 32 <= buf.available()

    def read_chunk(self):
        chunk = {}
        chunk["type"] = utils.unraw(
            self.buf.ru16l(),
            2,
            {
                0x0000: "RES_NULL_TYPE",
                0x0001: "RES_STRING_POOL_TYPE",
                0x0002: "RES_TABLE_TYPE",
                0x0003: "RES_XML_TYPE",
                0x0100: "RES_XML_START_NAMESPACE_TYPE",
                0x0101: "RES_XML_END_NAMESPACE_TYPE",
                0x0102: "RES_XML_START_ELEMENT_TYPE",
                0x0103: "RES_XML_END_ELEMENT_TYPE",
                0x0104: "RES_XML_CDATA_TYPE",
                0x017f: "RES_XML_LAST_CHUNK_TYPE",
                0x0180: "RES_XML_RESOURCE_MAP_TYPE",
                0x0200: "RES_TABLE_PACKAGE_TYPE",
                0x0201: "RES_TABLE_TYPE_TYPE",
                0x0202: "RES_TABLE_TYPE_SPEC_TYPE",
                0x0203: "RES_TABLE_LIBRARY_TYPE",
                0x0204: "RES_TABLE_OVERLAYABLE_TYPE",
                0x0205: "RES_TABLE_OVERLAYABLE_POLICY_TYPE",
                0x0206: "RES_TABLE_STAGED_ALIAS_TYPE",
            },
            True,
        )
        chunk["header-length"] = self.buf.ru16l()
        chunk["payload-length"] = self.buf.ru32l()

        self.buf.pasunit(chunk["payload-length"] - 8)

        match chunk["type"]:
            case "RES_XML_TYPE":
                chunk["subchunks"] = []
                while self.buf.unit > 0:
                    chunk["subchunks"].append(self.read_chunk())
            case "RES_STRING_POOL_TYPE":
                chunk["data"] = {}
                chunk["data"]["string-count"] = self.buf.ru32l()
                chunk["data"]["style-count"] = self.buf.ru32l()

                chunk["data"]["flags"] = {"raw": self.buf.ru32l(), "names": []}
                if chunk["data"]["flags"]["raw"] & 0x00000001:
                    chunk["data"]["flags"]["names"].append("SORTED")
                if chunk["data"]["flags"]["raw"] & 0x00000100:
                    chunk["data"]["flags"]["names"].append("UTF8")

                chunk["data"]["strings-start"] = self.buf.ru32l()
                chunk["data"]["styles-start"] = self.buf.ru32l()

                chunk["data"]["strings"] = []
                self.buf.skip(chunk["data"]["strings-start"] - 28)
                encoding = "utf8" if "UTF8" in chunk["data"]["flags"]["names"] else "utf16"
                while self.buf.unit > 0:
                    chunk["data"]["strings"].append(
                        self.buf.rs(
                            self.buf.ru16l() * (2 if encoding == "utf16" else 1),
                            encoding,
                        )
                    )
                    self.buf.skip(2)
            case "RES_XML_RESOURCE_MAP_TYPE":
                chunk["data"] = [self.buf.ru32l() for i in range(0, self.buf.unit // 4)]
            case "RES_XML_START_NAMESPACE_TYPE" | "RES_XML_START_ELEMENT_TYPE":
                chunk["data"] = {}
                chunk["data"]["line-number"] = self.buf.ru32l()
                chunk["data"]["comment-index"] = self.buf.ri32l()
            case "RES_XML_END_ELEMENT_TYPE" | "RES_XML_END_NAMESPACE_TYPE":
                chunk["data"] = {}
                chunk["data"]["ns-index"] = self.buf.ri32l()
                chunk["data"]["name-index"] = self.buf.ri32l()
            case _:
                chunk["unknown"] = True

        self.buf.sapunit()

        return chunk

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "android-xml"

        meta["root-chunk"] = self.read_chunk()

        return meta
