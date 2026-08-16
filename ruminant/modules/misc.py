from .. import module, utils, constants, ruminant_types
from ..buf import Buf
from . import chew
import tempfile
import sqlite3
import datetime
import gzip
import zlib
import binascii
import base64
import json
import math


debug = module.debug


@module.register
class TorrentModule(module.RuminantModule):
    desc = "BitTorrent files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        with buf:
            try:
                if buf.read(1) != b"d":
                    return False

                for i in range(0, 3):
                    c = buf.read(1)
                    if c in b"0123456789":
                        pass
                    elif c == b":":
                        return True
                    else:
                        return False

                return False
            except Exception:
                return False

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "magnet"

        meta["data"] = utils.read_bencode(self.buf)

        return meta


@module.register
class Sqlite3Module(module.RuminantModule):
    desc = "sqlite3 database files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(16) == b"SQLite format 3\x00"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "sqlite3"

        self.buf.skip(16)

        meta["header"] = {}
        meta["header"]["page-size"] = self.buf.ru16()
        if meta["header"]["page-size"] == 1:
            meta["header"]["page-size"] = 65536
        meta["header"]["write-version"] = self.buf.ru8()
        meta["header"]["read-version"] = self.buf.ru8()
        meta["header"]["reserved-per-page"] = self.buf.ru8()
        meta["header"]["max-embedded-payload-fraction"] = self.buf.ru8()
        meta["header"]["min-embedded-payload-fraction"] = self.buf.ru8()
        meta["header"]["leaf-payload-fraction"] = self.buf.ru8()
        meta["header"]["file-change-count"] = self.buf.ru32()
        meta["header"]["page-count"] = self.buf.ru32()
        meta["header"]["first-freelist"] = self.buf.ru32()
        meta["header"]["freelist-count"] = self.buf.ru32()
        meta["header"]["schema-cookie"] = self.buf.ru32()
        meta["header"]["schema-format"] = self.buf.ru32()
        meta["header"]["default-page-cache-size"] = self.buf.ru32()
        meta["header"]["largest-broot-page"] = self.buf.ru32()
        meta["header"]["encoding"] = utils.unraw(self.buf.ru32(), 4, {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"})
        meta["header"]["user-version"] = self.buf.ru32()
        meta["header"]["incremental-vaccum-mode"] = self.buf.ru32()
        meta["header"]["application-id"] = self.buf.ru32()
        meta["header"]["reserved"] = self.buf.rh(20)
        meta["header"]["version-valid-for"] = self.buf.ru32()
        meta["header"]["sqlite-version-number"] = self.buf.ru32()

        fd = tempfile.NamedTemporaryFile()
        self.buf.seek(0)
        to_copy = meta["header"]["page-size"] * meta["header"]["page-count"]
        while to_copy > 0:
            fd.write(self.buf.read(min(to_copy, 1 << 24)))
            to_copy = max(to_copy - (1 << 24), 0)

        db = sqlite3.connect(fd.name)
        cur = db.cursor()

        meta["schema"] = [x[0] for x in cur.execute("SELECT sql FROM sqlite_master")]

        db.close()
        fd.close()

        return meta


@module.register
class NbtModule(module.RuminantModule):
    desc = "Minecraft NBT files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return (not ctx["walk"]) and (buf.pu32() & 0xffffffc0 == 0x0a000000)

    def clean(self, root):
        if isinstance(root, dict):
            for k, v in list(root.items()):
                if k in ("sections", "Heightmaps"):
                    root[k] = None
                else:
                    self.clean(v)
        elif isinstance(root, list):
            for elem in root:
                self.clean(elem)

    def parse(self, root):
        if isinstance(root, dict):
            for k, v in list(root.items()):
                if k == "icon" and isinstance(v, str) and len(v) > 100:
                    try:
                        root[k] = {"raw": v, "parsed": chew(base64.b64decode(v))}
                    except binascii.Error:
                        pass
                else:
                    self.parse(v)
        elif isinstance(root, list):
            for elem in root:
                self.parse(elem)

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "nbt"

        meta["data"] = {}
        while self.buf.available() > 0:
            key, value = utils.read_nbt(self.buf)
            meta["data"][key] = value

        if self.extra_ctx.get("skip-chunk-data"):
            self.clean(meta["data"])

        self.parse(meta["data"])

        return meta


@module.register
class McaModule(module.RuminantModule):
    priority = 1
    desc = "Minecraft chunk region files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if ctx["walk"]:
            return False

        try:
            with buf:
                if buf.available() < 0x2000:
                    return False

                found_chunk = False
                for i in range(0, 1024):
                    offset = buf.ru32()
                    length = (offset & 0xff) * 0x1000
                    offset = (offset >> 8) * 0x1000

                    if offset < 2 and length != 0:
                        return False

                    if length == 0:
                        continue

                    found_chunk = True

                    with buf:
                        buf.seek(offset)
                        length2 = buf.ru32()
                        if length2 > length:
                            return False

                        if buf.ru8() not in (0x01, 0x02, 0x03, 0x04, 0x7f):
                            return False

                    return found_chunk
        except Exception:
            return False

        return False

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "mca"

        meta["chunk-count"] = 0
        meta["chunks"] = {}
        for i in range(0, 1024):
            offset = self.buf.ru32()
            length = (offset & 0xff) * 0x1000
            offset = (offset >> 8) * 0x1000

            if length != 0:
                meta["chunk-count"] += 1
                chunk: dict = {}
                meta["chunks"][f"({i % 32}, {i // 32})"] = chunk

                chunk["offset"] = offset
                chunk["padded-length"] = length
                chunk["length"] = 0

                with self.buf:
                    self.buf.seek(0x1000 + i * 4)
                    chunk["timestamp"] = datetime.datetime.fromtimestamp(self.buf.ru32(), datetime.timezone.utc).isoformat()

                    self.buf.seek(offset)
                    chunk["length"] = self.buf.ru32()
                    self.buf.pasunit(chunk["length"])

                    chunk["compression"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {0x01: "GZip", 0x02: "zlib", 0x03: "Uncompressed"},
                    )

                    data = None
                    content = self.buf.readunit()
                    match chunk["compression"]["raw"]:
                        case 0x01:
                            data = gzip.decompress(content)
                        case 0x02:
                            data = zlib.decompress(content)
                        case 0x03:
                            data = content
                        case _:
                            chunk["unknown"] = True

                    if data is not None:
                        chunk["data"] = chew(data, extra_ctx={"skip-chunk-data": True})

                    self.buf.sapunit()

        m = 0x2000
        for chunk in meta["chunks"].values():
            m = max(m, chunk["offset"] + chunk["padded-length"])

        self.buf.seek(m)

        return meta


@module.register
class BlendModule(module.RuminantModule):
    dev = True
    desc = "Blender project files, currently kinda broken."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(7) == b"BLENDER"

    def r16(self):
        match self.mode:
            case "le32" | "le64":
                return self.buf.ru16l()
            case "be32" | "be64":
                return self.buf.ru16()

    def r32(self):
        match self.mode:
            case "le32" | "le64":
                return self.buf.ru32l()
            case "be32" | "be64":
                return self.buf.ru32()

    def rptr(self):
        match self.mode:
            case "le32":
                return self.buf.ru32l()
            case "le64":
                return self.buf.ru64l()
            case "be32":
                return self.buf.ru32()
            case "be64":
                return self.buf.ru64()

    def rptrh(self):
        return hex(self.rptr())[2:].zfill(8 if "32" in self.mode else 16)

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "blend"
        self.buf.skip(7)
        meta["mode"] = {"_v": "le32", "_V": "be32", "-v": "le64", "-V": "be64"}[self.buf.rs(2)]
        self.mode = meta["mode"]
        meta["version"] = int(self.buf.rs(3))

        meta["blocks"] = []
        while self.buf.available() > 0:
            block = {}
            block["type"] = self.buf.rs(4)
            block["size"] = self.r32()
            block["ptr"] = self.rptrh()
            block["sdna-index"] = self.r32()
            block["count"] = self.r32()

            self.buf.pasunit(block["size"])

            block["data"] = {}
            match block["type"]:
                case "DNA1":
                    self.buf.skip(4)
                    block["data"]["sections"] = []

                    with self.buf.subunit():
                        while self.buf.available() > 0:
                            section = {}
                            section["name"] = self.buf.rs(4)
                            section["data"] = {}

                            match section["name"]:
                                case "NAME" | "TYPE":
                                    section["data"]["count"] = self.r32()
                                    section["data"]["strings"] = [self.buf.rzs() for i in range(0, section["data"]["count"])]
                                case "TLEN":
                                    count = 0
                                    for s in block["data"]["sections"]:
                                        if s["name"] == "TYPE":
                                            count = len(s["data"]["strings"])
                                            break

                                    section["data"]["sizes"] = [self.r16() for i in range(0, count)]
                                case _:
                                    section["unknown"] = True
                                    self.buf.skip(self.buf.available())

                            block["data"]["sections"].append(section)
                            while self.buf.tell() % 4 != 0:
                                self.buf.skip(1)
                case _:
                    block["unknown"] = True
                    with self.buf.subunit():
                        block["data"]["blob"] = chew(self.buf)

            self.buf.sapunit()
            meta["blocks"].append(block)

        return meta


@module.register
class GitModule(module.RuminantModule):
    desc = "Git-related files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 6:
            return False

        if buf.peek(4) not in (b"blob", b"tree", b"comm"):
            return False

        try:
            with buf:
                line = buf.rzs()
                line = line.split(" ")
                assert len(line) == 2
                assert line[0] in ("blob", "tree", "commit")
                int(line[1])
                return True
        except Exception:
            return False

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "git"

        line = self.buf.rzs().split(" ")
        meta["header"] = {}
        meta["header"]["type"] = line[0]
        meta["header"]["length"] = int(line[1])

        self.buf.pasunit(meta["header"]["length"])

        match meta["header"]["type"]:
            case "tree":
                meta["data"] = []
                while self.buf.hasunit():
                    line = self.buf.rzs().split(" ")
                    meta["data"].append({
                        "filename": line[1],
                        "mode": line[0],
                        "sha1": self.buf.rh(20),
                    })
            case "blob":
                with self.buf.subunit():
                    meta["data"] = chew(self.buf)
            case "commit":
                meta["data"] = {}
                meta["data"]["header"] = []
                while True:
                    line = utils.decode(self.buf.rl())
                    if line == "":
                        break

                    if line.startswith("gpgsig"):
                        line += "\n" + utils.decode(self.buf.rl()).strip()

                        while not line.endswith("-----"):
                            line += "\n" + utils.decode(self.buf.rl()).strip()

                    line = line.split(" ")
                    meta["data"]["header"].append({
                        "key": line[0],
                        "value": " ".join(line[1:]),
                    })

                meta["data"]["commit-message"] = self.buf.rs(self.buf.unit).strip().split("\n")

                for header in meta["data"]["header"]:
                    match header["key"]:
                        case "gpgsig":
                            header["parsed"] = chew(header["value"].encode("utf-8"))
                        case "author" | "committer":
                            header["parsed"] = {}
                            line = header["value"].split(" ")
                            header["parsed"]["name"] = " ".join(line[:-3])
                            header["parsed"]["email"] = line[-3][1:-1]
                            header["parsed"]["timestamp"] = utils.unix_to_date(int(line[-2]))
                            header["parsed"]["timezone"] = line[-1]

        self.buf.sapunit()

        return meta


@module.register
class OpenTimestampsProofModule(module.RuminantModule):
    desc = "OpenTimestamps Proof files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(31) == b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"

    def read_op(self):
        op = {}
        opcode = self.buf.ru8()

        match opcode:
            case 0x00:
                op["type"] = "attestation"
                op["size"] = None
                op["payload"] = {}
                op["payload"]["attestation-type"] = utils.unraw(
                    self.buf.ru64(),
                    8,
                    {
                        0x83dfe30d2ef90c8e: "Pending",
                        0x0588960d73d71901: "BitcoinBlockHeader",
                    },
                    True,
                )

                op["size"] = self.buf.ruleb()
                self.buf.pasunit(op["size"])

                match op["payload"]["attestation-type"]:
                    case "Pending":
                        op["payload"]["uri"] = self.buf.rs(self.buf.ruleb())
                    case "BitcoinBlockHeader":
                        op["payload"]["block-height"] = self.buf.ruleb()
                    case _:
                        op["payload"]["raw"] = self.buf.rh(self.buf.unit)

                self.buf.sapunit()
            case 0x08:
                op["type"] = "sha256"
            case 0xf0:
                op["type"] = "append"
                op["size"] = self.buf.ruleb()
                op["payload"] = self.buf.rh(op["size"])
            case 0xf1:
                op["type"] = "prepend"
                op["size"] = self.buf.ruleb()
                op["payload"] = self.buf.rh(op["size"])
            case 0xff:
                op["type"] = "fork"
                op["payload"] = {}
                op["payload"]["children"] = []
            case _:
                raise ValueError(f"Unknown opcode (0x{hex(opcode)[2:].zfill(2)})")

        return op

    def read_ops(self):
        ops = []

        level = 1
        while level > 0:
            ops.append(self.read_op())
            if ops[-1]["type"] == "attestation":
                level -= 1
            elif ops[-1]["type"] == "fork":
                level += 1

        root = []

        tree = root
        stack = [tree]
        while len(ops):
            elem = ops.pop(0)
            tree.append(elem)

            if elem["type"] == "fork":
                stack.append(tree)
                tree = []
                elem["payload"]["children"] = tree
            elif elem["type"] == "attestation":
                tree = stack.pop()

        return root

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "opentimestamps-proof"

        self.buf.skip(31)
        meta["version"] = self.buf.ru8()

        match meta["version"]:
            case 0x01:
                meta["file-hash-op"] = self.read_op()
                meta["file-hash"] = self.buf.rh({"sha256": 32}[meta["file-hash-op"]["type"]])
                meta["timestamp"] = self.read_ops()
            case _:
                meta["unknown"] = True

        return meta


@module.register
class JavaSerializationData(module.RuminantModule):
    desc = "Java serialization data as produced by java.io.ObjectOutputStream and similar classes."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(3) == b"\xac\xed\x00"

    def handle(self, obj):
        obj["data"]["handle"] = self.index
        self.handles[self.index] = obj
        self.index += 1

    def resolve(self, obj):
        if obj["type"] == "reference":
            return self.handles[obj["data"]["handle"]]

        return obj

    def read_type(self, typ):
        match typ:
            case "Z":
                val = bool(self.buf.ru8())
            case "F":
                val = self.buf.rf32()
            case "D":
                val = self.buf.rf64()
            case "B":
                val = self.buf.ri8()
            case "S":
                val = self.buf.ri16()
            case "C":
                val = chr(self.buf.ru16())
            case "I":
                val = self.buf.ri32()
            case "J":
                val = self.buf.ri64()
            case "L" | "[":
                val = self.read_element()
            case _:
                raise ValueError(f"Unknown classdata type {typ}")

        return val

    def read_classdesc_data(self, obj, classdata):
        fields = []
        head = obj
        while head["type"] != "null":
            head = self.resolve(head)
            fields.insert(0, head["data"]["fields"])
            head = head["data"]["super"]

        _fields = []
        for group in fields:
            _fields += group
        fields = _fields

        for field in fields:
            classdata[field["name"]] = self.read_type(field["type"])

    def debug_print(self, name):
        print("    " * self.level + name + " (" + str(self.buf.tell()) + ")")

    def read_element(self):
        if debug:
            self.level += 1

        tc = self.buf.ru8()
        obj = {}
        obj["type"] = None
        obj["data"] = {}

        match tc:
            case 0x70:
                obj["type"] = "null"
                if debug:
                    self.debug_print(obj["type"])
            case 0x71:
                obj["type"] = "reference"
                if debug:
                    self.debug_print(obj["type"])
                obj["data"]["handle"] = self.buf.ru32() - 0x7e0000
            case 0x72:
                obj["type"] = "classdesc"
                if debug:
                    self.debug_print(obj["type"])
                obj["data"]["name"] = self.buf.rs(self.buf.ru16())
                obj["data"]["serial-version-uid"] = self.buf.rh(8)
                self.handle(obj)
                obj["data"]["flags"] = utils.unpack_flags(
                    self.buf.ru8(),
                    (
                        (0, "WRITE_METHOD"),
                        (1, "SERIALIZABLE"),
                        (2, "EXTERNALIZABLE"),
                        (3, "BLOCK_DATA"),
                        (4, "ENUM"),
                    ),
                )
                obj["data"]["fields"] = []
                for i in range(0, self.buf.ru16()):
                    field = {}
                    field["type"] = self.buf.rs(1)
                    field["name"] = self.buf.rs(self.buf.ru16())
                    if field["type"] in "L[":
                        field["class-name"] = self.read_element()

                    obj["data"]["fields"].append(field)
                obj["data"]["annotation"] = []
                while True:
                    obj2 = self.read_element()
                    if obj2["type"] == "endblockdata":
                        break

                    obj["data"]["annotation"].append(obj2)
                obj["data"]["super"] = self.read_element()

            case 0x73:
                obj["type"] = "object"
                if debug:
                    self.debug_print(obj["type"])
                obj["data"]["classdesc"] = self.resolve(self.read_element())
                self.handle(obj)

                obj["data"]["classdata"] = {}
                if "SERIALIZABLE" in obj["data"]["classdesc"]["data"]["flags"]["names"]:
                    self.read_classdesc_data(obj["data"]["classdesc"], obj["data"]["classdata"])

                    if "WRITE_METHOD" in obj["data"]["classdesc"]["data"]["flags"]["names"]:
                        obj["data"]["object-annotation"] = []
                        while True:
                            obj2 = self.read_element()
                            if obj2["type"] == "endblockdata":
                                break

                            obj["data"]["object-annotation"].append(obj2)
                elif (
                    "EXTERNALIZABLE" in obj["data"]["classdesc"]["data"]["flags"]["names"]
                    and "BLOCK_DATA" not in obj["data"]["classdesc"]["data"]["flags"]["names"]
                ):
                    raise ValueError(f"Invalid state for flags: {obj['data']['flags']['names']}")
                elif (
                    "EXTERNALIZABLE" in obj["data"]["classdesc"]["data"]["flags"]["names"]
                    and "BLOCK_DATA" in obj["data"]["classdesc"]["data"]["flags"]["names"]
                ):
                    raise ValueError(f"Invalid state for flags: {obj['data']['flags']['names']}")
                else:
                    raise ValueError("Invalid state for flags: {obj['data']['classdesc']['data']['flags']['names']}")

            case 0x74:
                obj["type"] = "string"
                self.handle(obj)
                obj["data"]["payload"] = self.buf.rs(self.buf.ru16())
                if debug:
                    self.debug_print(obj["type"] + " " + obj["data"]["payload"])
            case 0x75:
                obj["type"] = "array"
                if debug:
                    self.debug_print(obj["type"])
                obj["data"]["classdesc"] = self.resolve(self.read_element())
                self.handle(obj)
                obj["data"]["values"] = []

                if (
                    len(obj["data"]["classdesc"]["data"]["name"]) == 2
                    and obj["data"]["classdesc"]["data"]["name"][1] in "BCDFIJSZ"
                ):
                    typ = obj["data"]["classdesc"]["data"]["name"][1]
                    for i in range(0, self.buf.ru32()):
                        obj["data"]["values"].append(self.read_type(typ))
                else:
                    for i in range(0, self.buf.ru32()):
                        obj["data"]["values"].append(self.read_element())
            case 0x77:
                obj["type"] = "blockdata"
                if debug:
                    self.debug_print(obj["type"])
                obj["data"]["payload"] = self.buf.rh(self.buf.ru8())
            case 0x78:
                obj["type"] = "endblockdata"
                if debug:
                    self.debug_print(obj["type"])
            case _:
                raise ValueError(f"Unknown type 0x{hex(tc)[2:].zfill(2)}")

        if debug:
            self.level -= 1

        return obj

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "java-serialization"

        if debug:
            self.level = 0

        self.buf.skip(2)
        meta["version"] = self.buf.ru16()

        self.index = 0
        self.handles: dict = {}
        meta["elements"] = []
        while True:
            bak = self.buf.backup()

            try:
                meta["elements"].append(self.read_element())
            except Exception as e:
                if debug:
                    for handle in self.handles.values():
                        if handle["type"] == "classdesc":
                            print(handle["data"]["name"], handle)

                    raise e

                self.buf.restore(bak)
                break

        return meta


@module.register
class SafeTensorsModule(module.RuminantModule):
    desc = "Hugging Face Safetensors files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.pu64l() < buf.available() and buf.peek(10)[8:] == b'{"'

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "safetensors"

        meta["header"] = json.loads(self.buf.rs(self.buf.ru64l()))
        base = self.buf.tell()

        max_offset = 0
        meta["sections"] = {}
        for k, v in meta["header"].items():
            if "data_offsets" in v:
                self.buf.seek(v["data_offsets"][0] + base)
                with self.buf.sub(v["data_offsets"][1] - v["data_offsets"][0]):
                    meta["sections"][k] = chew(self.buf, blob_mode=True)

                max_offset = max(max_offset, v["data_offsets"][1])

        self.buf.seek(max_offset + base)

        return meta


@module.register
class GgufModule(module.RuminantModule):
    desc = "GGUF model files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"GGUF"

    def read_value(self, typ):
        match typ:
            case 0:
                return "uint8", self.buf.ru8()
            case 1:
                return "int8", self.buf.ri8()
            case 2:
                return "uint16", self.buf.ru16l() if self.little else self.buf.ru16()
            case 3:
                return "int16", self.buf.ri16l() if self.little else self.buf.ri16()
            case 4:
                return "uint32", self.buf.ru32l() if self.little else self.buf.ru32()
            case 5:
                return "int32", self.buf.ri32l() if self.little else self.buf.ri32()
            case 6:
                return "float32", self.buf.rf32()
            case 7:
                return "bool", bool(self.buf.ru8())
            case 8:
                return "string", self.rs()
            case 9:
                typ = self.buf.ru32l() if self.little else self.buf.ru32()
                vals = []
                name = None
                for i in range(0, self.buf.ru64l() if self.little else self.buf.ru64()):
                    name, val = self.read_value(typ)
                    vals.append(val)

                return "[" + name + "]", vals
            case 10:
                return "uint64", self.buf.ru64l() if self.little else self.buf.ru64()
            case 11:
                return "int64", self.buf.ri64l() if self.little else self.buf.ri64()
            case 12:
                return "float64", self.buf.rf64()
            case _:
                raise ValueError(f"Unknown value type {typ}")

    def rs(self):
        return self.buf.rs(self.buf.ru64l() if self.little else self.buf.ru64())

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "GGUF"

        meta["header"] = {}
        self.buf.skip(4)
        self.little = bool(self.buf.pu32l() & 0xffff)
        meta["header"]["version"] = self.buf.ru32l() if self.little else self.buf.ru32()
        meta["header"]["tensor-count"] = self.buf.ru64l() if self.little else self.buf.ru64()
        meta["header"]["metadata-count"] = self.buf.ru64l() if self.little else self.buf.ru64()

        alignment = 32
        meta["metadata"] = []
        for i in range(0, meta["header"]["metadata-count"]):
            entry = {}
            entry["key"] = self.rs()
            typ = self.buf.ru32l() if self.little else self.buf.ru32()
            entry["type"], entry["value"] = self.read_value(typ)

            if entry["key"] == "general.alignment":
                alignment = entry["value"]

            meta["metadata"].append(entry)

        meta["tensors"] = []
        max_offset = 0
        for i in range(0, meta["header"]["tensor-count"]):
            tensor = {}
            tensor["name"] = self.rs()
            tensor["dimension-count"] = self.buf.ru32l() if self.little else self.buf.ru32()
            tensor["dimensions"] = [
                (self.buf.ru64l() if self.little else self.buf.ru64()) for j in range(0, tensor["dimension-count"])
            ]
            tensor["type"] = utils.unraw(
                self.buf.ru32l() if self.little else self.buf.ru32(),
                4,
                {
                    0: "F32",
                    1: "F16",
                    2: "Q4_0",
                    3: "Q4_1",
                    4: "Q4_2",
                    5: "Q4_3",
                    6: "Q5_0",
                    7: "Q5_1",
                    8: "Q8_0",
                    9: "Q8_1",
                    10: "Q2_K",
                    11: "Q3_K",
                    12: "Q4_K",
                    13: "Q5_K",
                    14: "Q6_K",
                    15: "Q8_K",
                    16: "IQ2_XXS",
                    17: "IQ2_XS",
                    18: "IQ3_XXS",
                    19: "IQ1_S",
                    20: "IQ4_NL",
                    21: "IQ3_S",
                    22: "IQ2_S",
                    23: "IQ4_XS",
                    24: "I8",
                    25: "I16",
                    26: "I32",
                    27: "I64",
                    28: "F64",
                    29: "IQ1_M",
                    30: "BF16",
                    31: "Q4_0_4_4",
                    32: "Q4_0_4_8",
                    33: "Q4_0_8_8",
                    34: "TQ1_0",
                    35: "TQ2_0",
                    36: "IQ4_NL_4_4",
                    37: "IQ4_NL_4_8",
                    38: "IQ4_NL_8_8",
                    39: "MXFP4",
                },
                True,
            )
            tensor["offset"] = self.buf.ru64l()

            meta["tensors"].append(tensor)

        tensor = meta["tensors"][0]
        for t in meta["tensors"]:
            if t["offset"] >= tensor["offset"]:
                tensor = t

        max_offset = tensor["offset"]

        prod = 1
        for dim in tensor["dimensions"]:
            prod *= dim

        match tensor["type"]:
            case "F16":
                max_offset += 2 * prod
            case "F32":
                max_offset += 4 * prod

        self.buf.seek((self.buf.tell() + alignment - 1) % alignment)
        self.buf.seek(self.buf.tell() + max_offset)

        return meta


@module.register
class AcpiModule(module.RuminantModule):
    dev = True
    desc = "ACPI tables like the ones in /sys/firmware/acpi/tables."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 8:
            return False

        with buf:
            header = buf.rs(4)

            if header not in (
                "APIC",
                "BATB",
                "BGRT",
                "CDIT",
                "CRAT",
                "DSDT",
                "ECDT",
                "FACP",
                "FACS",
                "FPDT",
                "HPET",
                "IVRS",
                "MCFG",
                "POAT",
                "SDEV",
                "SSDT",
                "TPM2",
                "UEFI",
                "VFCT",
                "WSMT",
            ):
                return False

            if buf.ru32l() > buf.available() + 8:
                return False

        return True

    def read_pkglen(self):
        first = self.buf.ru8()
        length = first & 0x3f
        s = 6

        for i in range(first >> 6):
            length |= self.buf.ru8() << s
            s += 8

        return length

    def read_list(self):
        terms = []
        while self.buf.unit > 0:
            term = self.read_aml_op()
            terms.append(term)

            if term["code"].startswith("Unknown"):
                break

        return terms

    def read_namestring(self):
        name = ""

        if self.buf.pu8() == 0x5c:
            name += "\\"
            self.buf.skip(1)

        while self.buf.pu8() == 0x5e:
            name += "^"
            self.buf.skip(1)

        if self.buf.pu8() == 0x2e:
            self.buf.skip(1)
            name += self.buf.rs(8)
        elif self.buf.pu8() == 0x2f:
            self.buf.skip(1)
            count = self.buf.ru8()
            name += self.buf.rs(4 * count)
        else:
            name += self.buf.rs(4)

        return name

    def read_field(self):
        match self.buf.pu8():
            case 0x00:
                return {"type": "ReservedField", "length": self.read_pkglen()}
            case 0x01:
                return {
                    "type": "AccessField",
                    "access": utils.unraw(
                        self.buf.rb(2),
                        1,
                        {
                            0x00: "Normal",
                            0x01: "Bytes",
                            0x02: "RawBytes",
                            0x03: "RawProcessBytes",
                        },
                        True,
                    ),
                    "reserved": self.buf.rb(2),
                    "access-type": utils.unraw(
                        self.buf.rb(4),
                        1,
                        {
                            0x00: "Any",
                            0x01: "Byte",
                            0x02: "Word",
                            0x03: "DWord",
                            0x04: "QWord",
                            0x05: "Buffer",
                            0x06: "Reserved",
                        },
                        True,
                    ),
                    "access-attrib": utils.unraw(
                        self.buf.ru8(),
                        1,
                        {
                            0x02: "Quick",
                            0x04: "SendReceive",
                            0x06: "Byte",
                            0x08: "Word",
                            0x0a: "Block",
                            0x0c: "ProcessCall",
                            0x0d: "BlockProcessCall",
                        },
                        True,
                    ),
                }
            case 0x02 | 0x03:
                raise NotImplementedError()
            case _:
                return {
                    "type": "NamedField",
                    "name": self.buf.rs(4),
                    "length": self.read_pkglen(),
                }

    def read_address(self):
        addr = {}
        addr["address-space"] = utils.unraw(
            self.buf.ru8(),
            1,
            {
                0x00: "SystemMemory",
                0x01: "SystemIO",
                0x02: "PCI_Config",
                0x03: "EmbeddedControl",
                0x04: "SMBus",
                0x05: "System CMOS",
                0x06: "PciBarTarget",
                0x07: "IPMI",
                0x08: "GeneralPurposeIO",
                0x09: "GenericSerialBus",
                0x0a: "PCC",
            },
            True,
        )
        addr["register-bit-width"] = self.buf.ru8()
        addr["register-bit-offset"] = self.buf.ru8()
        addr["reserved2"] = self.buf.ru8()
        addr["address"] = "0x" + hex(self.buf.ru64l())[2:].zfill(16)
        return addr

    def read_aml_op(self):
        op = {}
        code = self.buf.ru8()
        if code == 0x5b:
            code = (code << 8) | self.buf.ru8()

        match code:
            case 0x00:
                op["code"] = "ZeroOp"
            case 0x01:
                op["code"] = "OneOp"
            case 0x08:
                op["code"] = "NameOp"

                op["name"] = self.read_namestring()
                op["ref"] = self.read_aml_op()
            case 0x0a:
                op["code"] = "BytePrefix"

                op["value"] = self.buf.ru8()
            case 0x0b:
                op["code"] = "WordPrefix"

                op["value"] = self.buf.ru16l()
            case 0x0c:
                op["code"] = "DWordPrefix"

                op["value"] = self.buf.ru32l()
            case 0x10:
                op["code"] = "ScopeOp"
                op["length"] = self.read_pkglen()
                self.buf.pasunit(op["length"] - 1)

                op["name"] = self.read_namestring()
                op["terms"] = self.read_list()

                self.buf.sapunit()
            case 0x11:
                op["code"] = "BufferOp"
                pos = self.buf.tell()
                op["length"] = self.read_pkglen()

                op["size"] = self.read_aml_op()
                op["values"] = self.buf.rh(
                    max(
                        0,
                        min(op["size"]["value"], op["length"] - (self.buf.tell() - pos)),
                    )
                )
            case 0x14:
                op["code"] = "MethodOp"
                op["length"] = self.read_pkglen()
                self.buf.pasunit(op["length"] - 1)

                op["name"] = self.read_namestring()
                op["sync-level"] = self.buf.rb(4)
                op["serialized"] = bool(self.buf.rb(1))
                op["argument-count"] = self.buf.rb(3)
                op["terms"] = self.read_list()

                self.buf.sapunit()
            case 0x15:
                op["code"] = "ExternalOp"

                op["name"] = self.read_namestring()
                op["object-type"] = utils.unraw(
                    self.buf.ru8(),
                    1,
                    {
                        0x00: "Zero",
                        0x01: "Device",
                        0x02: "Event",
                        0x03: "Mutex",
                        0x04: "Method",
                        0x05: "Processor",
                        0x06: "Region",
                        0x07: "PowerResource",
                        0x08: "ByteData",
                        0x09: "WordData",
                        0x0a: "DWordData",
                        0x0b: "StringData",
                        0x0c: "BufferData",
                        0x0d: "PackageData",
                        0x0e: "QWordData",
                        0x0f: "ThermalZone",
                    },
                    True,
                )
                op["argument-count"] = self.buf.ru8()
            case 0x68:
                op["code"] = "Arg0Op"
            case 0x69:
                op["code"] = "Arg1Op"
            case 0x6a:
                op["code"] = "Arg2Op"
            case 0x6b:
                op["code"] = "Arg3Op"
            case 0x6c:
                op["code"] = "Arg4Op"
            case 0x6d:
                op["code"] = "Arg5Op"
            case 0x6e:
                op["code"] = "Arg6Op"
            case 0x93:
                op["code"] = "LEqualOp"

                op["left"] = self.read_aml_op()
                op["right"] = self.read_aml_op()
            case 0xa0:
                op["code"] = "IfOp"
                op["length"] = self.read_pkglen()
                self.buf.pasunit(op["length"] - 1)

                op["arg"] = self.read_aml_op()
                op["terms"] = self.read_list()

                self.buf.sapunit()
            case 0x5b01:
                op["code"] = "MutexOp"

                op["name"] = self.read_namestring()
                op["reserved"] = self.buf.rb(4)
                op["sync-level"] = self.buf.rb(4)
            case 0x5b80:
                op["code"] = "OpRegionOp"

                op["name"] = self.read_namestring()
                op["region"] = utils.unraw(
                    self.buf.ru8(),
                    1,
                    {
                        0x00: "SystemMemory",
                        0x01: "SystemIO",
                        0x02: "PCI_Config",
                        0x03: "EmbeddedControl",
                        0x04: "SMBus",
                        0x05: "System CMOS",
                        0x06: "PciBarTarget",
                        0x07: "IPMI",
                        0x08: "GeneralPurposeIO",
                        0x09: "GenericSerialBus",
                        0x0a: "PCC",
                    },
                    True,
                )
                op["offset"] = self.read_aml_op()
                op["length"] = self.read_aml_op()
            case 0x5b81:
                op["code"] = "FieldOp"
                op["length"] = self.read_pkglen()
                self.buf.pasunit(op["length"] - 1)

                op["name"] = self.read_namestring()
                op["reserved"] = self.buf.rb(1)
                op["update-rule"] = utils.unraw(
                    self.buf.rb(2),
                    1,
                    {0x00: "Preserve", 0x01: "WriteAsOnes", 0x02: "WriteAsZeros"},
                    True,
                )
                op["lock-rule"] = bool(self.buf.rb(1))
                op["access-type"] = utils.unraw(
                    self.buf.rb(4),
                    1,
                    {
                        0x00: "Any",
                        0x01: "Byte",
                        0x02: "Word",
                        0x03: "DWord",
                        0x04: "QWord",
                        0x05: "Buffer",
                        0x06: "Reserved",
                    },
                    True,
                )
                op["fields"] = []
                while self.buf.unit > 0:
                    op["fields"].append(self.read_field())

                self.buf.sapunit()
            case _:
                op["code"] = f"Unknown (0x{hex(code)[2:].zfill(2)})"

        return op

    def read_aml(self):
        tbl = {}
        tbl["opcodes"] = self.read_list()

        return tbl

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "acpi"

        meta["table-name"] = self.buf.rs(4)
        meta["length"] = self.buf.ru32l()
        self.buf.pasunit(meta["length"] - 8)

        meta["version"] = self.buf.ru8()

        csum = self.buf.ru8()
        with self.buf:
            self.buf.resetunit()
            self.buf.seek(self.buf.tell() - 10)
            actual_csum = (0x100 - (sum(self.buf.read(meta["length"]))) + csum) & 0xff
            meta["checksum"] = {"value": csum, "correct": csum == actual_csum}

            if not meta["checksum"]["correct"]:
                meta["checksum"]["actual"] = actual_csum

        meta["oem-id"] = self.buf.rs(6)
        meta["oem-table-id"] = self.buf.rs(8)
        meta["oem-revision"] = self.buf.ru32l()
        meta["creator"] = self.buf.rs(4)
        meta["creator-revision"] = self.buf.ru32l()

        meta["data"] = {}
        match meta["table-name"]:
            case "DSDT" | "SSDT" | "PSDT" | "OSDT":
                meta["data"] = self.read_aml()
            case "UEFI":
                meta["data"]["identifier"] = self.buf.rguid()
                meta["data"]["data-offset"] = self.buf.ru16l()
                self.buf.skip(meta["data"]["data-offset"] - 54)

                with self.buf.subunit():
                    meta["data"]["blob"] = chew(self.buf)
            case "HPET":
                meta["data"]["hardware-rev-id"] = self.buf.ru8()
                meta["data"]["comparator-count"] = self.buf.rb(5)
                meta["data"]["counter-size"] = self.buf.rb(1)
                meta["data"]["reserved1"] = self.buf.rb(1)
                meta["data"]["legacy-replacement"] = self.buf.rb(1)
                meta["data"]["pci-vendor-id"] = utils.unraw(self.buf.ru16l(), 2, constants.PCI_VENDORS, True)
                meta["data"]["address"] = self.read_address()
                meta["data"]["hpet-number"] = self.buf.ru8()
                meta["data"]["minimum-tick"] = self.buf.ru16l()
                meta["data"]["page-protection"] = self.buf.ru8()
            case "BGRT":
                meta["data"]["version"] = self.buf.ru16l()
                meta["data"]["reserved"] = self.buf.rb(5)
                meta["data"]["orientation-degrees"] = ["0", "90", "180", "270"][self.buf.rb(2)]
                meta["data"]["displayed"] = bool(self.buf.rb(1))
                meta["data"]["image-type"] = (utils.unraw(self.buf.ru8(), 1, {0x00: "Bitmap"}, True),)
                meta["data"]["address"] = ("0x" + hex(self.buf.ru64l())[2:].zfill(16),)
                meta["data"]["x-offset"] = self.buf.ru32l()
                meta["data"]["y-offset"] = self.buf.ru32l()
            case "ECDT":
                meta["data"]["control-port"] = self.read_address()
                meta["data"]["data-port"] = self.read_address()
                meta["data"]["uid"] = self.buf.ru32l()
                meta["data"]["gpe"] = self.buf.ru8()
                meta["data"]["id"] = self.buf.rzs()
            case "WSMT":
                meta["data"]["flags"] = utils.unpack_flags(
                    self.buf.ru32l(),
                    (
                        (0, "FIXED_COMM_BUFFERS"),
                        (1, "COMM_BUFFER_NESTED_PTR_PROTECTION"),
                        (2, "SYSTEM_RESOURCE_PROTECTION"),
                    ),
                )
            case _:
                with self.buf.subunit():
                    meta["data"]["blob"] = chew(self.buf)
                meta["unknown"] = True

        self.buf.sapunit()
        return meta


@module.register
class BplistModule(module.RuminantModule):
    desc = "Apple binary property lists."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(8) == b"bplist00" and buf.available() >= 40

    def read_size(self, op):
        if op & 0x0f != 0x0f:
            return op & 0x0f

        return int.from_bytes(self.buf.read(2 ** (self.buf.ru8() & 0x0f)), "big")

    def rebuild(self, obj, objs):
        match obj["type"]:
            case "dict":
                value = {}
                for entry in obj["value"]:
                    value[self.rebuild(objs[entry["key"]], objs)] = self.rebuild(objs[entry["value"]], objs)

                return value
            case "array":
                return [self.rebuild(objs[x], objs) for x in obj["value"]]
            case _:
                return obj.get("value")

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "bplist"

        self.buf.seek(self.buf.available() - 32)
        meta["trailer"] = {}
        meta["trailer"]["reserved"] = self.buf.rh(5)
        meta["trailer"]["sort-version"] = self.buf.ru8()
        meta["trailer"]["offset-table-size"] = self.buf.ru8()
        meta["trailer"]["object-reference-size"] = self.buf.ru8()
        meta["trailer"]["object-count"] = self.buf.ru64()
        meta["trailer"]["top-object-offset"] = self.buf.ru64()
        meta["trailer"]["offset-table-offset"] = self.buf.ru64()

        objects = []
        for i in range(0, meta["trailer"]["object-count"]):
            self.buf.seek(meta["trailer"]["offset-table-offset"] + meta["trailer"]["offset-table-size"] * i)
            self.buf.seek(int.from_bytes(self.buf.read(meta["trailer"]["offset-table-size"]), "big"))

            obj: dict = {}
            obj["offset"] = self.buf.tell() - 8

            op = self.buf.ru8()
            match op >> 4:
                case 0b0000:
                    obj["type"] = {
                        0b0000: "null",
                        0b1000: "false",
                        0b1001: "true",
                        0b1111: "fill",
                    }.get(op & 0x0f, f"Unknown simple (0b{bin(op & 0x0f)[2:].zfill(4)})")
                    obj["value"] = {0b1000: False, 0b1001: True}.get(op & 0x0f)
                case 0b0001:
                    obj["type"] = "int"
                    obj["size"] = self.read_size(op)
                    obj["value"] = int.from_bytes(self.buf.read(2 ** obj["size"]), "big")
                case 0b0010:
                    obj["type"] = "real"
                    obj["size"] = self.read_size(op)

                    match obj["size"]:
                        case 2:
                            obj["value"] = self.buf.rf32()
                        case 3:
                            obj["value"] = self.buf.rf64()
                        case _:
                            obj["value"] = None
                            obj["unknown"] = True
                case 0b0011:
                    obj["type"] = "date"
                    val = self.buf.rf64()
                    obj["value"] = (
                        utils.unix_to_date(int(val) + 978307200)[:-6] + "." + str(val).split(".")[1].zfill(6)[:6] + "+00:00"
                    )
                case 0b0100:
                    obj["type"] = "data"
                    obj["size"] = self.read_size(op)
                    obj["value"] = self.buf.rh(obj["size"])
                case 0b0101:
                    obj["type"] = "ascii-string"
                    obj["size"] = self.read_size(op)
                    obj["value"] = self.buf.read(obj["size"]).decode("latin-1")
                case 0b0110:
                    obj["type"] = "unicode-string"
                    obj["size"] = self.read_size(op)
                    obj["value"] = self.buf.read(obj["size"] * 2).decode("utf-16be")
                case 0b1000:
                    obj["type"] = "uid"
                    obj["size"] = self.read_size(op)
                    obj["value"] = int.from_bytes(self.buf.read(obj["size"] + 1), "big")
                case 0b1010:
                    obj["type"] = "array"
                    obj["size"] = self.read_size(op)

                    obj["value"] = [
                        int.from_bytes(
                            self.buf.read(meta["trailer"]["object-reference-size"]),
                            "big",
                        )
                        for i in range(0, obj["size"])
                    ]
                case 0b1101:
                    obj["type"] = "dict"
                    obj["size"] = self.read_size(op)
                    keys = [
                        int.from_bytes(
                            self.buf.read(meta["trailer"]["object-reference-size"]),
                            "big",
                        )
                        for i in range(0, obj["size"])
                    ]
                    obj["value"] = [
                        {
                            "key": key,
                            "value": int.from_bytes(
                                self.buf.read(meta["trailer"]["object-reference-size"]),
                                "big",
                            ),
                        }
                        for key in keys
                    ]
                case _:
                    obj["type"] = f"Unknown (0b{bin(op >> 4)[2:].zfill(4)})"
                    obj["unknown"] = True

            objects.append(obj)

        meta["objects"] = objects
        meta["root"] = self.rebuild(objects[meta["trailer"]["top-object-offset"]], objects)

        self.buf.seek(self.buf.size())

        return meta


@module.register
class OsmPbfFormat(module.RuminantModule):
    desc = "OpenStreetMap protobuf files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 15:
            return False

        with buf:
            if buf.ru32() & 0xfffffff0 != 0:
                return False

            if buf.ru16() != 0x0a09:
                return False

            if buf.rs(9) != "OSMHeader":
                return False
        return True

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "osm-pbf"

        meta["blobs"] = []
        while self.buf.available() > 0:
            blob: dict = {}
            blob["header"] = {}
            blob["header"]["length"] = self.buf.ru32()

            self.buf.pasunit(blob["header"]["length"])

            blob["header"]["data"] = utils.read_protobuf(
                self.buf,
                self.buf.unit,
                True,
                {"keys": {1: "type", 2: "indexdata", 3: "datasize"}, 1: "utf-8"},
            )

            self.buf.sapunit()

            self.buf.pasunit(blob["header"]["data"]["datasize"])

            body = utils.read_protobuf(self.buf, self.buf.unit)
            blob["body-size"] = body[2]

            keys = list(body.keys())
            keys.remove(2)
            blob["compression"] = utils.unraw(
                keys[0],
                1,
                {
                    0x01: "raw",
                    0x03: "zlib",
                    0x04: "lzma",
                    0x05: "bzip2",
                    0x06: "lz4",
                    0x07: "zstd",
                },
                True,
            )

            content = body[keys[0]]
            match blob["compression"]:
                case "raw":
                    pass
                case "zlib":
                    content = zlib.decompress(content)
                case _:
                    blob["unknown"] = True

            if "unknown" not in blob:
                buf = Buf(content)
                # https://github.com/openstreetmap/OSM-binary/blob/master/osmpbf/osmformat.proto
                blob["data"] = utils.read_protobuf(
                    buf,
                    buf.available(),
                    True,
                    {
                        "OSMHeader": {
                            "keys": {
                                1: "bbox",
                                4: "required_features",
                                5: "optional_features",
                                16: "writingprogram",
                                17: "source",
                                32: "osmosis_replication_timestamp",
                                33: "osmosis_replication_sequence_number",
                                34: "osmosis_replication_base_url",
                            },
                            1: {
                                "keys": {1: "left", 2: "right", 3: "top", 4: "bottom"},
                                1: "s64",
                                2: "s64",
                                3: "s64",
                                4: "s64",
                            },
                            4: "utf-8",
                            5: "utf-8",
                            16: "utf-8",
                            17: "utf-8",
                            34: "utf-8",
                        },
                        "OSMData": {
                            "keys": {1: "stringtable", 2: "primitivegroup"},
                            1: {"keys": {1: "s"}, 1: "utf-8"},
                            2: {
                                "keys": {
                                    1: "nodes",
                                    2: "dense",
                                    3: "ways",
                                    4: "relations",
                                    5: "changesets",
                                },
                                1: {},
                                2: {
                                    "keys": {
                                        1: "id",
                                        5: "denseinfo",
                                        8: "lat",
                                        9: "lon",
                                        10: "keys_vals",
                                    },
                                    1: "i64",
                                    5: {
                                        "keys": {
                                            1: "version",
                                            2: "timestamp",
                                            3: "changeset",
                                            4: "uid",
                                            5: "user_sid",
                                            6: "visible",
                                        },
                                        1: "u32",
                                        2: "i64",
                                        3: "i64",
                                        4: "i32",
                                        5: "i32",
                                        6: "u8",
                                    },
                                    8: "i64",
                                    9: "i64",
                                    10: "u32",
                                },
                                3: {
                                    "keys": {
                                        1: "id",
                                        2: "keys",
                                        3: "vals",
                                        4: "info",
                                        8: "refs",
                                        9: "lat",
                                        10: "lon",
                                    },
                                    2: "u32",
                                    3: "u32",
                                    4: {
                                        "keys": {
                                            1: "version",
                                            2: "timestamp",
                                            3: "changeset",
                                            4: "uid",
                                            5: "user_sid",
                                            6: "visible",
                                        }
                                    },
                                    8: "i64",
                                    9: "i64",
                                    10: "i64",
                                },
                                4: {},
                                5: {},
                            },
                        },
                    }.get(blob["header"]["data"]["type"], {}),
                )

            self.buf.sapunit()

            meta["blobs"].append(blob)

        return meta


@module.register
class StlModule(module.RuminantModule):
    priority = 1
    desc = "STL 3D model files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        try:
            with buf:
                buf.skip(80)
                triangle_count = buf.ru32l()
                assert triangle_count > 0
                assert buf.available() >= triangle_count * 50

                for i in range(0, triangle_count):
                    buf.skip(12)

                    for i in range(0, 9):
                        value = buf.rf32l()
                        assert not math.isnan(value)
                        assert not math.isinf(value)
                        assert value >= -1e6
                        assert value <= 1e6

                    assert buf.ru16l() == 0

                return True

        except Exception:
            return False

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "stl"

        meta["header"] = self.buf.rs(80)
        meta["triangle-count"] = self.buf.ru32l()

        minv = [0.0, 0.0, 0.0]
        maxv = [0.0, 0.0, 0.0]
        for i in range(0, meta["triangle-count"]):
            self.buf.skip(12)

            for j in range(0, 3):
                v = (self.buf.rf32l(), self.buf.rf32l(), self.buf.rf32l())
                minv[0] = min(minv[0], v[0])
                minv[1] = min(minv[1], v[1])
                minv[2] = min(minv[2], v[2])
                maxv[0] = max(maxv[0], v[0])
                maxv[1] = max(maxv[1], v[1])
                maxv[2] = max(maxv[2], v[2])

            self.buf.skip(2)

        meta["bounding-box"] = [minv, maxv]

        return meta


@module.register
class AppleDoubleModule(module.RuminantModule):
    desc = "AppleDouble files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"\x00\x05\x16\x07"

    def chew(self) -> ruminant_types.JSON:
        # https://datatracker.ietf.org/doc/html/rfc1740#appendix-B
        meta: dict = {}
        meta["type"] = "apple-double"

        self.buf.skip(4)

        meta["version"] = f"{self.buf.ru16()}.{self.buf.ru16()}"
        meta["filler"] = self.buf.rs(16)
        meta["entry-count"] = self.buf.ru16()

        meta["entries"] = []
        for i in range(0, meta["entry-count"]):
            entry: dict = {}
            entry["id"] = self.buf.ru32()
            entry["offset"] = self.buf.ru32()
            entry["length"] = self.buf.ru32()
            entry["data"] = {}

            meta["entries"].append(entry)

        max_offset = self.buf.tell()

        if self.buf.peek(38)[34:] == b"ATTR":
            self.buf.skip(38)
            meta["debug-tag"] = self.buf.ru32()
            meta["total-size"] = self.buf.ru32()
            max_offset = max(max_offset, meta["total-size"])
            meta["data-offset"] = self.buf.ru32()
            meta["data-length"] = self.buf.ru32()
            meta["reserved"] = self.buf.rh(12)
            meta["flags"] = self.buf.ru16()
            meta["attribute-count"] = self.buf.ru16()

            meta["attributes"] = []
            for i in range(0, meta["attribute-count"]):
                attr = {}
                attr["offset"] = self.buf.ru32()
                attr["length"] = self.buf.ru32()
                attr["flags"] = self.buf.ru16()
                attr["name"] = self.buf.rs(self.buf.ru8())

                with self.buf:
                    self.buf.seek(attr["offset"])
                    attr["payload"] = self.buf.rs(attr["length"])

                meta["attributes"].append(attr)

        for entry in meta["entries"]:
            self.buf.seek(entry["offset"])
            self.buf.pasunit(entry["length"])

            match entry["id"]:
                case 2:
                    entry["id"] = "Resource"
                    entry["data"]["payload"] = self.buf.rh(self.buf.unit)
                case 9:
                    entry["id"] = "Finder Info"
                    entry["data"]["type"] = self.buf.rs(4)
                    entry["data"]["creator"] = self.buf.rs(4)
                    flags = self.buf.ru16()
                    entry["data"]["flags"] = utils.unpack_flags(
                        flags,
                        (
                            (0, "on-desktop"),
                            (5, "switch-launch"),
                            (6, "shared"),
                            (7, "no-inits"),
                            (8, "been-inited"),
                            (10, "custom-icon"),
                            (11, "stationary"),
                            (12, "name-locked"),
                            (13, "has-bundle"),
                            (14, "invisible"),
                            (15, "alias"),
                        ),
                    )
                    entry["data"]["color"] = (flags >> 1) & 0b111
                    entry["data"]["position"] = [self.buf.ru16() for i in range(0, 2)]
                    entry["data"]["folder"] = self.buf.ru16()
                    entry["data"]["icon-id"] = self.buf.ru16()
                    entry["data"]["unused"] = [self.buf.ru16() for i in range(0, 3)]
                    entry["data"]["script"] = self.buf.ri8()
                    entry["data"]["xflags"] = self.buf.ri8()
                    entry["data"]["comment"] = self.buf.ru16()
                    entry["data"]["put-away"] = self.buf.ru32()
                case _:
                    entry["id"] = f"Unknown (0x{hex(entry['id'])[2:].zfill(8)})"
                    entry["unknown"] = True

            self.buf.sapunit()

        for entry in meta["entries"]:
            max_offset = max(max_offset, entry["offset"] + entry["length"])

        self.buf.seek(max_offset)

        return meta


@module.register
class MicrosoftPrinterSettingsModule(module.RuminantModule):
    desc = "Microsoft printer settings files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 220:
            return False

        with buf:
            buf.seek(64)
            if buf.ru16l() != 0x0401:
                return False

            buf.seek(68)
            if buf.ru16l() != 220:
                return False

            return buf.size() >= buf.ru16l() + 220

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "printer-setting"

        meta["device-name"] = self.buf.rs(64, "utf-16le")
        meta["spec-version"] = self.buf.ru16l()
        meta["driver-version"] = self.buf.ru16l()
        meta["size"] = self.buf.ru16l()
        meta["driver-extra-size"] = self.buf.ru16l()
        meta["fields"] = self.buf.ru32l()
        meta["orientation"] = self.buf.ri16l()
        meta["paper-size"] = self.buf.ri16l()
        meta["paper-length"] = self.buf.ri16l()
        meta["paper-width"] = self.buf.ri16l()
        meta["scale"] = self.buf.ri16l()
        meta["copies"] = self.buf.ri16l()
        meta["default-source"] = self.buf.ri16l()
        meta["print-quality"] = self.buf.ri16l()
        meta["color"] = self.buf.ri16l()
        meta["duplex"] = self.buf.ri16l()
        meta["y-resolution"] = self.buf.ri16l()
        meta["tt-option"] = self.buf.ri16l()
        meta["collate"] = self.buf.ri16l()
        meta["form-name"] = self.buf.rs(64, "utf-16le")
        meta["log-pixels"] = self.buf.ru16l()
        meta["bits-per-pel"] = self.buf.ru32l()
        meta["pels-width"] = self.buf.ru32l()
        meta["pels-height"] = self.buf.ru32l()
        meta["display-flags"] = self.buf.ru32l()
        meta["display-frequency"] = self.buf.ru32l()
        meta["icm-method"] = self.buf.ru32l()
        meta["icm-intent"] = self.buf.ru32l()
        meta["media-type"] = self.buf.ru32l()
        meta["dither-type"] = self.buf.ru32l()
        meta["reserved1"] = self.buf.ru32l()
        meta["reserved2"] = self.buf.ru32l()
        meta["panning-width"] = self.buf.ru32l()
        meta["panning-height"] = self.buf.ru32l()

        self.buf.pasunit(meta["driver-extra-size"])

        with self.buf.subunit():
            meta["driver-extra"] = chew(self.buf, blob_mode=True)

        self.buf.sapunit()

        return meta
