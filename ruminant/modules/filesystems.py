from .. import module, utils, constants, ruminant_types
from ..buf import Buf
from . import chew
import zlib


@module.register
class BtrfsModule(module.RuminantModule):
    dev = True
    desc = "BTRFS filesystems."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 0x10000:
            return False

        with buf:
            buf.seek(0x10040)
            return buf.peek(8) == b"_BHRfS_M"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "btrfs"

        self.buf.seek(0x10000)
        meta["header"] = {}
        meta["header"]["checksum"] = self.buf.rh(32)
        meta["header"]["uuid"] = self.buf.ruuid()
        meta["header"]["header-paddr"] = self.buf.ru64l()
        meta["header"]["flags"] = self.buf.ru64l()
        self.buf.skip(8)
        meta["header"]["generation"] = self.buf.ru64l()
        meta["header"]["root-tree-laddr"] = self.buf.ru64l()
        meta["header"]["chunk-tree-laddr"] = self.buf.ru64l()
        meta["header"]["log-tree-laddr"] = self.buf.ru64l()
        meta["header"]["log-root-transid"] = self.buf.ru64l()
        meta["header"]["total-bytes"] = self.buf.ru64l()
        meta["header"]["bytes-used"] = self.buf.ru64l()
        meta["header"]["root-dir-object-id"] = self.buf.ru64l()
        meta["header"]["device-count"] = self.buf.ru64l()
        meta["header"]["sector-size"] = self.buf.ru32l()
        meta["header"]["node-size"] = self.buf.ru32l()
        meta["header"]["leaf-size"] = self.buf.ru32l()
        meta["header"]["stripe-size"] = self.buf.ru32l()
        meta["header"]["sys-chunk-array-size"] = self.buf.ru32l()
        meta["header"]["chunk-root-generation"] = self.buf.ru64l()
        meta["header"]["compat-flags"] = utils.unpack_flags(self.buf.ru64l(), constants.BTRFS_FLAGS)
        meta["header"]["compat-flags-ro"] = utils.unpack_flags(self.buf.ru64l(), constants.BTRFS_FLAGS)
        meta["header"]["incompat-flags"] = utils.unpack_flags(self.buf.ru64l(), constants.BTRFS_FLAGS)

        self.buf.seek(0)
        if meta["header"]["device-count"] == 1:
            self.buf.skip(meta["header"]["total-bytes"])
        else:
            self.buf.skip(self.buf.available())

        return meta


@module.register
class MbrGptModule(module.RuminantModule):
    desc = "MBR and GPT parition tables of drives."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if ctx["walk"]:
            return False

        if buf.available() < 512:
            return False

        return buf.peek(512)[510:] == b"\x55\xaa"

    def seek_lba(self, lba):
        self.buf.seek(self.bs * lba)

    def read_gpt(self):
        gpt = {}

        if self.buf.read(8) != b"EFI PART":
            gpt["invalid"] = True
            return gpt

        temp = self.buf.ru32l()
        gpt["revision"] = f"{temp >> 16}.{temp & 0xffff}"
        gpt["header-size"] = self.buf.ru32l()
        gpt["crc32"] = {
            "raw": self.buf.rh(4),
        }
        with self.buf:
            self.buf.seek(self.buf.tell() - 20)
            data = bytearray(self.buf.read(gpt["header-size"]))
            data[16] = 0
            data[17] = 0
            data[18] = 0
            data[19] = 0
            crc32 = zlib.crc32(data).to_bytes(4, "little").hex()
            gpt["crc32"]["correct"] = gpt["crc32"]["raw"] == crc32
            if not gpt["crc32"]["correct"]:
                gpt["crc32"]["actual"] = crc32
        gpt["reserved"] = self.buf.ru32l()
        gpt["current-lba"] = self.buf.ru64l()
        gpt["backup-lba"] = self.buf.ru64l()
        gpt["first-usable-lba"] = self.buf.ru64l()
        gpt["last-usable-lba"] = self.buf.ru64l()
        gpt["disk-guid"] = self.buf.rguid()
        gpt["partition-entries-lba"] = self.buf.ru64l()
        gpt["partition-entry-count"] = self.buf.ru32l()
        gpt["partition-entry-size"] = self.buf.ru32l()
        gpt["partition-entries-crc"] = {"raw": self.buf.rh(4)}

        self.seek_lba(gpt["partition-entries-lba"])
        crc32 = (
            zlib.crc32(self.buf.peek(gpt["partition-entry-size"] * gpt["partition-entry-count"])).to_bytes(4, "little").hex()
        )
        gpt["partition-entries-crc"]["correct"] = gpt["partition-entries-crc"]["raw"] == crc32
        if not gpt["partition-entries-crc"]["correct"]:
            gpt["partition-entries-crc"]["actual"] = crc32

        self.buf.pasunit(gpt["partition-entry-size"] * gpt["partition-entry-count"])
        gpt["partition-entries"] = []

        number = 0
        while self.buf.unit > 0:
            partition = {}
            self.buf.pasunit(gpt["partition-entry-size"])

            if sum(self.buf.peek(self.buf.unit)):
                temp = self.buf.rguid()
                partition["number"] = number
                partition["type"] = constants.GPT_TYPE_UUIDS.get(temp, f"Unknown ({temp})")
                partition["guid"] = self.buf.rguid()
                partition["first-lba"] = self.buf.ru64l()
                partition["last-lba"] = self.buf.ru64l()
                partition["flags"] = utils.unpack_flags(self.buf.ru64l(), ((60, "read-only"),))
                partition["name"] = self.buf.rs(self.buf.unit, "utf-16le")
                gpt["partition-entries"].append(partition)

            self.buf.sapunit()
            number += 1

        self.buf.sapunit()

        gpt["partitions"] = []
        for partition in gpt["partition-entries"]:
            self.seek_lba(partition["first-lba"])
            with self.buf.sub((partition["last-lba"] - partition["first-lba"] + 1) * self.bs):
                gpt["partitions"].append(chew(self.buf))

        return gpt

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "mbr-gpt"

        self.buf.pasunit(512)

        meta["mbr"] = {}
        meta["mbr"]["bootcode"] = self.buf.rh(440)
        meta["mbr"]["disk-id"] = hex(self.buf.ru32l())[2:].zfill(8)
        meta["mbr"]["copy-protected"] = self.buf.ru16l() == 0x5a5a
        meta["mbr"]["partition-entries"] = []

        number = 0
        for i in range(0, 4):
            partition = {}
            partition["number"] = number

            if sum(self.buf.peek(16)) == 0:
                continue
            number += 1

            partition["flags"] = utils.unpack_flags(self.buf.ru8(), ((7, "bootable"),))
            partition["start-chs"] = self.buf.rh(3)
            partition["parition-type"] = utils.unraw(
                self.buf.ru8(),
                1,
                {
                    0x00: "Empty / Unused",
                    0x01: "FAT12",
                    0x02: "XENIX root",
                    0x03: "XENIX usr",
                    0x04: "FAT16 (<32 MB)",
                    0x05: "Extended (CHS)",
                    0x06: "FAT16",
                    0x07: "NTFS / HPFS / exFAT",
                    0x0a: "OS/2 Boot Manager",
                    0x0b: "FAT32 (CHS)",
                    0x0c: "FAT32 (LBA)",
                    0x0e: "FAT16 (LBA)",
                    0x0f: "Extended (LBA)",
                    0x11: "Hidden FAT12",
                    0x12: "Hidden FAT16",
                    0x14: "Hidden FAT16 (<32 MB)",
                    0x16: "Hidden FAT16",
                    0x17: "Hidden NTFS",
                    0x1b: "Hidden FAT32",
                    0x1c: "Hidden FAT32 (LBA)",
                    0x1e: "Hidden FAT16 (LBA)",
                    0x27: "Windows Recovery Environment",
                    0x42: "Microsoft Dynamic Disk",
                    0x82: "Linux swap",
                    0x83: "Linux filesystem",
                    0x84: "Linux hibernation",
                    0x85: "Linux extended",
                    0x8e: "Linux LVM",
                    0xa5: "FreeBSD",
                    0xa6: "OpenBSD",
                    0xa8: "Apple UFS",
                    0xa9: "NetBSD",
                    0xab: "Apple boot",
                    0xac: "Apple RAID",
                    0xad: "Apple RAID offline",
                    0xae: "Apple Boot",
                    0xaf: "Apple HFS / HFS+",
                    0xbe: "Solaris boot",
                    0xbf: "Solaris",
                    0xda: "Non-FS data",
                    0xdb: "CP/M / Concurrent DOS",
                    0xe1: "SpeedStor",
                    0xe3: "SpeedStor FAT",
                    0xee: "GPT Protective MBR",
                    0xf2: "DOS secondary",
                    0xfb: "VMware VMFS",
                    0xfc: "VMware VMKCORE",
                },
                True,
            )
            partition["end-chs"] = self.buf.rh(3)
            partition["start-lba"] = self.buf.ru32l()
            partition["sector-count"] = self.buf.ru32l()

            meta["mbr"]["partition-entries"].append(partition)

        self.buf.sapunit()

        meta["mbr"]["partitions"] = []
        for partition in meta["mbr"]["partition-entries"]:
            try:
                self.buf.seek(partition["start-lba"] * 512)

                with self.buf.sub(partition["sector-count"] * 512):
                    meta["mbr"]["partitions"].append(chew(self.buf))
            except Exception:
                pass

        self.bs = None
        self.buf.seek(512)
        if self.buf.peek(8) == b"EFI PART":
            self.bs = 512
        else:
            self.buf.seek(4096)

            if self.buf.peek(8) == b"EFI PART":
                self.bs = 4096

        if self.bs:
            meta["block-size"] = self.bs
            meta["gpt"] = {}

            self.buf.seek(self.bs)
            meta["gpt"]["primary"] = self.read_gpt()

            self.buf.seek(self.buf.size() - self.bs)
            meta["gpt"]["secondary"] = self.read_gpt()

        self.buf.seek(self.buf.size())

        return meta


@module.register
class BtrfsSteamModule(module.RuminantModule):
    desc = "btrfs stream files generated by btrfs send."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(13) == b"btrfs-stream\x00"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "btrfs-stream"

        self.buf.skip(13)
        meta["version"] = self.buf.ru32l()

        meta["commands"] = []
        while self.buf.available() > 0:
            cmd: dict = {}
            cmd["length"] = self.buf.ru32l()
            cmd["type"] = utils.unraw(
                self.buf.ru16l(),
                2,
                {
                    0x0000: "UNSPEC",
                    0x0001: "SUBVOL",
                    0x0002: "SNAPSHOT",
                    0x0003: "MKFILE",
                    0x0004: "MKDIR",
                    0x0005: "MKNOD",
                    0x0006: "MKFIFO",
                    0x0007: "MKSOCK",
                    0x0008: "SYMLINK",
                    0x0009: "RENAME",
                    0x000a: "LINK",
                    0x000b: "UNLINK",
                    0x000c: "RMDIR",
                    0x000d: "SET_XATTR",
                    0x000e: "REMOVE_XATTR",
                    0x000f: "WRITE",
                    0x0010: "CLONE",
                    0x0011: "TRUNCATE",
                    0x0012: "CHMOD",
                    0x0013: "CHOWN",
                    0x0014: "UTIMES",
                    0x0015: "END",
                    0x0016: "UPDATE_EXTENT",
                    0x0017: "FALLOCATE",
                    0x0018: "FILEATTR",
                    0x0019: "ENCODED_WRITE",
                },
                True,
            )

            crc32c = self.buf.ru32l()
            with self.buf:
                self.buf.skip(-10)
                crc = 0

                for i in range(0, 6):
                    crc = constants.CRC32C_TABLE[(crc ^ self.buf.ru8()) & 0xff] ^ (crc >> 8)

                for i in range(0, 4):
                    self.buf.skip(1)
                    crc = constants.CRC32C_TABLE[crc & 0xff] ^ (crc >> 8)

                for i in range(0, cmd["length"]):
                    crc = constants.CRC32C_TABLE[(crc ^ self.buf.ru8()) & 0xff] ^ (crc >> 8)

            cmd["crc32c"] = {
                "value": hex(crc32c)[2:].zfill(8),
                "correct": crc32c == crc,
            }

            if not cmd["crc32c"]["correct"]:
                cmd["crc32c"]["actual"] = hex(crc)[2:].zfill(8)

            self.buf.pasunit(cmd["length"])

            cmd["values"] = []
            while self.buf.hasunit():
                value = {}
                typ = self.buf.ru16l()
                value["type"] = utils.unraw(
                    typ,
                    2,
                    {
                        0x0000: "UNSPEC",
                        0x0001: "UUID",
                        0x0002: "CTRANSID",
                        0x0003: "INO",
                        0x0004: "SIZE",
                        0x0005: "MODE",
                        0x0006: "UID",
                        0x0007: "GID",
                        0x0008: "RDEV",
                        0x0009: "CTIME",
                        0x000a: "MTIME",
                        0x000b: "ATIME",
                        0x000c: "OTIME",
                        0x000d: "XATTR_NAME",
                        0x000e: "XATTR_DATA",
                        0x000f: "PATH",
                        0x0010: "PATH_TO",
                        0x0011: "PATH_LINK",
                        0x0012: "FILE_OFFSET",
                        0x0013: "DATA",
                        0x0014: "CLONE_UUID",
                        0x0015: "CLONE_CTRANSID",
                        0x0016: "CLONE_PATH",
                        0x0017: "CLONE_OFFSET",
                        0x0018: "CLONE_LEN",
                        0x0019: "FALLOCATE_MODE",
                        0x001a: "FILEATTR",
                        0x001b: "UNENCODED_FILE_LEN",
                        0x001c: "UNENCODED_LEN",
                        0x001d: "UNENCODED_OFFSET",
                        0x001e: "COMPRESSION",
                        0x001f: "ENCRYPTION",
                    },
                    True,
                )
                value["length"] = self.buf.ru16l()

                self.buf.pasunit(value["length"])

                match typ:
                    # invalid
                    case 0x0000:
                        value["value"] = self.buf.rh(self.buf.unit)
                    # uuid
                    case 0x0001:
                        value["value"] = self.buf.ruuid()
                    # u64
                    case 0x0002 | 0x0003 | 0x0004 | 0x0006 | 0x0007 | 0x0008 | 0x0012 | 0x0015 | 0x0017 | 0x0018:
                        value["value"] = self.buf.ru64l()
                    # u64 octal
                    case 0x0005:
                        value["value"] = "0o" + oct(self.buf.ru64l())[2:].zfill(3)
                    case 0x0009 | 0x000a | 0x000b | 0x000c:
                        s = utils.unix_to_date(self.buf.ru64l()).split("+")
                        value["value"] = s[0] + "." + str(self.buf.ru32l()).zfill(9) + "+" + s[1]
                    # string
                    case 0x000d | 0x000f | 0x0010 | 0x0011 | 0x0016:
                        value["value"] = self.buf.rs(self.buf.unit)
                    # data (string)
                    case 0x000e:
                        value["value"] = self.buf.rs(self.buf.unit)
                    # data
                    case 0x0013:
                        with self.buf.subunit():
                            value["value"] = chew(self.buf, blob_mode=True)
                    case _:
                        value["unknown"] = True

                self.buf.sapunit()
                cmd["values"].append(value)

            self.buf.sapunit()
            meta["commands"].append(cmd)

        return meta
