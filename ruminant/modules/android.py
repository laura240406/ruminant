from .. import module, utils, ruminant_types
from ..buf import Buf
from . import chew


@module.register
class VbmetaModule(module.RuminantModule):
    desc = "vbmeta partitions from AVB."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"AVB0"

    # read a public key given the algorithm
    def read_pubkey(self, algo):
        key = {}

        match algo:
            # RSA is the only supported family right now
            case (
                "SHA256_RSA2048" | "SHA256_RSA4096" | "SHA256_RSA8192" | "SHA512_RSA2048" | "SHA512_RSA4096" | "SHA512_RSA8192"
            ):
                bits = self.buf.ru32()
                key["bits"] = bits
                key["n0inv"] = self.buf.ru32()
                key["modulus"] = int.from_bytes(self.buf.read((bits + 7) // 8)) & ((1 << bits) - 1)
                key["rrmodn"] = int.from_bytes(self.buf.read((bits + 7) // 8)) & ((1 << bits) - 1)

                n = key["modulus"]
                # check whether values are correct
                key["n0inv-correct"] = key["n0inv"] == 2**32 - pow(n, -1, 2**32)
                key["rrmodn-correct"] = key["rrmodn"] == 2 ** (key["bits"] * 2) % n

        return key

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "vbmeta"

        self.buf.skip(4)
        meta["header"] = {}
        meta["header"]["libavb-version"] = f"{self.buf.ru32()}.{self.buf.ru32()}"
        meta["header"]["authentication-data-block-size"] = self.buf.ru64()
        meta["header"]["auxiliary-data-block-size"] = self.buf.ru64()
        # signature algorithm
        meta["header"]["algorithm-type"] = utils.unraw(
            self.buf.ru32(),
            4,
            {
                0x00: "NONE",
                0x01: "SHA256_RSA2048",
                0x02: "SHA256_RSA4096",
                0x03: "SHA256_RSA8192",
                0x04: "SHA512_RSA2048",
                0x05: "SHA512_RSA4096",
                0x06: "SHA512_RSA8192",
            },
        )
        meta["header"]["hash-offset"] = self.buf.ru64()
        meta["header"]["hash-size"] = self.buf.ru64()
        meta["header"]["signature-offset"] = self.buf.ru64()
        meta["header"]["signature-size"] = self.buf.ru64()
        meta["header"]["public-key-offset"] = self.buf.ru64()
        meta["header"]["public-key-size"] = self.buf.ru64()
        meta["header"]["public-key-metadata-offset"] = self.buf.ru64()
        meta["header"]["public-key-metadata-size"] = self.buf.ru64()
        meta["header"]["descriptors-offset"] = self.buf.ru64()
        meta["header"]["descriptors-size"] = self.buf.ru64()
        temp = self.buf.ru64()
        # rollback index to prevent downgrades
        # it's supposed to be an incrementing integer
        # Google uses the unix timestamp as it increments with time and also specifies the signing date
        meta["header"]["rollback-index"] = {
            "raw": temp,
            "date": utils.unix_to_date(temp),
        }
        # flags are unused right now
        meta["header"]["flags"] = utils.unpack_flags(self.buf.ru32(), [])
        meta["header"]["rollback-index-location"] = self.buf.ru32()
        meta["header"]["release-string"] = self.buf.rs(48)
        # unused right now, room for extension
        meta["header"]["padding"] = chew(self.buf.read(128), blob_mode=True)

        meta["authentication-data-block"] = {}
        self.buf.seek(256 + meta["header"]["hash-offset"])
        meta["authentication-data-block"]["hash"] = self.buf.rh(meta["header"]["hash-size"])
        self.buf.seek(256 + meta["header"]["signature-offset"])
        meta["authentication-data-block"]["signature"] = self.buf.rh(meta["header"]["signature-size"])

        meta["auxiliary-data-block"] = {}

        self.buf.seek(256 + meta["header"]["authentication-data-block-size"] + meta["header"]["descriptors-offset"])
        self.buf.pasunit(meta["header"]["descriptors-size"])

        # these are now kind of key-value pairs
        meta["auxiliary-data-block"]["descriptors"] = []
        while self.buf.hasunit():
            tag: dict = {}
            typ = self.buf.ru64()
            tag["type"] = None
            tag["length"] = self.buf.ru64()
            tag["payload"] = {}

            self.buf.pasunit(tag["length"])
            match typ:
                # key-value pair
                case 0x00:
                    tag["type"] = "PROPERTY"
                    klen = self.buf.ru64()
                    vlen = self.buf.ru64()
                    tag["payload"]["key"] = self.buf.rs(klen)
                    self.buf.skip(1)
                    tag["payload"]["value"] = self.buf.rs(vlen)
                    self.buf.skip(1)
                # dm-verity hash tree for partition with optional forward error correction
                case 0x01:
                    tag["type"] = "HASHTREE"
                    tag["payload"]["dm-verity-version"] = self.buf.ru32()
                    tag["payload"]["image-size"] = self.buf.ru64()
                    tag["payload"]["tree-offset"] = self.buf.ru64()
                    tag["payload"]["tree-size"] = self.buf.ru64()
                    tag["payload"]["data-block-size"] = self.buf.ru32()
                    tag["payload"]["hash-block-size"] = self.buf.ru32()
                    tag["payload"]["fec-num-roots"] = self.buf.ru32()
                    tag["payload"]["fec-offset"] = self.buf.ru64()
                    tag["payload"]["fec-size"] = self.buf.ru64()
                    tag["payload"]["hash-name"] = self.buf.rs(32)
                    tag["payload"]["partition-name-length"] = self.buf.ru32()
                    tag["payload"]["salt-length"] = self.buf.ru32()
                    tag["payload"]["root-digest-length"] = self.buf.ru32()
                    tag["payload"]["flags"] = utils.unpack_flags(self.buf.ru32(), [])
                    tag["payload"]["reserved"] = chew(self.buf.read(60), blob_mode=True)
                    tag["payload"]["partition-name"] = self.buf.rs(tag["payload"]["partition-name-length"])
                    tag["payload"]["salt"] = self.buf.rh(tag["payload"]["salt-length"])
                    tag["payload"]["root-digest"] = self.buf.rh(tag["payload"]["root-digest-length"])
                # root hash for partition
                case 0x02:
                    tag["type"] = "HASH"
                    tag["payload"]["image-size"] = self.buf.ru64()
                    tag["payload"]["hash-name"] = self.buf.rs(32)
                    tag["payload"]["partition-name-length"] = self.buf.ru32()
                    tag["payload"]["salt-length"] = self.buf.ru32()
                    tag["payload"]["root-digest-length"] = self.buf.ru32()
                    tag["payload"]["reserved"] = chew(self.buf.read(64), blob_mode=True)
                    tag["payload"]["partition-name"] = self.buf.rs(tag["payload"]["partition-name-length"])
                    tag["payload"]["salt"] = self.buf.rh(tag["payload"]["salt-length"])
                    tag["payload"]["root-digest"] = self.buf.rh(tag["payload"]["root-digest-length"])
                # command line for Linux kernel, seems to be baked into the kernel nowadays so unused
                case 0x03:
                    tag["type"] = "KERNEL_CMDLINE"
                    tag["payload"]["flags"] = utils.unpack_flags(self.buf.ru32(), [])
                    tag["payload"]["cmdline"] = self.buf.rs(self.buf.ru32())
                # chain partition signed by other key
                case 0x04:
                    tag["type"] = "CHAIN_PARTITION"
                    tag["payload"]["rollback-index-location"] = self.buf.ru32()
                    tag["payload"]["parition-name-length"] = self.buf.ru32()
                    tag["payload"]["public-key-length"] = self.buf.ru32()
                    tag["payload"]["flags"] = utils.unpack_flags(self.buf.ru32(), [])
                    tag["payload"]["reserved"] = chew(self.buf.read(60), blob_mode=True)
                    tag["payload"]["partition-name"] = self.buf.rs(tag["payload"]["parition-name-length"])
                    tag["payload"]["public-key"] = self.read_pubkey(meta["header"]["algorithm-type"]["name"])
                case _:
                    tag["type"] = f"UNKNOWN (0x{hex(typ)[2:].zfill(16)})"
                    tag["payload"]["blob"] = chew(self.buf.readunit())

            self.buf.sapunit()

            # align to 8 bytes
            if tag["length"] % 8:
                self.buf.skip(8 - (tag["length"] % 8))

            meta["auxiliary-data-block"]["descriptors"].append(tag)

        self.buf.sapunit()

        # images don't have to be signed so check
        if meta["header"]["public-key-size"]:
            self.buf.seek(256 + meta["header"]["authentication-data-block-size"] + meta["header"]["public-key-offset"])
            self.buf.pasunit(meta["header"]["public-key-size"])

            meta["auxiliary-data-block"]["public-key"] = self.read_pubkey(meta["header"]["algorithm-type"]["name"])
            # again, no other algorithm is supported right now
            if "RSA" in meta["header"]["algorithm-type"]["name"]:
                sig = pow(
                    int(meta["authentication-data-block"]["signature"], 16),
                    65537,
                    meta["auxiliary-data-block"]["public-key"]["modulus"],
                ).to_bytes(len(meta["authentication-data-block"]["signature"]) // 2, "big")
                sig = sig[2:].lstrip(b"\xff")[1:]
                meta["auxiliary-data-block"]["public-key"]["signature"] = utils.read_der(Buf(sig))

            self.buf.sapunit()

        # optional public key metadata
        if meta["header"]["public-key-metadata-size"]:
            self.buf.seek(256 + meta["header"]["authentication-data-block-size"] + meta["header"]["public-key-metadata-offset"])
            self.buf.pasunit(meta["header"]["public-key-metadata-size"])

            with self.buf.subunit():
                meta["auxiliary-data-block"]["public-key-metadata"] = chew(self.buf)

            self.buf.sapunit()

        # align to next page
        if self.buf.tell() % 4096:
            self.buf.skip(4096 - (self.buf.tell() % 4096))

        return meta


@module.register
class AndroidBootImgModule(module.RuminantModule):
    dev = True
    desc = "Android boot images"

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(8) == b"ANDROID!"

    # for addresses
    def hex(self, v):
        return {"raw": v, "hex": hex(v)}

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "android-bootimg"

        meta["header"] = {}
        self.buf.skip(40)
        meta["header"]["header-version"] = self.buf.ru32l()
        self.buf.seek(8)
        match meta["header"]["header-version"]:
            case 0:
                meta["header"]["kernel-size"] = self.buf.ru32l()
                meta["header"]["kernel-address"] = self.buf.ru32l()
                meta["header"]["ramdisk-size"] = self.buf.ru32l()
                meta["header"]["ramdisk-address"] = self.buf.ru32l()
                meta["header"]["second-size"] = self.buf.ru32l()
                meta["header"]["second-address"] = self.buf.ru32l()
                meta["header"]["tags-address"] = self.buf.ru32l()
                meta["header"]["page-size"] = self.buf.ru32l()
                meta["header"]["unused"] = self.buf.ru32l()
                meta["header"]["os-version"] = self.buf.ru32l()
                meta["header"]["name"] = self.buf.rs(16)
                meta["header"]["cmdline"] = self.buf.rs(512)
                meta["header"]["id"] = self.buf.rh(32)
                meta["header"]["extra-cmdline"] = self.buf.rs(1024)

                if self.buf.tell() % meta["header"]["page-size"]:
                    self.buf.skip(meta["header"]["page-size"] - (self.buf.tell() % meta["header"]["page-size"]))

                self.buf.pasunit(meta["header"]["kernel-size"])

                with self.buf.subunit():
                    meta["kernel"] = chew(self.buf)

                self.buf.sapunit()

                if self.buf.tell() % meta["header"]["page-size"]:
                    self.buf.skip(meta["header"]["page-size"] - (self.buf.tell() % meta["header"]["page-size"]))

                self.buf.pasunit(meta["header"]["ramdisk-size"])

                with self.buf.subunit():
                    meta["ramdisk"] = chew(self.buf)

                self.buf.sapunit()

                if self.buf.tell() % meta["header"]["page-size"]:
                    self.buf.skip(meta["header"]["page-size"] - (self.buf.tell() % meta["header"]["page-size"]))

                self.buf.pasunit(meta["header"]["second-size"])

                with self.buf.subunit():
                    meta["second"] = chew(self.buf)

                self.buf.sapunit()

                if self.buf.tell() % meta["header"]["page-size"]:
                    self.buf.skip(meta["header"]["page-size"] - (self.buf.tell() % meta["header"]["page-size"]))
            case 3 | 4:
                meta["header"]["kernel-size"] = self.buf.ru32l()
                meta["header"]["ramdisk-size"] = self.buf.ru32l()
                temp = self.buf.ru32l()
                meta["header"]["os-version"] = (
                    f"{(temp >> 25) & 0x7f}.{(temp >> 18) & 0x7f}.{(temp >> 11) & 0x7f} {((temp >> 4) & 0x7f) + 2000}-{str(temp & 0x0f).zfill(2)}"
                )
                meta["header"]["header-size"] = self.buf.ru32l()
                meta["header"]["reserved"] = self.buf.rh(16)
                self.buf.skip(4)
                meta["header"]["cmdline"] = self.buf.rs(1536)

                if meta["header"]["header-version"] == 4:
                    meta["header"]["signature-size"] = self.buf.ru32l()

                self.buf.seek(4096)
                self.buf.pasunit(meta["header"]["kernel-size"])

                with self.buf.subunit():
                    meta["kernel"] = chew(self.buf)

                self.buf.sapunit()
                while self.buf.tell() % 4096:
                    self.buf.skip(1)

                self.buf.pasunit(meta["header"]["ramdisk-size"])

                with self.buf.subunit():
                    meta["ramdisk"] = chew(self.buf)

                self.buf.sapunit()

                if self.buf.tell() % 4096:
                    self.buf.skip(4096 - (self.buf.tell() % 4096))
            case _:
                meta["unknown"] = True

        return meta
