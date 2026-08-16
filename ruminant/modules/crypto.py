from .. import module, utils, secrets, crypto, ruminant_types
from ..buf import Buf
from ..constants import AGE_DRAND_CHAINS
from . import chew
import base64
import hashlib
import json
import hmac
import gzip
from typing import cast


@module.register
class DerModule(module.RuminantModule):
    priority = 1
    desc = "ASN.1 DER binary files detected on a best-effort basis."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.pu8() == 0x30 and (buf.pu16() & 0xf0) in (0x80, 0x30)

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "der"

        meta["data"] = []
        while True:
            bak = self.buf.backup()

            try:
                meta["data"].append(utils.read_der(self.buf))
            except Exception:
                self.buf.restore(bak)
                break

        return meta


@module.register
class PemModule(module.RuminantModule):
    desc = "PEM encoded files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return (
            buf.peek(27) == b"-----BEGIN CERTIFICATE-----"
            or buf.peek(15) == b"-----BEGIN RSA "
            or buf.peek(26) == b"-----BEGIN PUBLIC KEY-----"
            or buf.peek(27) == b"-----BEGIN PRIVATE KEY-----"
            or buf.peek(30) == b"-----BEGIN EC PRIVATE KEY-----"
            or buf.peek(37) == b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
        )

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "pem"

        self.buf.rl()

        content = b""
        while True:
            line = self.buf.rl()
            if self.buf.available() == 0 or line.startswith(b"-----END"):
                break

            content += line

        while self.buf.peek(1) in (b"\r", b"\n"):
            self.buf.skip(1)

        meta["data"] = utils.read_der(Buf(base64.b64decode(content)))

        return meta


@module.register
class PgpModule(module.RuminantModule):
    desc = "Binary or armored PGP files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() > 4 and buf.pu8() in (0x85, 0x89) and buf.peek(4)[3] in (0x03, 0x04):
            return True

        return buf.peek(15) == b"-----BEGIN PGP "

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "pgp"

        if self.buf.peek(1) == b"-":
            if self.buf.rl() == b"-----BEGIN PGP SIGNED MESSAGE-----":
                message = b""

                meta["message-hash"] = self.buf.rl().split(b": ")[1].decode("utf-8")
                self.buf.rl()

                while True:
                    line = self.buf.rl()

                    if self.buf.available() == 0 or line == b"-----BEGIN PGP SIGNATURE-----":
                        break

                    message += line + b"\n"

                meta["message"] = utils.decode(message).split("\n")[:-1]

            content = b""
            while True:
                line = self.buf.rl()
                if self.buf.available() == 0 or line.startswith(b"-----END PGP "):
                    break

                if b":" in line:
                    continue

                content += line

            while self.buf.peek(1) in (b"\r", b"\n"):
                self.buf.skip(1)

            if b"=" in content:
                while content[-1] != b"="[0]:
                    content = content[:-1]

            fd = Buf(base64.b64decode(content))
        else:
            fd = self.buf

        meta["data"] = []
        while fd.available() > 0:
            meta["data"].append(utils.read_pgp(fd))

        return meta


@module.register
class KdbxModule(module.RuminantModule):
    desc = "KeePass database files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(8) == b"\x03\xd9\xa2\x9ag\xfbK\xb5"

    def walk_document(self, document, f):
        if "text" in document and document.get("attributes", {}).get("Protected", False):
            document["text"] = {
                "raw": document["text"],
                "decrypted": utils.decode(f(base64.b64decode(document["text"]))),
            }

            if document["text"]["decrypted"].startswith("-----BEGIN "):
                parsed = chew(document["text"]["decrypted"].encode("utf-8"))
                if parsed["type"] not in ("unknown", "error", "text"):
                    document["text"]["parsed"] = parsed
        elif document["tag"] == "Value" and "text" in document:
            parsed = chew(document["text"].encode("utf-8"))
            if parsed["type"] not in ("unknown", "error", "text"):
                document["text"] = {"raw": document["text"], "parsed": parsed}

        for child in document.get("children", ()):
            self.walk_document(child, f)

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "kdbx"

        self.buf.skip(8)
        version = self.buf.ru32l()
        meta["version"] = f"{version >> 16}.{version & 0xffff}"

        meta["fields"] = []
        running = True
        while running:
            field: dict = {}
            typ = self.buf.ru8()

            length = self.buf.ru32l()
            self.buf.pushunit()
            self.buf.setunit(length)

            match typ:
                case 0x00:
                    field["type"] = "End of header"
                    running = False
                case 0x02:
                    field["type"] = "Encryption algorithm"
                    uuid = utils.to_uuid(self.buf.read(16))
                    field["algorithm"] = {
                        "raw": uuid,
                        "name": {
                            "31c1f2e6-bf71-4350-be58-05216afc5aff": "AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding)",
                            "d6038a2b-8b6f-4cb5-a524-339a31dbb59a": "ChaCha20 (RFC 8439)",
                            "ad68f29f-576f-4bb9-a36a-d47af965346c": "Twofish",
                        }.get(uuid, "Unknown"),
                    }
                case 0x03:
                    field["type"] = "Compression algorithm"
                    field["algorithm"] = utils.unraw(self.buf.ru32l(), 4, {0: "No compression", 1: "GZip"})
                case 0x04:
                    field["type"] = "Master salt/seed"
                    field["salt"] = self.buf.rh(32)
                case 0x07:
                    field["type"] = "Encryption IV/nonce"
                    field["iv"] = self.buf.rh(self.buf.unit)
                case 0x0b | 0x0c:
                    field["type"] = {
                        0x0b: "KDF parameters",
                        0x0c: "Public custom data",
                    }.get(typ)

                    field["dict"] = {}
                    version = self.buf.ru16l()
                    field["dict"]["version"] = f"{version >> 8}.{version & 0xff}"

                    field["dict"]["entries"] = []

                    running2 = True
                    while running2:
                        entry: dict = {}
                        typ2 = self.buf.ru8()
                        if typ2 == 0x00:
                            entry["type"] = "end"
                            running2 = False
                        else:
                            entry["name"] = self.buf.rs(self.buf.ru32l())

                            length2 = self.buf.ru32l()

                            self.buf.pushunit()
                            self.buf.setunit(length2)

                            match typ2:
                                case 0x04:
                                    entry["type"] = "uint32"
                                    entry["data"] = self.buf.ru32l()
                                case 0x05:
                                    entry["type"] = "uint64"
                                    entry["data"] = self.buf.ru64l()
                                case 0x08:
                                    entry["type"] = "boolean"
                                    entry["data"] = bool(self.buf.ru8())
                                case 0x0c:
                                    entry["type"] = "int32"
                                    entry["data"] = self.buf.ri32l()
                                case 0x0d:
                                    entry["type"] = "int64"
                                    entry["data"] = self.buf.ri64l()
                                case 0x18:
                                    entry["type"] = "string"
                                    entry["data"] = self.buf.rs(self.buf.unit)
                                case 0x42:
                                    entry["type"] = "bytes"
                                    entry["data"] = self.buf.rh(self.buf.unit)
                                case _:
                                    entry["type"] = f"Unknown (0x{hex(typ2)[2:].zfill(2)})"

                            match entry["name"], entry["type"]:
                                case "$UUID", "bytes":
                                    entry["data"] = utils.to_uuid(bytes.fromhex(entry["data"]))
                                    entry["data"] = {
                                        "raw": entry["data"],
                                        "name": {
                                            "c9d9f39a-628a-4460-bf74-0d08c18a4fea": "AES-KDF",
                                            "ef636ddf-8c29-444b-91f7-a9a403e30a0c": "Argon2d",
                                            "9e298b19-56db-4773-b23d-fc3ec6f0a1e6": "Argon2id",
                                        }.get(entry["data"], "Unknown"),
                                    }

                            self.buf.skipunit()
                            self.buf.popunit()

                        field["dict"]["entries"].append(entry)
                case _:
                    field["type"] = f"Unknown (0x{hex(typ)[2:].zfill(2)})"

            self.buf.skipunit()
            self.buf.popunit()

            meta["fields"].append(field)

        meta["sha256"] = {}
        meta["sha256"]["value"] = self.buf.rh(32)
        with self.buf:
            length = self.buf.tell() - 32
            self.buf.seek(0)
            header_data = self.buf.read(length)
            sha256_hash = hashlib.sha256(header_data).hexdigest()

            meta["sha256"]["correct"] = meta["sha256"]["value"] == sha256_hash
            if not meta["sha256"]["correct"]:
                meta["sha256"]["actual"] = sha256_hash

        meta["hmac-sha256"] = self.buf.rh(32)

        meta["key"] = {
            "name": meta["hmac-sha256"],
            "found": secrets.get(meta["hmac-sha256"]) is not None,
            "can-decrypt": False,
        }

        mode = None
        params = {}
        master_seed = b""
        encryption_algorithm = None
        compression_algorithm = None
        iv = b""
        for field in meta["fields"]:
            if field["type"] == "KDF parameters" and field["dict"]["version"] == "1.0":
                for entry in field["dict"]["entries"]:
                    if entry["type"] == "end":
                        break

                    match entry["name"]:
                        case "$UUID":
                            mode = {"Argon2d": "2d", "Argon2id": "2id"}.get(entry["data"]["name"])
                        case "I" | "M" | "P" | "S" | "V":
                            params[entry["name"]] = entry["data"]
            elif field["type"] == "Master salt/seed":
                master_seed = bytes.fromhex(field["salt"])
            elif field["type"] == "Encryption algorithm":
                encryption_algorithm = {
                    "AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding)": "aes",
                    "ChaCha20 (RFC 8439)": "chacha20",
                }.get(field["algorithm"]["name"])
            elif field["type"] == "Encryption IV/nonce":
                iv = bytes.fromhex(field["iv"])
            elif field["type"] == "Compression algorithm":
                compression_algorithm = {"GZip": "gzip"}.get(field["algorithm"]["name"])

        T = None

        if (
            meta["key"]["found"]
            and mode in ("2d", "2id")
            and encryption_algorithm in ("aes", "chacha20")
            and compression_algorithm in (None, "gzip")
        ):
            meta["key"]["can-decrypt"] = True
            R = hashlib.sha256(hashlib.sha256(cast(str, secrets.get(meta["hmac-sha256"])).encode("utf8")).digest()).digest()
            T = crypto.argon2(
                R,
                bytes.fromhex(params["S"]),
                params["I"],
                params["M"] // 1024,
                params["P"],
                32,
                mode[1:],
                params["V"],
            )

        is_correct = False
        if T is not None:
            decyption_key = hashlib.sha256(master_seed + T).digest()
            header_hmac_key = hashlib.sha512(b"\xff" * 8 + hashlib.sha512(master_seed + T + b"\x01").digest()).digest()
            header_hmac = hmac.digest(header_hmac_key, header_data, "sha256")
            is_correct = header_hmac.hex() == meta["hmac-sha256"]

            meta["key"]["correct"] = is_correct

        if T is not None and is_correct:
            content = b""

            meta["block-count"] = 0
            meta["blocks"] = []
            while self.buf.available() > 0:
                block = {}
                block["hmac"] = self.buf.rh(32)
                block["length"] = self.buf.ru32l()
                content += self.buf.read(block["length"])

                block_hmac = hmac.digest(
                    hashlib.sha512(
                        meta["block-count"].to_bytes(8, "little") + hashlib.sha512(master_seed + T + b"\x01").digest()
                    ).digest(),
                    meta["block-count"].to_bytes(8, "little") + block["length"].to_bytes(4, "little") + content,
                    "sha256",
                )

                block["correct"] = block_hmac.hex() == block["hmac"]

                meta["block-count"] += 1
                meta["blocks"].append(block)

            match encryption_algorithm:
                case "aes":
                    content = crypto.aes_cbc_pkcs7(decyption_key, iv, content)
                case "chacha20":
                    content = crypto.chacha20(content, decyption_key, iv, 0)

            match compression_algorithm:
                case "gzip":
                    content = gzip.decompress(content)

            buf = Buf(content)
            meta["content"] = []

            inner_encryption_algorithm = None
            inner_key = b""
            should_break = False
            while buf.available() > 0 and not should_break:
                entry = {}
                entry["type"] = utils.unraw(
                    buf.ru8(),
                    1,
                    {
                        0x00: "End of header",
                        0x01: "Inner encryption algorithm",
                        0x02: "Inner encryption key",
                        0x03: "Binary content",
                    },
                    True,
                )
                entry["length"] = buf.ru32l()

                buf.pasunit(entry["length"])

                entry["payload"] = {}
                match entry["type"]:
                    case "End of header":
                        should_break = True
                    case "Inner encryption algorithm":
                        entry["payload"]["encryption-algorithm"] = utils.unraw(
                            buf.ru32l(),
                            4,
                            {0x00000002: "Salsa20", 0x00000003: "ChaCha20"},
                            True,
                        )

                        inner_encryption_algorithm = {"ChaCha20": "chacha20"}.get(entry["payload"]["encryption-algorithm"])
                    case "Inner encryption key":
                        inner_key = buf.read(buf.unit)
                        entry["payload"]["key"] = inner_key.hex()
                    case "Binary content":
                        entry["payload"]["flags"] = utils.unpack_flags(buf.ru8(), ((0, "binary"),))

                        with buf.subunit():
                            entry["payload"]["content"] = chew(buf)
                    case _:
                        with buf.subunit():
                            entry["payload"] = chew(buf)

                        entry["unknown"] = True

                buf.sapunit()
                meta["content"].append(entry)

            with buf.sub(buf.available()):
                meta["document"] = {"raw": chew(buf, blob_mode=True)}

            def f(x):
                return x

            # flake8 is stupid
            f(b"")

            match inner_encryption_algorithm:
                case "chacha20":
                    inner_key = hashlib.sha512(inner_key).digest()
                    index = 0

                    del f

                    def f(x):
                        nonlocal index

                        keystream = b""
                        for i in range(index // 64, (index + len(x) + 63) // 64):
                            keystream += crypto.chacha_block(
                                b"expand 32-byte k" + inner_key[:32] + i.to_bytes(4, "little") + inner_key[32:44]
                            )

                        payload = bytes([c ^ k for c, k in zip(x, keystream[index % 64 : (index % 64) + len(x)])])
                        index += len(x)
                        return payload

                    # flake8 is stupid
                    f(b"")

            document = utils.read_xml(buf)
            self.walk_document(document, f)
            meta["document"]["parsed"] = document
        else:
            meta["block-count"] = 0
            meta["blocks"] = []
            while self.buf.available() > 0:
                block = {}
                block["hmac"] = self.buf.rh(32)
                block["length"] = self.buf.ru32l()
                self.buf.skip(block["length"])

                meta["block-count"] += 1
                meta["blocks"].append(block)

        return meta


@module.register
class AgeModule(module.RuminantModule):
    desc = "age encrypted files including the tlock extension."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(34) == b"-----BEGIN AGE ENCRYPTED FILE-----" or buf.peek(20) == b"age-encryption.org/v"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "age"

        meta["data"] = {}
        meta["data"]["armored"] = self.buf.peek(1) == b"-"

        if meta["data"]["armored"]:
            self.buf.rl()

            content = b""
            while True:
                line = self.buf.rl()
                if line.startswith(b"----"):
                    break

                content += line

            content = base64.b64decode(content)
            return chew(content)

        self.buf.skip(20)
        meta["data"]["version"] = int(self.buf.rl())

        header_length = None
        match meta["data"]["version"]:
            case 1:
                meta["data"]["stanzas"] = []

                while True:
                    stanza = {}

                    pos = self.buf.tell()
                    line = self.buf.rl()
                    if line.startswith(b"---"):
                        header_length = pos + 3
                        meta["data"]["header-mac"] = {"value": base64.b64decode(line[4:] + b"==").hex()}
                        break

                    stanza["type"] = utils.decode(line).split(" ")[1]
                    stanza["arguments"] = {}
                    args = utils.decode(line).split(" ")[2:]
                    match stanza["type"]:
                        case "X25519":
                            stanza["arguments"]["ephemeral-share"] = args[0]
                        case "scrypt":
                            stanza["arguments"]["salt"] = base64.b64decode(args[0] + "==").hex()
                            stanza["arguments"]["work"] = 1 << int(args[1])
                        case "tlock":
                            stanza["arguments"]["round"] = int(args[0])
                            stanza["arguments"]["chain"] = args[1]

                            if stanza["arguments"]["chain"] in AGE_DRAND_CHAINS:
                                chain = AGE_DRAND_CHAINS[stanza["arguments"]["chain"]]
                                stanza["parsed"] = {}
                                stanza["parsed"]["chain-name"] = chain["name"]
                                stanza["parsed"]["decryption-time"] = utils.unix_to_date(
                                    chain["genesis"] + chain["period"] * (stanza["arguments"]["round"] - 1)
                                )
                        case _:
                            stanza["arguments"] = args
                            stanza["unknown"] = True

                    line = b""
                    while self.buf.peek(3) not in (b"---", b"-> "):
                        line += self.buf.rl()

                    stanza["wrapped-key"] = base64.b64decode(line + b"==").hex()

                    meta["data"]["stanzas"].append(stanza)

                file_key = None
                for stanza in meta["data"]["stanzas"]:
                    match stanza["type"]:
                        case "X25519":
                            name = hashlib.sha256(stanza["arguments"]["ephemeral-share"].encode("utf-8")).hexdigest()
                            key = secrets.get(name)

                            stanza["key"] = {"name": name, "found": key is not None}
                            if key is not None:
                                if not crypto.bech32_verify_checksum(cast(str, key)):
                                    stanza["key"]["correct"] = False
                                else:
                                    data_part = cast(str, key).split("1")[-1][:-6].lower()
                                    words = ["qpzry9x8gf2tvdw0s3jn54khce6mua7l".find(c) for c in data_part]
                                    priv = bytes(crypto.bech32_convertbits(words, 5, 8, pad=False))

                                    pub = crypto.curve25519(b"\x09" + bytes(31), priv)
                                    words = crypto.bech32_convertbits(pub, 8, 5)
                                    checksum = crypto.bech32_create_checksum("age", words)
                                    encoded_data = "".join(["qpzry9x8gf2tvdw0s3jn54khce6mua7l"[i] for i in words + checksum])
                                    recipient = "age1" + encoded_data
                                    stanza["recipient"] = recipient

                                    shared_secret = crypto.curve25519(
                                        base64.b64decode(stanza["arguments"]["ephemeral-share"] + "==="),
                                        priv,
                                    )
                                    wrap_key = crypto.hkdf_sha256(
                                        shared_secret,
                                        salt=base64.b64decode(stanza["arguments"]["ephemeral-share"] + "===") + pub,
                                        info=b"age-encryption.org/v1/X25519",
                                        length=32,
                                    )
                                    stanza["wrap-key"] = wrap_key.hex()

                                    try:
                                        file_key = crypto.chacha20_poly1305(
                                            bytes.fromhex(stanza["wrapped-key"])[:-16],
                                            wrap_key,
                                            bytes(12),
                                            bytes.fromhex(stanza["wrapped-key"])[-16:],
                                        )
                                        stanza["key"]["correct"] = True
                                    except AssertionError:
                                        stanza["key"]["correct"] = False
                        case "scrypt":
                            data = stanza["wrapped-key"].encode("utf-8")
                            for k, v in stanza["arguments"].items():
                                data += len(k).to_bytes(4, "little") + k.encode("utf-8")

                                match v.__class__.__name__:
                                    case "int":
                                        data += v.to_bytes(8, "little", signed=True)
                                    case "str":
                                        data += len(v).to_bytes(4, "little") + v.encode("utf-8")

                            name = hashlib.sha256(data).hexdigest()
                            key = secrets.get(name)

                            stanza["key"] = {"name": name, "found": key is not None}

                            if key is not None:
                                wrap_key = hashlib.scrypt(
                                    cast(str, key).encode("utf-8"),
                                    salt=b"age-encryption.org/v1/scrypt" + bytes.fromhex(stanza["arguments"]["salt"]),
                                    n=stanza["arguments"]["work"],
                                    r=8,
                                    p=1,
                                    maxmem=2**31 - 1,
                                    dklen=32,
                                )
                                stanza["wrap-key"] = wrap_key.hex()

                                try:
                                    file_key = crypto.chacha20_poly1305(
                                        bytes.fromhex(stanza["wrapped-key"])[:-16],
                                        wrap_key,
                                        bytes(12),
                                        bytes.fromhex(stanza["wrapped-key"])[-16:],
                                    )
                                    stanza["key"]["correct"] = True
                                except AssertionError:
                                    stanza["key"]["correct"] = False

                nonce = self.buf.read(16)
                meta["data"]["payload-nonce"] = nonce.hex()

                if file_key is not None:
                    meta["data"]["file-key"] = file_key.hex()
                    with self.buf:
                        self.buf.seek(0)
                        header_key = crypto.hkdf_sha256(file_key, info=b"header", length=32)
                        header_hmac = hmac.new(header_key, self.buf.read(header_length), hashlib.sha256).hexdigest()
                        meta["data"]["header-mac"]["correct"] = meta["data"]["header-mac"]["value"] == header_hmac
                        if not meta["data"]["header-mac"]["correct"]:
                            meta["data"]["header-mac"]["actual"] = header_hmac

                    payload_key = crypto.hkdf_sha256(file_key, salt=nonce, info=b"payload", length=32)
                    fd = utils.tempfd()
                    counter = 0
                    while self.buf.available() > 0:
                        block = self.buf.read(min(65536 + 16, self.buf.available()))
                        block, tag = block[:-16], block[-16:]
                        block = crypto.chacha20_poly1305(
                            block,
                            payload_key,
                            counter.to_bytes(11, "big") + (b"\x00" if self.buf.available() > 0 else b"\x01"),
                            tag,
                        )
                        fd.write(block)
                        counter += 1

                    fd.seek(0)
                    meta["data"]["payload"] = chew(fd)

                else:
                    meta["data"]["block-count"] = (self.buf.available() + 65536 + 15 - 16) // (65536 + 16)
                    self.buf.skip(self.buf.available())
            case _:
                meta["unknown"] = True

        return meta


@module.register
class LuksModule(module.RuminantModule):
    desc = "Linux Unified Key Setup version 1 and 2 headers."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(6) == b"LUKS\xba\xbe"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "luks"

        self.buf.skip(6)
        meta["header"] = {}
        meta["header"]["version"] = self.buf.ru16()

        match meta["header"]["version"]:
            case 1:
                meta["header"]["cipher-name"] = self.buf.rs(32)
                meta["header"]["cipher-mode"] = self.buf.rs(32)
                meta["header"]["hash-spec"] = self.buf.rs(32)
                meta["header"]["payload-offset"] = self.buf.ru32()
                meta["header"]["key-bytes"] = self.buf.ru32()
                meta["header"]["mk-digest"] = self.buf.rh(20)
                meta["header"]["mk-digest-salt"] = self.buf.rh(32)
                meta["header"]["mk-digest-iter"] = self.buf.ru32()
                meta["header"]["uuid"] = self.buf.rs(40)

                meta["header"]["key-slots"] = []
                for i in range(0, 8):
                    ks = {}
                    ks["active"] = utils.unraw(
                        self.buf.ru32(),
                        4,
                        {0x0000dead: "disabled", 0x00ac71f3: "enabled"},
                        True,
                    )
                    ks["iterations"] = self.buf.ru32()
                    ks["salt"] = self.buf.rh(32)
                    ks["key-material-offset"] = self.buf.ru32()
                    ks["stripes"] = self.buf.ru32()
                    meta["header"]["key-slots"].append(ks)

                self.buf.skip(self.buf.available())
            case 2:
                meta["header"]["header-length"] = self.buf.ru64()

                self.buf.pasunit(meta["header"]["header-length"] - 16)

                meta["header"]["sequence-id"] = self.buf.ru64()
                meta["header"]["label"] = self.buf.rs(48)
                meta["header"]["checksum-algorithm"] = self.buf.rs(32)
                meta["header"]["salt"] = self.buf.rh(64)
                meta["header"]["uuid"] = self.buf.rs(40)
                meta["header"]["subsystem"] = self.buf.rs(48)
                meta["header"]["header-offset"] = self.buf.ru64()
                self.buf.skip(184)
                meta["header"]["checksum"] = self.buf.rh(64)
                self.buf.skip(7 * 512)
                meta["json"] = json.loads(self.buf.rs(self.buf.unit))

                self.buf.sapunit()

                m = 0
                for _, v in meta["json"].get("segments", {}).items():
                    if v.get("size") == "dynamic":
                        m = self.buf.size() - int(v.get("offset", 0))
                        break

                    m = max(m, int(v.get("offset", 0)) + int(v.get("size", 0)))

                keys = {}
                for index, keyslot in meta["json"].get("keyslots", {}).items():
                    blob = keyslot["kdf"]["type"].encode("utf-8") + base64.b64decode(keyslot["kdf"].get("salt"))

                    try:
                        self.buf.seek(keyslot["area"]["offset"])
                        blob += self.buf.read(keyslot["area"]["size"])
                    except Exception:
                        pass

                    name = hashlib.sha256(blob).hexdigest()

                    key = secrets.get(name)
                    keyslot["key"] = {}
                    keyslot["key"]["name"] = name
                    keyslot["key"]["found"] = key is not None

                    if key is not None:
                        bkey = bytes.fromhex(cast(str, key))
                        keys[int(index)] = [bkey[: len(bkey) // 2], bkey[len(bkey) // 2 :]]

                for index, segment in meta["json"].get("segments", {}).items():
                    index = int(index)

                    if index in keys and segment.get("encryption") == "aes-xts-plain64":
                        self.buf.seek(int(segment["offset"]))
                        with self.buf.sub(segment["size"] if segment["size"] != "dynamic" else self.buf.available()):
                            buf = crypto.CryptoBuf(
                                self.buf,
                                crypto.aes_xts_plain64(
                                    keys[index][0],
                                    keys[index][1],
                                    segment["sector_size"],
                                ),
                            )

                            segment["data"] = chew(buf)

                self.buf.seek(m)
            case _:
                meta["unknown"] = True

        return meta


@module.register
class SshSignatureModule(module.RuminantModule):
    desc = "SSH signatures like the ones that Git uses."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(29) == b"-----BEGIN SSH SIGNATURE-----"

    def rb(self, buf=None):
        if buf is None:
            buf = self.ibuf

        return buf.read(self.ibuf.ru32())

    def rs(self, buf=None):
        if buf is None:
            buf = self.ibuf

        return buf.rs(self.ibuf.ru32())

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "ssh-signature"

        self.buf.rl()
        lines = b""
        while True:
            line = self.buf.rl()
            if line == b"-----END SSH SIGNATURE-----":
                break

            lines += line

        self.ibuf = Buf(base64.b64decode(lines))
        self.ibuf.skip(6)

        meta["data"] = {}
        meta["data"]["version"] = self.ibuf.ru32()

        self.ibuf.pasunit(self.ibuf.ru32())
        meta["data"]["public-key"] = {}
        meta["data"]["public-key"]["algorithm"] = self.rs()
        meta["data"]["public-key"]["blob"] = self.rb().hex()
        self.ibuf.sapunit()

        meta["data"]["namespace"] = self.rs()
        meta["data"]["reserved"] = self.rs()
        meta["data"]["hash-algorithm"] = self.rs()

        self.ibuf.pasunit(self.ibuf.ru32())
        meta["data"]["signature"] = {}
        meta["data"]["signature"]["algorithm"] = self.rs()
        meta["data"]["signature"]["blob"] = self.rb().hex()
        self.ibuf.sapunit()

        return meta


@module.register
class OpenSshPrivateKeyModule(module.RuminantModule):
    dev = True
    desc = "OpenSSH private keys."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(35) == b"-----BEGIN OPENSSH PRIVATE KEY-----"

    def rb(self, buf=None):
        if buf is None:
            buf = self.ibuf

        return buf.read(self.ibuf.ru32())

    def rs(self, buf=None):
        if buf is None:
            buf = self.ibuf

        return buf.rs(self.ibuf.ru32())

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "openssh-private-key"

        self.buf.rl()
        lines = b""
        while True:
            line = self.buf.rl()
            if line == b"-----END OPENSSH PRIVATE KEY-----":
                break

            lines += line

        self.ibuf = Buf(base64.b64decode(lines))

        meta["data"] = {}
        meta["data"]["magic"] = self.ibuf.rzs()
        if meta["data"]["magic"] != "openssh-key-v1":
            meta["unknown"] = True
            return meta

        meta["data"]["cipher"] = self.rs()
        meta["data"]["kdfname"] = self.rs()
        match meta["data"]["kdfname"]:
            case "none":
                meta["data"]["kdfoptions"] = self.rs()
            case "bcrypt":
                meta["data"]["kdfoptions"] = {
                    "salt": self.rs(),
                    "rounds": self.ibuf.ru32(),
                }
            case _:
                meta["unknown"] = True
                return meta
        meta["data"]["nkeys"] = self.ibuf.ru32()
        meta["data"]["public-keys"] = [self.rb().hex() for i in range(0, meta["data"]["nkeys"])]

        return meta


@module.register
class EfiSignatureListModule(module.RuminantModule):
    desc = "EFI signature lists."

    GUIDS = ("a5c059a1-94e4-4aa7-87b5-ab155c2bf072",)

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 4:
            return False

        if buf.available() > 16 and buf.pguid() in EfiSignatureListModule.GUIDS:
            return True

        with buf:
            buf.skip(4)
            return buf.available() > 16 and buf.pguid() in EfiSignatureListModule.GUIDS

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "efi-signature-list"

        if self.buf.pguid() not in EfiSignatureListModule.GUIDS:
            meta["flags"] = self.buf.ru32l()

        meta["guid"] = self.buf.rguid()
        meta["signature-list-size"] = self.buf.ru32l()
        self.buf.pasunit(meta["signature-list-size"] - 20)
        meta["signature-header-size"] = self.buf.ru32l()
        meta["signature-size"] = self.buf.ru32l()
        meta["signature-header"] = self.buf.rh(meta["signature-header-size"])

        meta["signatures"] = []
        while self.buf.hasunit():
            sig: dict = {}
            sig["owner"] = self.buf.rguid()

            self.buf.pasunit(min(meta["signature-size"], self.buf.available()))

            sig["data"] = utils.read_der(self.buf)

            self.buf.sapunit()
            meta["signatures"].append(sig)

        self.buf.sapunit()

        return meta
