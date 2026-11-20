from .. import module, utils, secrets, crypto, ruminant_types
from ..buf import Buf, UnitException
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
            or buf.peek(35) == b"-----BEGIN CERTIFICATE REQUEST-----"
            or buf.peek(29) == b"-----BEGIN DH PARAMETERS-----"
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


@module.register
class BitcoinBlockModule(module.RuminantModule):
    desc = "Bitcoin/Litecoin block files. Run your node with blocksxor=0 or decrypt manually."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) in (b"\xf9\xbe\xb4\xd9", b"\xfb\xc0\xb6\xdb")

    def read_cpi(self) -> int:
        tmp = self.buf.ru8()

        match tmp:
            case 0xfd:
                return self.buf.ru16l()
            case 0xfe:
                return self.buf.ru32l()
            case 0xff:
                return self.buf.ru64l()
            case _:
                return tmp

    def read_tx(self, is_coinbase) -> ruminant_types.JSON:
        tx: dict = {}

        base = self.buf.tell()

        tx["length"] = None
        tx["txid"] = None
        tx["wtxid"] = None
        tx["version"] = self.buf.ru32l()
        if self.buf.pu8() == 0:
            tx["segwit"] = True
            self.buf.skip(2)

        tx["input-count"] = self.read_cpi()
        tx["inputs"] = []
        for i in range(0, tx["input-count"]):
            inpt: dict = {}
            inpt["txid"] = self.buf.read(32)[::-1].hex()
            inpt["vout"] = self.buf.ri32l()
            inpt["scriptsig-length"] = self.read_cpi()
            inpt["scriptsig"] = self.buf.read(inpt["scriptsig-length"])
            inpt["sequence"] = self.buf.ri32l()

            tx["inputs"].append(inpt)

        tx["output-count"] = self.read_cpi()
        tx["outputs"] = []
        for i in range(0, tx["output-count"]):
            output: dict = {}
            output["value"] = self.buf.ru64l()
            output["scriptpubkey-length"] = self.read_cpi()
            output["scriptpubkey"] = self.disassemble_script(self.buf.read(output["scriptpubkey-length"]), False, False, [])

            tx["outputs"].append(output)

        wit_offset = self.buf.tell()

        if tx.get("segwit"):
            for inpt in tx["inputs"]:
                inpt["segwit-stack-size"] = self.read_cpi()

                inpt["segwit-stack"] = []
                for i in range(0, inpt["segwit-stack-size"]):
                    inpt["segwit-stack"].append(self.buf.rh(self.read_cpi()))

                inpt["scriptsig"] = self.disassemble_script(inpt["scriptsig"], is_coinbase, True, inpt["segwit-stack"])
        else:
            for inpt in tx["inputs"]:
                inpt["scriptsig"] = self.disassemble_script(inpt["scriptsig"], is_coinbase, True, [])

        tx["locktime"] = self.buf.ru32l()

        with self.buf:
            length = self.buf.tell() - base
            tx["length"] = length
            self.buf.seek(base)
            self.buf.resetunit()

            tmp = self.buf.read(4)

            if tx.get("segwit"):
                self.buf.skip(2)

            tx["txid"] = (
                hashlib
                .sha256(
                    hashlib.sha256(
                        tmp
                        + self.buf.read(wit_offset - base - (6 if tx.get("segwit") else 4))
                        + tx["locktime"].to_bytes(4, "little")
                    ).digest()
                )
                .digest()[::-1]
                .hex()
            )

            self.buf.seek(base)
            self.buf.resetunit()
            tx["wtxid"] = hashlib.sha256(hashlib.sha256(self.buf.read(length)).digest()).digest()[::-1].hex()

        return tx

    def unpack_key(self, key: bytes) -> dict:
        if key[0] == 0x02:
            return {"type": "compressed", "x": int.from_bytes(key[1:33]), "y": "even"}
        elif key[0] == 0x03:
            return {"type": "compressed", "x": int.from_bytes(key[1:33]), "y": "odd"}
        elif key[0] == 0x04:
            return {
                "type": "uncompressed",
                "x": int.from_bytes(key[1:33]),
                "y": int.from_bytes(key[33:]),
            }
        else:
            raise ValueError(f"Unknown key format {key[0]}")

    def disassemble_script(
        self, scr: bytes, is_coinbase: bool, is_input: bool, segwit_stack: list[str], taproot: bool = False
    ) -> dict:
        ops: list = []
        buf = Buf(scr)

        while buf.available():
            try:
                op = buf.ru8()

                match op:
                    case 0x00:
                        ops.append("OP_0")
                    case 0x4c:
                        ops.append("<" + buf.rh(buf.ru8()) + ">")
                    case 0x4d:
                        ops.append("<" + buf.rh(buf.ru16l()) + ">")
                    case 0x4e:
                        ops.append("<" + buf.rh(buf.ru32l()) + ">")
                    case 0x4f:
                        ops.append("OP_1NEGATE")
                    case 0x50:
                        ops.append("OP_RESERVED")
                    case 0x51:
                        ops.append("OP_1")
                    case 0x52:
                        ops.append("OP_2")
                    case 0x53:
                        ops.append("OP_3")
                    case 0x54:
                        ops.append("OP_4")
                    case 0x55:
                        ops.append("OP_5")
                    case 0x56:
                        ops.append("OP_6")
                    case 0x57:
                        ops.append("OP_7")
                    case 0x58:
                        ops.append("OP_8")
                    case 0x59:
                        ops.append("OP_9")
                    case 0x5a:
                        ops.append("OP_10")
                    case 0x5b:
                        ops.append("OP_11")
                    case 0x5c:
                        ops.append("OP_12")
                    case 0x5d:
                        ops.append("OP_13")
                    case 0x5e:
                        ops.append("OP_14")
                    case 0x5f:
                        ops.append("OP_15")
                    case 0x60:
                        ops.append("OP_16")
                    case 0x61:
                        ops.append("OP_NOP")
                    case 0x62:
                        ops.append("OP_VER")
                    case 0x63:
                        ops.append("OP_IF")
                    case 0x64:
                        ops.append("OP_NOTIF")
                    case 0x65:
                        ops.append("OP_VERIF")
                    case 0x66:
                        ops.append("OP_VERNOTIF")
                    case 0x67:
                        ops.append("OP_ELSE")
                    case 0x68:
                        ops.append("OP_ENDIF")
                    case 0x69:
                        ops.append("OP_VERIFY")
                    case 0x6a:
                        ops.append("OP_RETURN")
                    case 0x6b:
                        ops.append("OP_TOALTSTACK")
                    case 0x6c:
                        ops.append("OP_FROMALTSTACK")
                    case 0x6d:
                        ops.append("OP_2DROP")
                    case 0x6e:
                        ops.append("OP_2DUP")
                    case 0x6f:
                        ops.append("OP_3DUP")
                    case 0x70:
                        ops.append("OP_2OVER")
                    case 0x71:
                        ops.append("OP_2ROT")
                    case 0x72:
                        ops.append("OP_2SWAP")
                    case 0x73:
                        ops.append("OP_IFDUP")
                    case 0x74:
                        ops.append("OP_DEPTH")
                    case 0x75:
                        ops.append("OP_DROP")
                    case 0x76:
                        ops.append("OP_DUP")
                    case 0x77:
                        ops.append("OP_NIP")
                    case 0x78:
                        ops.append("OP_OVER")
                    case 0x79:
                        ops.append("OP_PICK")
                    case 0x7a:
                        ops.append("OP_ROLL")
                    case 0x7b:
                        ops.append("OP_ROT")
                    case 0x7c:
                        ops.append("OP_SWAP")
                    case 0x7d:
                        ops.append("OP_TUCK")
                    case 0x7e:
                        ops.append("OP_CAT")
                    case 0x7f:
                        ops.append("OP_SUBSTR")
                    case 0x80:
                        ops.append("OP_LEFT")
                    case 0x81:
                        ops.append("OP_RIGHT")
                    case 0x82:
                        ops.append("OP_SIZE")
                    case 0x83:
                        ops.append("OP_INVERT")
                    case 0x84:
                        ops.append("OP_AND")
                    case 0x85:
                        ops.append("OP_OR")
                    case 0x86:
                        ops.append("OP_XOR")
                    case 0x87:
                        ops.append("OP_EQUAL")
                    case 0x88:
                        ops.append("OP_EQUALVERIFY")
                    case 0x89:
                        ops.append("OP_RESERVED1")
                    case 0x8a:
                        ops.append("OP_RESERVED2")
                    case 0x8b:
                        ops.append("OP_1ADD")
                    case 0x8c:
                        ops.append("OP_1SUB")
                    case 0x8d:
                        ops.append("OP_2MUL")
                    case 0x8e:
                        ops.append("OP_2DIV")
                    case 0x8f:
                        ops.append("OP_NEGATE")
                    case 0x90:
                        ops.append("OP_ABS")
                    case 0x91:
                        ops.append("OP_NOT")
                    case 0x92:
                        ops.append("OP_0NOTEQUAL")
                    case 0x93:
                        ops.append("OP_ADD")
                    case 0x94:
                        ops.append("OP_SUB")
                    case 0x95:
                        ops.append("OP_MUL")
                    case 0x96:
                        ops.append("OP_DIV")
                    case 0x97:
                        ops.append("OP_MOD")
                    case 0x98:
                        ops.append("OP_LSHIFT")
                    case 0x99:
                        ops.append("OP_RSHIFT")
                    case 0x9a:
                        ops.append("OP_BOOLAND")
                    case 0x9b:
                        ops.append("OP_BOOLOR")
                    case 0x9c:
                        ops.append("OP_NUMEQUAL")
                    case 0x9d:
                        ops.append("OP_NUMEQUALVERIFY")
                    case 0x9e:
                        ops.append("OP_NUMNOTEQUAL")
                    case 0x9f:
                        ops.append("OP_LESSTHAN")
                    case 0xa0:
                        ops.append("OP_GREATERTHAN")
                    case 0xa1:
                        ops.append("OP_LESSTHANOREQUAL")
                    case 0xa2:
                        ops.append("OP_GREATERTHANOREQUAL")
                    case 0xa3:
                        ops.append("OP_MIN")
                    case 0xa4:
                        ops.append("OP_MAX")
                    case 0xa5:
                        ops.append("OP_WITHIN")
                    case 0xa6:
                        ops.append("OP_RIPEMD160")
                    case 0xa7:
                        ops.append("OP_SHA1")
                    case 0xa8:
                        ops.append("OP_SHA256")
                    case 0xa9:
                        ops.append("OP_HASH160")
                    case 0xaa:
                        ops.append("OP_HASH256")
                    case 0xab:
                        ops.append("OP_CODESEPARATOR")
                    case 0xac:
                        ops.append("OP_CHECKSIG")
                    case 0xad:
                        ops.append("OP_CHECKSIGVERIFY")
                    case 0xae:
                        ops.append("OP_CHECKMULTISIG")
                    case 0xaf:
                        ops.append("OP_CHECKMULTISIGVERIFY")
                    case 0xb0:
                        ops.append("OP_NOP1")
                    case 0xb1:
                        ops.append("OP_CHECKLOCKTIMEVERIFY")
                    case 0xb2:
                        ops.append("OP_CHECKSEQUENCEVERIFY")
                    case 0xb3:
                        ops.append("OP_NOP4")
                    case 0xb4:
                        ops.append("OP_NOP5")
                    case 0xb5:
                        ops.append("OP_NOP6")
                    case 0xb6:
                        ops.append("OP_NOP7")
                    case 0xb7:
                        ops.append("OP_NOP8")
                    case 0xb8:
                        ops.append("OP_NOP9")
                    case 0xb9:
                        ops.append("OP_NOP10")
                    case 0xba:
                        ops.append("OP_CHECKSIGADD")
                    case _:
                        if op >= 0x01 and op <= 0x4b:
                            ops.append("<" + buf.rh(op) + ">")
                        else:
                            ops.append("UNK_" + hex(op)[2:].zfill(2))
            except UnitException:
                ops.append("ERROR")
                break

        script: dict = {}
        script["raw"] = ops

        if is_coinbase and len(ops) >= 2 and all([op[0] == "<" for op in ops]):
            script["type"] = "coinbase"
            script["parsed"] = {}
            script["parsed"]["height-or-difficulty"] = int.from_bytes(bytes.fromhex(ops[0][1:-1]), "little")
            script["parsed"]["extra-nonces"] = []

            for op in ops[1:]:
                script["parsed"]["extra-nonces"].append(utils.decode(bytes.fromhex(op[1:-1])))
        elif (
            not is_coinbase and not is_input and not taproot and len(ops) == 2 and ops[0][0] == "<" and ops[1] == "OP_CHECKSIG"
        ):
            script["type"] = "p2pk"
            script["parsed"] = {}
            script["parsed"]["pubkey"] = self.unpack_key(bytes.fromhex(ops[0][1:-1]))
        elif (
            not is_coinbase
            and not is_input
            and len(ops) == 5
            and ops[0] == "OP_DUP"
            and ops[1] == "OP_HASH160"
            and ops[2][0] == "<"
            and ops[3] == "OP_EQUALVERIFY"
            and ops[4] == "OP_CHECKSIG"
        ):
            script["type"] = "p2pkh"
            script["parsed"] = {}
            script["parsed"]["public-key-hash"] = ops[2][1:-1]

            if self.mode == "btc":
                script["parsed"]["address"] = utils.b58check_encode(b"\x00" + bytes.fromhex(ops[2][1:-1]))
            elif self.mode == "ltc":
                script["parsed"]["address"] = utils.b58check_encode(b"\x30" + bytes.fromhex(ops[2][1:-1]))
        elif not is_coinbase and is_input and len(ops) == 2 and len(ops[1]) in (68, 132) and ops[0][:3] == "<30":
            script["type"] = "p2pkh-sig"
            script["parsed"] = {}
            script["parsed"]["public-key"] = utils.read_der(Buf(bytes.fromhex(ops[0][1:-1])))
            script["parsed"]["signature"] = self.unpack_key(bytes.fromhex(ops[1][1:-1]))
        elif not is_input and len(ops) == 6 and ops[0] == "OP_2" and ops[4] == "OP_3" and ops[5] == "OP_CHECKMULTISIG":
            script["type"] = "2/3-multisig"
            script["parsed"] = {}
            script["parsed"]["keys"] = [
                self.unpack_key(bytes.fromhex(ops[1][1:-1])),
                self.unpack_key(bytes.fromhex(ops[2][1:-1])),
                self.unpack_key(bytes.fromhex(ops[3][1:-1])),
            ]
        elif not is_input and len(ops) == 5 and ops[0] == "OP_2" and ops[3] == "OP_2" and ops[4] == "OP_CHECKMULTISIG":
            script["type"] = "2/2-multisig"
            script["parsed"] = {}
            script["parsed"]["keys"] = [
                self.unpack_key(bytes.fromhex(ops[1][1:-1])),
                self.unpack_key(bytes.fromhex(ops[2][1:-1])),
            ]
        elif (
            not is_coinbase
            and is_input
            and len(ops) == 1
            and ops[0].startswith("<30")
            and len(ops[0]) in (140, 141, 142, 143, 144, 145, 146)
        ):
            script["type"] = "p2pk-sig"
            script["parsed"] = {}
            script["parsed"]["signature"] = utils.read_der(Buf(bytes.fromhex(ops[0][1:-1])[:-1]))
            tmp = bytes.fromhex(ops[0][1:-1])[-1]
            script["parsed"]["sighash"] = {
                "anyone-can-pay": tmp >= 0x80,
                "type": utils.unraw(tmp & 0x7f, 1, {0: "DEFAULT", 1: "ALL", 2: "NONE", 3: "SINGLE"}, True),
            }
        elif not is_coinbase and not is_input and len(ops) == 2 and ops[0] == "OP_0" and len(ops[1]) in (42, 66):
            if len(ops[1]) == 42:
                script["type"] = "p2wpkh"
                script["parsed"] = {}
                script["parsed"]["public-key-hash"] = ops[1][1:-1]
            else:
                script["type"] = "p2wsh"
                script["parsed"] = {}
                script["parsed"]["script-hash"] = ops[1][1:-1]

            if self.mode == "btc":
                script["parsed"]["address"] = crypto.encode_segwit_address("bc", 0, bytes.fromhex(ops[1][1:-1]), 1)
            elif self.mode == "ltc":
                script["parsed"]["address"] = crypto.encode_segwit_address("ltc", 0, bytes.fromhex(ops[1][1:-1]), 1)
        elif not is_coinbase and not is_input and len(ops) == 2 and ops[0] == "OP_1" and len(ops[1]) == 66:
            script["type"] = "p2tr"
            script["parsed"] = {}
            script["parsed"]["taproot-hash"] = ops[1][1:-1]

            if self.mode == "btc":
                script["parsed"]["address"] = crypto.encode_segwit_address("bc", 1, bytes.fromhex(ops[1][1:-1]), 0x2bc830a3)
            elif self.mode == "ltc":
                script["parsed"]["address"] = crypto.encode_segwit_address("ltc", 1, bytes.fromhex(ops[1][1:-1]), 0x2bc830a3)
        elif (
            not is_coinbase
            and not is_input
            and len(ops) == 3
            and ops[0] == "OP_HASH160"
            and ops[1][0] == "<"
            and ops[2] == "OP_EQUAL"
        ):
            script["type"] = "p2sh"
            script["parsed"] = {}
            script["parsed"]["script-hash"] = ops[1][1:-1]

            if self.mode == "btc":
                script["parsed"]["address"] = utils.b58check_encode(b"\x05" + bytes.fromhex(ops[1][1:-1]))
            elif self.mode == "ltc":
                script["parsed"]["address"] = utils.b58check_encode(b"\x32" + bytes.fromhex(ops[1][1:-1]))
        elif (
            len(ops) >= 5
            and ops[1] == "OP_CHECKSIG"
            and ops[2] == "OP_0"
            and ops[3] == "OP_IF"
            and ops[4] == "<6f7264>"
            and ops[-1] == "OP_ENDIF"
        ):
            script["type"] = "ordinal"
            script["parsed"] = {}
            ops = ops[5:]

            metadata = b""
            script["parsed"]["tags"] = []
            while len(ops) >= 2:
                typ = ops[0]
                if typ == "OP_0":
                    ops = ops[1:]
                    break

                if ops[1].startswith("OP_"):
                    data = bytes([int(ops[1][3:])])
                else:
                    data = bytes.fromhex(ops[1][1:-1])
                ops = ops[2:]

                # https://docs.ordinals.com/inscriptions.html
                match typ:
                    case "<01>" | "OP_1":
                        script["parsed"]["tags"].append({"type": "content-type", "value": utils.decode(data)})
                    case "<02>" | "OP_2":
                        script["parsed"]["tags"].append({"type": "pointer", "index": int.from_bytes(data, "little")})
                    case "<03>" | "OP_3":
                        script["parsed"]["tags"].append({
                            "type": "parent",
                            "txid": data[:32][::-1].hex(),
                            "index": int.from_bytes(data[32:], "little"),
                        })
                    case "<05>" | "OP_5":
                        metadata += data
                    case "<0d>" | "OP_13":
                        script["parsed"]["tags"].append({"type": "rune", "payload": data.hex()})
                    case _:
                        script["parsed"]["tags"].append({"type": f"Unknown ({typ})", "payload": data.hex()})

            if len(metadata):
                script["parsed"]["tags"].append({"type": "metadata", "cbor": utils.read_cbor(Buf(metadata))})

            body = b""
            if len(ops):
                for op in ops:
                    if not op.startswith("<"):
                        break

                    body += bytes.fromhex(op[1:-1])

                script["parsed"]["body"] = chew(body)
        elif not is_coinbase and not is_input and len(ops) == 2 and ops[0] == "OP_8" and ops[1][0] == "<":
            script["type"] = "hogex-commitment"
            script["parsed"] = {}
            script["parsed"]["hash"] = ops[1][1:-1]
        elif not is_coinbase and not is_input and len(ops) == 2 and ops[0] == "OP_9" and ops[1][0] == "<":
            script["type"] = "hogex-peg-in"
            script["parsed"] = {}
            script["parsed"]["mw-output-id"] = ops[1][1:-1]
        elif len(ops) == 0 and len(segwit_stack) > 0:
            if len(segwit_stack) == 2 and segwit_stack[0].startswith("30") and len(segwit_stack[1]) == 66:
                script["type"] = "p2wpkh-sig"
                script["parsed"] = {}
                script["parsed"]["public-key"] = utils.read_der(Buf(bytes.fromhex(segwit_stack[0])))
                script["parsed"]["signature"] = self.unpack_key(bytes.fromhex(segwit_stack[1]))
            elif (len(segwit_stack) == 1 and len(segwit_stack[0]) in (128, 130)) or (
                len(segwit_stack) == 2 and segwit_stack[1][0] == 0x50 and len(segwit_stack[0]) in (128, 130)
            ):
                script["type"] = "p2tr-key-sig"
                script["parsed"] = {}
                script["parsed"]["signature"] = bytes.fromhex(segwit_stack[0])[:64].hex()
                tmp = bytes.fromhex(segwit_stack[0] + "00")[64]
                script["parsed"]["sighash"] = {
                    "anyone-can-pay": tmp >= 0x80,
                    "type": utils.unraw(tmp & 0x7f, 1, {0: "DEFAULT", 1: "ALL", 2: "NONE", 3: "SINGLE"}, True),
                }

                if len(segwit_stack) == 2:
                    script["parsed"]["annex-a"] = segwit_stack[1]
            elif (
                len(segwit_stack) >= 2
                and len(segwit_stack[-1]) >= 66
                and (
                    (len(segwit_stack[-1]) % 64 == 2 and segwit_stack[-1][0] == "c")
                    or (segwit_stack[-1][0] == 0x50 and len(segwit_stack[-2]) % 64 == 2 and segwit_stack[-2][0] == "c")
                )
            ):
                script["type"] = "p2tr-script-sig"
                script["parsed"] = {}

                segwit_stack = segwit_stack[:]

                if segwit_stack[-1][0] == 0x50:
                    script["parsed"]["annex-a"] = segwit_stack.pop()

                script["parsed"]["inputs"] = segwit_stack[:-2]
                script["parsed"]["tapscript"] = self.disassemble_script(bytes.fromhex(segwit_stack[-2]), False, False, [], True)
                script["parsed"]["control-block"] = segwit_stack[-1]
            else:
                script["type"] = "p2wsh-sig"
                script["parsed"] = {}
                script["parsed"]["inputs"] = []
                for i in segwit_stack[:-1]:
                    try:
                        if len(i) > 4 and i[:4] == "3045":
                            script["parsed"]["inputs"].append(utils.read_der(Buf(bytes.fromhex(i))))

                        if (len(i) == 130 and i[:2] == "04") or (len(i) == 66 and i[:2] in ("02", "03")):
                            script["parsed"]["inputs"].append(self.unpack_key(bytes.fromhex(i)))
                    except Exception:
                        script["parsed"]["inputs"].append(i)

                script["parsed"]["script"] = self.disassemble_script(bytes.fromhex(segwit_stack[-1]), False, False, [])

        return script

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}

        match self.buf.rh(4):
            case "f9beb4d9":
                self.mode = "btc"
                meta["type"] = "bitcoin-block"
            case "fbc0b6db":
                self.mode = "ltc"
                meta["type"] = "litecoin-block"

        meta["length"] = self.buf.ru32l()
        self.buf.pasunit(meta["length"])

        hdr = self.buf.peek(80)

        meta["header"] = {}
        meta["header"]["version"] = self.buf.ru32l()
        meta["header"]["prev-hash"] = self.buf.read(32)[::-1].hex()
        meta["header"]["merkle-root"] = self.buf.read(32)[::-1].hex()
        meta["header"]["timestamp"] = utils.unix_to_date(self.buf.ru32l())
        mantissa = self.buf.ru24l()
        meta["header"]["difficulty"] = (mantissa << (8 * (self.buf.ru8() - 3))).to_bytes(32, "big").hex()
        meta["header"]["nonce"] = self.buf.ru32l()

        meta["header"]["id"] = hashlib.sha256(hashlib.sha256(hdr).digest()).digest()[::-1].hex()

        if self.mode == "btc":
            meta["header"]["is-below-difficulty"] = int.from_bytes(
                hashlib.sha256(hashlib.sha256(hdr).digest()).digest(), "little"
            ) < int(meta["header"]["difficulty"], 16)
        elif self.mode == "ltc":
            h = hashlib.scrypt(password=hdr, salt=hdr, n=1024, r=1, p=1, dklen=32, maxmem=2 * 1024 * 1024)
            meta["header"]["pow-hash"] = h[::-1].hex()
            meta["header"]["is-below-difficulty"] = int.from_bytes(h, "little") < int(meta["header"]["difficulty"], 16)

        meta["transaction-count"] = self.read_cpi()
        meta["transactions"] = []
        for i in range(0, meta["transaction-count"]):
            meta["transactions"].append(self.read_tx(i == 0))

        self.buf.sapunit()

        return meta
