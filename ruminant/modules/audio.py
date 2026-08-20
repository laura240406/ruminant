from .. import module, utils, ruminant_types
from ..buf import Buf, UnitException
from . import chew
from ..media import FFMpreg
import zlib
import json


@module.register
class FlacModule(module.RuminantModule):
    desc = "FLAC audio files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"fLaC"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "flac"

        self.buf.skip(4)

        meta["blocks"] = []
        more = True
        while more:
            block: dict = {}
            block["type"] = None

            flags = self.buf.ru8()
            more = not bool(flags & 0x80)
            typ = flags & 0x7f

            length = self.buf.ru24()
            block["length"] = length

            self.buf.pushunit()
            self.buf.setunit(length)

            block["data"] = {}
            match typ:
                case 0:
                    block["type"] = "Streaminfo"
                    block["data"]["min-block-size"] = self.buf.ru16()
                    block["data"]["max-block-size"] = self.buf.ru16()
                    block["data"]["min-frame-size"] = self.buf.ru24()
                    block["data"]["max-frame-size"] = self.buf.ru24()

                    temp = self.buf.ru64()
                    block["data"]["sample-rate"] = temp >> 44
                    block["data"]["channel-count"] = ((temp >> 41) & 0x07) + 1
                    block["data"]["bits-per-sample"] = ((temp >> 36) & 0x1f) + 1
                    block["data"]["sample-count"] = temp & 0xfffffffff

                    block["data"]["unencoded-md5"] = self.buf.rh(16)
                case 1:
                    block["type"] = "Padding"
                    block["data"]["non-zero"] = sum(self.buf.readunit()) > 0
                case 2:
                    block["type"] = "Application"
                    block["data"]["application-id"] = self.buf.rs(4, "latin-1")
                case 3:
                    block["type"] = "Seek table"
                    block["data"]["entries"] = []
                    while self.buf.hasunit():
                        entry = {}
                        entry["first-sample"] = self.buf.ri64()
                        entry["offset"] = self.buf.ru64()
                        entry["sample-count"] = self.buf.ru16()

                        block["data"]["entries"].append(entry)
                case 4:
                    block["type"] = "Vorbis comment"
                    block["data"]["vendor-string"] = self.buf.rs(self.buf.ru32l())

                    block["data"]["user-strings"] = []
                    for i in range(0, self.buf.ru32l()):
                        block["data"]["user-strings"].append(self.buf.rs(self.buf.ru32l()))
                case 6:
                    block["type"] = "Picture"
                    picture_type = self.buf.ru32()
                    block["data"]["picture-type"] = {
                        0: "Other",
                        1: "PNG file icon of 32x32 pixels (see [RFC2083])",
                        2: "General file icon",
                        3: "Front cover",
                        4: "Back cover",
                        5: "Liner notes page",
                        6: "Media label (e.g., CD, Vinyl or Cassette label)",
                        7: "Lead artist, lead performer, or soloist",
                        8: "Artist or performer",
                        9: "Conductor",
                        10: "Band or orchestra",
                        11: "Composer",
                        12: "Lyricist or text writer",
                        13: "Recording location",
                        14: "During recording",
                        15: "During performance",
                        16: "Movie or video screen capture",
                        # this is a joke value since Xiph.Org (owner of FLAC) uses the green swordtail as their logo
                        # since its Latin name is Xiphophorus hellerii
                        17: "A bright colored fish",
                        18: "Illustration",
                        19: "Band or artist logotype",
                        20: "Publisher or studio logotype",
                    }.get(picture_type, "Unknown") + f" (0x{hex(picture_type)[2:].zfill(4)})"
                    block["data"]["media-type"] = self.buf.rs(self.buf.ru32())
                    block["data"]["description"] = self.buf.rs(self.buf.ru32())
                    block["data"]["width"] = self.buf.ru32()
                    block["data"]["height"] = self.buf.ru32()
                    block["data"]["bits-per-pixel"] = self.buf.ru32()
                    block["data"]["palette-element-count"] = self.buf.ru32()
                    block["data"]["picture"] = chew(self.buf.read(self.buf.ru32()))
                case _:
                    block["type"] = f"Unknown (0x{hex(typ)[2:].zfill(2)})"
                    block["unknown"] = True

            meta["blocks"].append(block)

            self.buf.skipunit()
            self.buf.popunit()

        return meta


@module.register
class ID3v2Module(module.RuminantModule):
    desc = "ID3 version 2 metadata in MP3 files or MPEG-TS streams."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(3) == b"ID3"

    # helper since we need this a lot
    def read_length(self, unsynchronized):
        if unsynchronized or self.force:
            length = 0

            for i in range(0, 4):
                length <<= 7
                length |= self.buf.ru8() & 0x7f

            return length
        else:
            return self.buf.ru32()

    def chew(self) -> ruminant_types.JSON:
        self.force = False

        bak = self.buf.backup()
        # try to decode it like the standard dictates
        try:
            return self._chew()
        except (AssertionError, UnitException):
            # some files are broken, try again while forcing unsynchronized mode
            self.force = True
            self.buf.restore(bak)
            return self._chew()

    # actual chew()
    def _chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "id3v2"

        self.buf.skip(3)
        meta["header"] = {}
        meta["header"]["version"] = str("2." + str(self.buf.ru8()) + "." + str(self.buf.ru8()))

        flags = self.buf.ru8()
        meta["header"]["flags"] = {
            "raw": flags,
            "unsynchronized": bool(flags & 0x80),
            "has-extended-header": bool(flags & 0x40),
            "experimental": bool(flags & 0x20),
            "has-footer": bool(flags & 0x10),
        }

        meta["header"]["length"] = self.read_length(bool(flags & 0x80))
        self.buf.pushunit()
        self.buf.setunit(meta["header"]["length"])

        if meta["header"]["flags"]["has-extended-header"]:
            meta["extended-header"] = {}

            extended_header_length = self.read_length(bool(flags & 0x80))
            meta["extended-header"]["length"] = extended_header_length

            self.buf.pushunit()
            self.buf.setunit(extended_header_length - 4)

            meta["extended-header"]["flags"] = self.buf.rh(self.buf.ru8())

            meta["extended-header"]["flag-values"] = []
            while self.buf.hasunit():
                meta["extended-header"]["flag-values"].append(self.buf.rh(self.buf.ru8()))

            self.buf.skipunit()
            self.buf.popunit()

        meta["frames"] = []
        while self.buf.hasunit():
            if self.buf.pu16() == 0xfffb:
                self.buf.setunit(0)
                break

            frame = {}
            frame["type"] = self.buf.rs(4)
            # last type is just 4 zero bytes
            if frame["type"] == "":
                break

            if self.buf.unit == 0:
                break

            frame["length"] = self.read_length(bool(flags & 0x80))

            status_flags = self.buf.ru8()
            frame["status-flags"] = {
                "raw": status_flags,
                "discard-on-tag-alter": bool(status_flags & 0b01000000),
                "discard-on-file-alter": bool(status_flags & 0b00100000),
                "read-only": bool(status_flags & 0b00010000),
            }

            format_flags = self.buf.ru8()
            frame["format-flags"] = {
                "raw": format_flags,
                "is-grouped": bool(format_flags & 0b01000000),
                "is-compressed": bool(format_flags & 0b00001000),
                "is-encrypted": bool(format_flags & 0b00000100),
                "is-unsynchronized": bool(format_flags & 0b00000010),
                "has-data-length-indictator": bool(format_flags & 0b00000001),
            }

            if frame["format-flags"]["is-grouped"]:
                frame["format-flags"]["group-id"] = self.buf.ru8()

            if frame["format-flags"]["has-data-length-indictator"]:
                frame["format-flags"]["data-length"] = self.read_length(bool(format_flags & 0b00000010))

            content = self.buf.read(frame["length"])

            if frame["format-flags"]["is-unsynchronized"]:
                # ununsynchronize
                content = content.replace(b"\xff\x00", b"\xff")

            if frame["format-flags"]["is-encrypted"]:
                # we can't read this
                frame["data"] = content.hex()
                frame["encrypted"] = True
            else:
                if frame["format-flags"]["is-compressed"]:
                    content = zlib.decompress(content)

                match frame["type"]:
                    case "PRIV":
                        frame["data"] = utils.decode(content).split("\x00")
                    case "APIC":
                        encoding = {
                            0: "latin-1",
                            1: "utf-16",
                            2: "utf-16be",
                            3: "utf-8",
                        }.get(content[0], "utf-8")
                        content = content[1:]

                        mime_type = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            mime_type += content[: 2 if "16" in encoding else 1]
                            content = content[2 if "16" in encoding else 1 :]

                        frame["data"] = {}
                        frame["data"]["encoding"] = encoding
                        frame["data"]["mime-type"] = mime_type.decode(encoding)
                        frame["data"]["image-type"] = utils.unraw(
                            content[0],
                            1,
                            {
                                0x00: "Other",
                                0x01: "32x32 pixels file icon PNG only",
                                0x02: "Other file icon",
                                0x03: "Cover front",
                                0x04: "Cover back",
                                0x05: "Leaflet page",
                                0x06: "Media e.g. label side of CD",
                                0x07: "Lead artist/lead performer/soloist",
                                0x08: "Artist/performer",
                                0x09: "Conductor",
                                0x0a: "Band/Orchestra",
                                0x0b: "Composer",
                                0x0c: "Lyricist/text writer",
                                0x0d: "Recording Location",
                                0x0e: "During recording",
                                0x0f: "During performance",
                                0x10: "Movie/video screen capture",
                                0x11: "A bright coloured fish",
                                0x12: "Illustration",
                                0x13: "Band/artist logotype",
                                0x14: "Publisher/Studio logotype",
                            },
                        )
                        content = content[1:]

                        desc = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            desc += content[: 2 if "16" in encoding else 1]
                            content = content[2 if "16" in encoding else 1 :]

                        frame["data"]["description"] = desc.decode(encoding)
                        frame["data"]["image"] = chew(content)
                    case "COMM":
                        encoding = {
                            0: "latin-1",
                            1: "utf-16",
                            2: "utf-16be",
                            3: "utf-8",
                        }.get(content[0], "utf-8")
                        content = content[1:]

                        language = content[:3].decode("latin-1").rstrip("\x00")
                        content = content[3:]

                        short_description = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            short_description += content[: 2 if "16" in encoding else 1]
                            content = content[2 if "16" in encoding else 1 :]

                        frame["data"] = {}
                        frame["data"]["encoding"] = encoding
                        frame["data"]["language"] = language
                        frame["data"]["short-description"] = short_description.decode(encoding)
                        frame["data"]["text"] = content.decode(encoding).rstrip("\x00")
                    case "GEOB":
                        encoding = {
                            0: "latin-1",
                            1: "utf-16",
                            2: "utf-16be",
                            3: "utf-8",
                        }.get(content[0], "utf-8")
                        content = content[1:]

                        mime_type = b""
                        while content[0]:
                            mime_type += content[0:1]
                            content = content[1:]
                        content = content[1:]

                        file_name = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            file_name += content[: 2 if "16" in encoding else 1]
                            content = content[2 if "16" in encoding else 1 :]

                        description = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            description += content[: 2 if "16" in encoding else 1]
                            content = content[2 if "16" in encoding else 1 :]

                        frame["data"] = {}
                        frame["data"]["encoding"] = encoding
                        frame["data"]["mime-type"] = mime_type.decode("latin-1")
                        frame["data"]["file-name"] = file_name.decode(encoding)
                        frame["data"]["description"] = description.decode(encoding)
                        frame["data"]["blob"] = chew(content)
                    case "USLT":
                        frame["data"] = {}
                        frame["data"]["encoding"] = {
                            0: "latin-1",
                            1: "utf-16",
                            2: "utf-16be",
                            3: "utf-8",
                        }.get(content[0])
                        frame["data"]["language"] = content[1:3].decode("latin1")
                        descriptor = b""
                        content = content[4:]

                        if frame["data"]["encoding"] in ("utf-16", "utf-16be"):
                            while len(content) and content[:2] != b"\x00\x00":
                                descriptor += content[:2]
                                content = content[2:]

                            content = content[2:]
                        else:
                            while len(content) and content[0] != b"\x00":
                                descriptor += content[:1]
                                content = content[1:]

                            content = content[1:]

                        frame["data"]["content-descriptor"] = descriptor.decode(frame["data"]["encoding"]).rstrip("\x00")
                        frame["data"]["text"] = content.decode(frame["data"]["encoding"]).rstrip("\x00")
                    case "UFID":
                        frame["data"] = {}
                        frame["data"]["owner-identifier"] = content.split(b"\x00")[0].decode("utf-8")
                        frame["data"]["identifier"] = content.split(b"\x00")[1].decode("utf-8")
                    case (
                        "TALB"
                        | "TIT1"
                        | "TIT2"
                        | "TIT3"
                        | "TYER"
                        | "TXXX"
                        | "TPE1"
                        | "TSSE"
                        | "TCOM"
                        | "TPUB"
                        | "TOPE"
                        | "TOAL"
                        | "TCON"
                        | "TPE2"
                        | "TENC"
                        | "TBPM"
                        | "TRCK"
                        | "TDEN"
                        | "TDTG"
                        | "TOFN"
                        | "TCOP"
                        | "TIME"
                        | "TLAN"
                        | "TDAT"
                        | "TPOS"
                        | "TDRC"
                        | "TCMP"
                        | "TDOR"
                        | "TMED"
                        | "TEXT"
                        | "TSO2"
                        | "TSOC"
                        | "TSRC"
                        | "TSOP"
                    ):
                        frame["data"] = {}
                        frame["data"]["encoding"] = {
                            0: "latin-1",
                            1: "utf-16",
                            2: "utf-16be",
                            3: "utf-8",
                        }.get(content[0])
                        frame["data"]["string"] = content[1:].decode(frame["data"]["encoding"]).rstrip("\x00")

                        if frame["type"] == "TXXX":
                            frame["data"]["namespace"] = frame["data"]["string"].split("\x00")[0]
                            frame["data"]["string"] = frame["data"]["string"].split("\x00")[1]

                            match frame["data"]["namespace"]:
                                case "segmentmetadata":
                                    frame["data"]["string"] = json.loads(frame["data"]["string"])
                    case "WORS" | "WPUB":
                        frame["data"] = content.decode("latin-1")
                    case _:
                        frame["data"] = content.hex()
                        frame["unknown"] = True

            meta["frames"].append(frame)

        self.buf.skipunit()
        self.buf.popunit()

        if meta["header"]["flags"]["has-footer"]:
            self.buf.skip(10)

        return meta


@module.register
class Mp3Module(module.RuminantModule):
    desc = "Raw MP3 files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 4:
            return False

        if buf.pu32() & 0b11111111111_00_11_0_0000_00_0_000000000 == 0b11111111111_00_01_0_0000_00_0_000000000:
            return (buf.pu32() >> 12) & 0b1111 != 0b1111 and (buf.pu32() >> 10) & 0b11 != 0b11

        return False

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "mp3"

        meta["frames"] = []
        while Mp3Module.identify(self.buf, {}):
            meta["frames"].append(FFMpreg.read_mp3_frame(self.buf))

        if self.buf.available() >= 128 and self.buf.peek(3) == b"TAG":
            # ID3v1 footer
            self.buf.skip(3)

            meta["footer"] = {}
            meta["footer"]["title"] = self.buf.rs(30)
            meta["footer"]["artist"] = self.buf.rs(30)
            meta["footer"]["album"] = self.buf.rs(30)
            meta["footer"]["year"] = self.buf.rs(4)

            if self.buf.peek(30)[28] == 0:
                meta["footer"]["comment"] = self.buf.rs(29)
                meta["footer"]["track-number"] = self.buf.ru8()
            else:
                meta["footer"]["comment"] = self.buf.rs(30)

            meta["footer"]["genre"] = utils.unraw(
                self.buf.ru8(),
                1,
                {
                    0x00: "Blues",
                    0x01: "Classic Rock",
                    0x02: "Country",
                    0x03: "Dance",
                    0x04: "Disco",
                    0x05: "Funk",
                    0x06: "Grunge",
                    0x07: "Hip-Hop",
                    0x08: "Jazz",
                    0x09: "Metal",
                    0x0a: "New Age",
                    0x0b: "Oldies",
                    0x0c: "Other",
                    0x0d: "Pop",
                    0x0e: "R&B",
                    0x0f: "Rap",
                    0x10: "Reggae",
                    0x11: "Rock",
                    0x12: "Techno",
                    0x13: "Industrial",
                    0x14: "Alternative",
                    0x15: "Ska",
                    0x16: "Death Metal",
                    0x17: "Pranks",
                    0x18: "Soundtrack",
                    0x19: "Euro-Techno",
                    0x1a: "Ambient",
                    0x1b: "Trip-Hop",
                    0x1c: "Vocal",
                    0x1d: "Jazz+Funk",
                    0x1e: "Fusion",
                    0x1f: "Trance",
                    0x20: "Classical",
                    0x21: "Instrumental",
                    0x22: "Acid",
                    0x23: "House",
                    0x24: "Game",
                    0x25: "Sound Clip",
                    0x26: "Gospel",
                    0x27: "Noise",
                    0x28: "AlternRock",
                    0x29: "Bass",
                    0x2a: "Soul",
                    0x2b: "Punk",
                    0x2c: "Space",
                    0x2d: "Meditative",
                    0x2e: "Instrumental Pop",
                    0x2f: "Instrumental Rock",
                    0x30: "Ethnic",
                    0x31: "Gothic",
                    0x32: "Darkwave",
                    0x33: "Techno-Industrial",
                    0x34: "Electronic",
                    0x35: "Pop-Folk",
                    0x36: "Eurodance",
                    0x37: "Dream",
                    0x38: "Southern Rock",
                    0x39: "Comedy",
                    0x3a: "Cult",
                    0x3b: "Gangsta",
                    0x3c: "Top 40",
                    0x3d: "Christian Rap",
                    0x3e: "Pop/Funk",
                    0x3f: "Jungle",
                    0x40: "Native American",
                    0x41: "Cabaret",
                    0x42: "New Wave",
                    0x43: "Psychadelic",
                    0x44: "Rave",
                    0x45: "Showtunes",
                    0x46: "Trailer",
                    0x47: "Lo-Fi",
                    0x48: "Tribal",
                    0x49: "Acid Punk",
                    0x4a: "Acid Jazz",
                    0x4b: "Polka",
                    0x4c: "Retro",
                    0x4d: "Musical",
                    0x4e: "Rock & Roll",
                    0x4f: "Hard Rock",
                    0x50: "Folk",
                    0x51: "Folk-Rock",
                    0x52: "National Folk",
                    0x53: "Swing",
                    0x54: "Fast Fusion",
                    0x55: "Bebob",
                    0x56: "Latin",
                    0x57: "Revival",
                    0x58: "Celtic",
                    0x59: "Bluegrass",
                    0x5a: "Avantgarde",
                    0x5b: "Gothic Rock",
                    0x5c: "Progressive Rock",
                    0x5d: "Psychedelic Rock",
                    0x5e: "Symphonic Rock",
                    0x5f: "Slow Rock",
                    0x60: "Big Band",
                    0x61: "Chorus",
                    0x62: "Easy Listening",
                    0x63: "Acoustic",
                    0x64: "Humour",
                    0x65: "Speech",
                    0x66: "Chanson",
                    0x67: "Opera",
                    0x68: "Chamber Music",
                    0x69: "Sonata",
                    0x6a: "Symphony",
                    0x6b: "Booty Bass",
                    0x6c: "Primus",
                    0x6d: "Porn Groove",
                    0x6e: "Satire",
                    0x6f: "Slow Jam",
                    0x70: "Club",
                    0x71: "Tango",
                    0x72: "Samba",
                    0x73: "Folklore",
                    0x74: "Ballad",
                    0x75: "Power Ballad",
                    0x76: "Rhythmic Soul",
                    0x77: "Freestyle",
                    0x78: "Duet",
                    0x79: "Punk Rock",
                    0x7a: "Drum Solo",
                    0x7b: "A capella",
                    0x7c: "Euro-House",
                    0x7d: "Dance Hall",
                    0xff: "Unknown",
                },
                True,
            )

        return meta


@module.register
class MidiModule(module.RuminantModule):
    desc = "MIDI files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"MThd"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "midi"

        self.buf.skip(4)
        meta["header-length"] = self.buf.ru32()

        self.buf.pasunit(meta["header-length"])

        meta["format"] = utils.unraw(
            self.buf.ru16(),
            1,
            {
                0x0000: "Single track",
                0x0001: "Multiple tracks",
                0x0002: "Multiple songs",
            },
            True,
        )
        meta["channel-count"] = self.buf.ru16()
        meta["division"] = self.buf.ri16()

        self.buf.sapunit()

        last_opcode = 0
        meta["tracks"] = []
        while self.buf.peek(4) == b"MTrk":
            track: dict = {}
            self.buf.skip(4)
            track["length"] = self.buf.ru32()

            self.buf.pasunit(track["length"])

            track["events"] = []
            while self.buf.hasunit():
                event = {}
                event["delta"] = self.buf.ruleb()

                op = self.buf.ru8()
                event["opcode"] = op

                if op == 0xf0 or op == 0xf7:
                    event["data-length"] = self.buf.ruleb()
                    event["data"] = self.buf.rh(event["data-length"])
                elif op == 0xff:
                    event["meta-event-type"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {
                            0x01: "Text",
                            0x02: "Copyright Notice",
                            0x03: "Track Name",
                            0x21: "Port Prefix",
                            0x2f: "End Of Track",
                            0x51: "Set Tempo",
                            0x58: "Time Signature",
                            0x59: "Key Signature",
                        },
                        True,
                    )
                    event["data-length"] = self.buf.ruleb()

                    self.buf.pasunit(event["data-length"])

                    match event["meta-event-type"]:
                        case "Time Signature":
                            event["data"] = {
                                "numerator": self.buf.ru8(),
                                "denominator": self.buf.ru8(),
                                "clocks-per-metronome-tick": self.buf.ru8(),
                                "32nds-per-24-clocks-count": self.buf.ru8(),
                            }
                        case "Key Signature":
                            event["data"] = {
                                "value": self.buf.ri8(),
                                "key": utils.unraw(
                                    self.buf.ru8(),
                                    1,
                                    {0x00: "Major", 0x01: "Minor"},
                                    True,
                                ),
                            }
                        case "Set Tempo":
                            temp = self.buf.ru24()
                            event["data"] = {
                                "microseconds-per-quater": temp,
                                "estimated-bpm": round(60000000 / temp),
                            }
                        case "Port Prefix":
                            event["data"] = {"port": self.buf.ru8()}
                        case "End Of Track":
                            pass
                        case "Text" | "Copyright Notice" | "Track Name":
                            event["data"] = {"string": self.buf.rs(self.buf.unit)}
                        case _:
                            event["data"] = {"raw": self.buf.rh(self.buf.unit)}
                            event["unknown"] = True

                    self.buf.sapunit()
                else:
                    event["channel"] = op & 0x0f
                    if op & 0x80:
                        event["opcode"] = utils.unraw(
                            op >> 4,
                            1,
                            {
                                0x08: "Note Off",
                                0x09: "Note On",
                                0x0a: "Polyphonic Key Pressure",
                                0x0b: "Control Change",
                                0x0c: "Program Change",
                                0x0d: "Channel Pressure",
                                0x0e: "Pitch Bend Change",
                            },
                            True,
                        )
                        last_opcode = op
                    else:
                        del event["channel"]
                        event["opcode"] = "Continued"
                        op = last_opcode
                        self.buf.skip(-1)

                    match op >> 4:
                        case 0x08 | 0x09:
                            event["note-number"] = self.buf.ru8()
                            event["velocity"] = self.buf.ru8()
                        case 0x0a:
                            event["note-number"] = self.buf.ru8()
                            event["pressure-value"] = self.buf.ru8()
                        case 0x0b:
                            event["controller-number"] = self.buf.ru8()
                            event["controller-value"] = self.buf.ru8()
                        case 0x0c:
                            event["program-change"] = self.buf.ru8()
                        case 0x0d:
                            event["pressure-value"] = self.buf.ru8()
                        case 0x0e:
                            event["fine-change"] = self.buf.ru8()
                            event["coarse-change"] = self.buf.ru8()
                        case _:
                            event["unknown"] = True
                            self.buf.skip(self.buf.unit if self.buf.unit is not None else 0)

                track["events"].append(event)

            self.buf.sapunit()
            meta["tracks"].append(track)

        return meta
