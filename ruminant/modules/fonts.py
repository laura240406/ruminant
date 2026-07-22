from .. import module, utils, constants, ruminant_types
from ..buf import Buf
from . import chew
from typing import cast


@module.register
class TrueTypeModule(module.RuminantModule):
    desc = "TrueType font files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        size = buf.available()

        if size < 12:
            return False

        if buf.peek(4) not in (b"\x00\x01\x00\x00", b"OTTO"):
            return False

        with buf:
            buf.skip(4)
            table_count = buf.ru16()
            buf.skip(6)

            if buf.available() < table_count * 16:
                return False

            for i in range(0, table_count):
                buf.skip(8)

                if buf.ru32() + buf.ru32() > size:
                    return False

        return True

    def read_dsig(self):
        dsig = {}

        base = self.buf.tell()

        dsig["version"] = self.buf.ru32()
        dsig["signature-count"] = self.buf.ru16()
        flags = self.buf.ru16()
        dsig["flags"] = {"raw": flags, "no-resigning": bool(flags & 0x01)}

        most_offset = self.buf.tell()

        dsig["signatures"] = []
        for i in range(0, dsig["signature-count"]):
            sig = {}
            sig["format"] = self.buf.ru32()
            sig["length"] = self.buf.ru32()
            sig["offset"] = self.buf.ru32()

            most_offset = max(most_offset, sig["offset"] + sig["length"] + base)

            with self.buf:
                self.buf.seek(sig["offset"] + base)
                self.buf.pushunit()
                self.buf.setunit(sig["length"])

                match sig["format"]:
                    case 1:
                        sig["reserved"] = self.buf.rh(4)
                        sig["length"] = self.buf.ru32()
                        sig["data"] = utils.read_der(self.buf)
                    case _:
                        sig["unknown"] = True
                        with self.subunit():
                            sig["data"] = chew(self.buf)

                self.buf.skipunit()
                self.buf.popunit()

            dsig["signatures"].append(sig)

        self.buf.seek(((most_offset + 3) // 4) * 4)

        return dsig

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "truetype"

        self.buf.skip(4)

        num_tables = self.buf.ru16()
        meta["table-count"] = num_tables
        meta["search-range"] = self.buf.ru16()
        meta["entry-selector"] = self.buf.ru16()
        meta["range-shift"] = self.buf.ru16()

        meta["tables"] = []
        for i in range(0, num_tables):
            table = {}

            table["tag"] = self.buf.rs(4, "latin-1")
            table["checksum"] = self.buf.rh(4)
            table["offset"] = self.buf.ru32()
            table["length"] = self.buf.ru32()

            with self.buf:
                self.buf.seek(table["offset"])
                self.buf.setunit(table["length"])

                table["data"] = {}
                match table["tag"]:
                    case "OS/2":
                        table["data"]["version"] = self.buf.ru16()
                        table["data"]["x-avg-char-width"] = self.buf.ri16()
                        table["data"]["us-weight-class"] = self.buf.ru16()
                        table["data"]["us-width-class"] = self.buf.ru16()
                        table["data"]["fs-type"] = self.buf.ri16()
                        table["data"]["y-subscript-x-size"] = self.buf.ri16()
                        table["data"]["y-subscript-y-size"] = self.buf.ri16()
                        table["data"]["y-subscript-x-offset"] = self.buf.ri16()
                        table["data"]["y-subscript-y-offset"] = self.buf.ri16()
                        table["data"]["y-superscript-x-size"] = self.buf.ri16()
                        table["data"]["y-superscript-y-size"] = self.buf.ri16()
                        table["data"]["y-superscript-x-offset"] = self.buf.ri16()
                        table["data"]["y-superscript-y-offset"] = self.buf.ri16()
                        table["data"]["y-strikeout-size"] = self.buf.ri16()
                        table["data"]["y-strikeout-position"] = self.buf.ri16()
                        table["data"]["s-family-class"] = self.buf.ri16()
                        table["data"]["panose"] = self.buf.rh(10)
                        table["data"]["ul-unicode-range"] = self.buf.rh(16)
                        table["data"]["ach-vend-id"] = self.buf.rs(4)
                        table["data"]["fs-selection"] = self.buf.ru16()
                        table["data"]["fs-first-char-index"] = self.buf.ru16()
                        table["data"]["fs-last-char-index"] = self.buf.ru16()

                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["s-typo-descender"] = self.buf.ri16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["s-typo-line-gap"] = self.buf.ri16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["us-win-ascent"] = self.buf.ru16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["us-win-descent"] = self.buf.ru16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 4:
                            table["data"]["ul-code-page-range1"] = self.buf.ru32()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 4:
                            table["data"]["ul-code-page-range2"] = self.buf.ru32()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["sx-height"] = self.buf.ri16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["s-cap-height"] = self.buf.ri16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["us-default-char"] = self.buf.ru16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["us-break-char"] = self.buf.ru16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["us-max-context"] = self.buf.ru16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["us-lower-point-size"] = self.buf.ru16()
                        else:
                            self.buf.skipunit()
                        if self.buf.unit is None or self.buf.unit >= 2:
                            table["data"]["us-upper-point-size"] = self.buf.ru16()
                        else:
                            self.buf.skipunit()
                    case "cvt ":
                        table["data"]["entry-count"] = cast(int, self.buf.unit) // 4
                    case "fpgm" | "prep":
                        table["data"]["instruction-count"] = self.buf.unit
                    case "head":
                        table["data"]["version"] = str(self.buf.ru16()) + "." + str(self.buf.ru16())
                        table["data"]["revision"] = self.buf.ru32()
                        table["data"]["checksum-adjustment"] = self.buf.ru32()
                        table["data"]["magic"] = self.buf.rh(4)
                        table["data"]["flags"] = self.buf.rh(2)
                        table["data"]["units-per-em"] = self.buf.ru16()
                        table["data"]["created"] = utils.mp4_time_to_iso(
                            self.buf.ri64() if self.buf.pu32() == 0 else self.buf.ri64l()
                        )
                        table["data"]["modified"] = utils.mp4_time_to_iso(
                            self.buf.ri64() if self.buf.pu32() == 0 else self.buf.ri64l()
                        )
                        table["data"]["x-min"] = self.buf.ri16()
                        table["data"]["y-min"] = self.buf.ri16()
                        table["data"]["x-max"] = self.buf.ri16()
                        table["data"]["y-max"] = self.buf.ri16()

                        mac_style = self.buf.ru16()
                        table["data"]["mac-style"] = {
                            "raw": mac_style,
                            "bold": bool(mac_style & 0x01),
                            "italic": bool(mac_style & 0x02),
                            "underline": bool(mac_style & 0x04),
                            "outline": bool(mac_style & 0x08),
                            "shadow": bool(mac_style & 0x10),
                            "condensed": bool(mac_style & 0x20),
                            "extended": bool(mac_style & 0x40),
                        }

                        table["data"]["lowest-rec-ppem"] = self.buf.ru16()
                        table["data"]["font-direction-hint"] = self.buf.ri16()
                        table["data"]["index-to-loc-format"] = self.buf.ri16()
                        table["data"]["glyph-data-format"] = self.buf.ri16()
                    case "hhea":
                        table["data"]["version"] = str(self.buf.ru16()) + "." + str(self.buf.ru16())
                        table["data"]["ascent"] = self.buf.ri16()
                        table["data"]["descent"] = self.buf.ri16()
                        table["data"]["line-gap"] = self.buf.ri16()
                        table["data"]["advance-width-max"] = self.buf.ru16()
                        table["data"]["min-left-side-bearing"] = self.buf.ri16()
                        table["data"]["min-right-side-bearing"] = self.buf.ri16()
                        table["data"]["x-max-extent"] = self.buf.ri16()
                        table["data"]["caret-slope-rise"] = self.buf.ri16()
                        table["data"]["caret-slope-run"] = self.buf.ri16()
                        table["data"]["caret-offset"] = self.buf.ri16()
                        table["data"]["reserved"] = self.buf.ri16()
                        table["data"]["reserved"] = self.buf.ri16()
                        table["data"]["reserved"] = self.buf.ri16()
                        table["data"]["reserved"] = self.buf.ri16()
                        table["data"]["metric-data-format"] = self.buf.ri16()
                        table["data"]["num-of-long-hor-metrics"] = self.buf.ru16()
                    case "maxp":
                        table["data"]["version"] = str(self.buf.ru16()) + "." + str(self.buf.ru16())
                        table["data"]["num-glyphs"] = self.buf.ru16()
                        if table["data"]["version"] != "0.5" and self.buf.hasunit():
                            table["data"]["max-points"] = self.buf.ru16()
                            table["data"]["max-contours"] = self.buf.ru16()
                            table["data"]["max-component-points"] = self.buf.ru16()
                            table["data"]["max-component-contours"] = self.buf.ru16()
                            table["data"]["max-zones"] = self.buf.ru16()
                            table["data"]["max-twilight-points"] = self.buf.ru16()
                            table["data"]["max-storage"] = self.buf.ru16()
                            table["data"]["max-function-defs"] = self.buf.ru16()
                            table["data"]["max-instruction-defs"] = self.buf.ru16()
                            table["data"]["max-stack-elements"] = self.buf.ru16()
                            table["data"]["max-size-of-instructions"] = self.buf.ru16()
                            table["data"]["max-component-elements"] = self.buf.ru16()
                            table["data"]["max-component-depth"] = self.buf.ru16()
                    case "name":
                        offset = self.buf.tell()
                        table["data"]["format"] = self.buf.ru16()
                        count = self.buf.ru16()
                        table["data"]["count"] = count
                        string_offset = self.buf.ru16()
                        table["data"]["string-offset"] = string_offset

                        table["data"]["entries"] = []
                        for i in range(0, count):
                            entry: dict = {}
                            platform_id = self.buf.ru16()
                            entry["platform"] = {
                                0: "Unicode",
                                1: "Macintosh",
                                2: "Reserved",
                                3: "Microsoft",
                            }.get(platform_id, "Unknown") + f" (0x{hex(platform_id)[2:].zfill(4)})"

                            platform_specific_id = self.buf.ru16()
                            entry["platform-specific"] = {
                                0: {
                                    0: "Version 1.0 semantics",
                                    1: "Version 1.1 semantics",
                                    2: "ISO 10646 1993 semantics (deprecated)",
                                    3: "Unicode 2.0 or later semantics (BMP only)",
                                    4: "Unicode 2.0 or later semantics (non-BMP characters allowed)",
                                },
                                1: {
                                    0: "Roman",
                                    1: "Japanese",
                                    2: "Traditional Chinese",
                                    3: "Korean",
                                    4: "Arabic",
                                    5: "Hebrew",
                                    6: "Greek",
                                    7: "Russian",
                                    8: "RSymbol",
                                    9: "Devanagari",
                                    10: "Gurmukhi",
                                    11: "Gujarati",
                                    12: "Oriya",
                                    13: "Bengali",
                                    14: "Tamil",
                                    15: "Telugu",
                                    16: "Kannada",
                                    17: "Malayalam",
                                    18: "Sinhalese",
                                    19: "Burmese",
                                    20: "Khmer",
                                    21: "Thai",
                                    22: "Laotian",
                                    23: "Georgian",
                                    24: "Armenian",
                                    25: "Simplified Chinese",
                                    26: "Tibetan",
                                    27: "Mongolian",
                                    28: "Geez",
                                    29: "Slavic",
                                    30: "Vietnamese",
                                    31: "Sindhi",
                                    32: "(Uninterpreted)",
                                },
                                3: {
                                    0: "Symbol",
                                    1: "Unicode BMP",
                                    2: "ShiftJIS",
                                    3: "PRC",
                                    4: "Big5",
                                    5: "Wansung",
                                    6: "Johab",
                                    7: "Reserved",
                                    8: "Reserved",
                                    9: "Reserved",
                                    10: "Unicode full repertoire",
                                },
                            }.get(platform_id, {}).get(
                                platform_specific_id, "Unknown"
                            ) + f" (0x{hex(platform_specific_id)[2:].zfill(4)})"

                            language_id = self.buf.ru16()
                            entry["language"] = {
                                1: {
                                    0: "English",
                                    1: "French",
                                    2: "German",
                                    3: "Italian",
                                    4: "Dutch",
                                    5: "Swedish",
                                    6: "Spanish",
                                    7: "Danish",
                                    8: "Portuguese",
                                    9: "Norwegian",
                                    10: "Hebrew",
                                    11: "Japanese",
                                    12: "Arabic",
                                    13: "Finnish",
                                    14: "Greek",
                                    15: "Icelandic",
                                    16: "Maltese",
                                    17: "Turkish",
                                    18: "Croatian",
                                    19: "Chinese (traditional)",
                                    20: "Urdu",
                                    21: "Hindi",
                                    22: "Thai",
                                    23: "Korean",
                                    24: "Lithuanian",
                                    25: "Polish",
                                    26: "Hungarian",
                                    27: "Estonian",
                                    28: "Latvian",
                                    29: "Sami",
                                    30: "Faroese",
                                    31: "Farsi/Persian",
                                    32: "Russian",
                                    33: "Chinese (simplified)",
                                    34: "Flemish",
                                    35: "Irish Gaelic",
                                    36: "Albanian",
                                    37: "Romanian",
                                    38: "Czech",
                                    39: "Slovak",
                                    40: "Slovenian",
                                    41: "Yiddish",
                                    42: "Serbian",
                                    43: "Macedonian",
                                    44: "Bulgarian",
                                    45: "Ukrainian",
                                    46: "Byelorussian",
                                    47: "Uzbek",
                                    48: "Kazakh",
                                    49: "Azerbaijani (Cyrillic script)",
                                    50: "Azerbaijani (Arabic script)",
                                    51: "Armenian",
                                    52: "Georgian",
                                    53: "Moldavian",
                                    54: "Kirghiz",
                                    55: "Tajiki",
                                    56: "Turkmen",
                                    57: "Mongolian (Mongolian script)",
                                    58: "Mongolian (Cyrillic script)",
                                    59: "Pashto",
                                    60: "Kurdish",
                                    61: "Kashmiri",
                                    62: "Sindhi",
                                    63: "Tibetan",
                                    64: "Nepali",
                                    65: "Sanskrit",
                                    66: "Marathi",
                                    67: "Bengali",
                                    68: "Assamese",
                                    69: "Gujarati",
                                    70: "Punjabi",
                                    71: "Oriya",
                                    72: "Malayalam",
                                    73: "Kannada",
                                    74: "Tamil",
                                    75: "Telugu",
                                    76: "Sinhalese",
                                    77: "Burmese",
                                    78: "Khmer",
                                    79: "Lao",
                                    80: "Vietnamese",
                                    81: "Indonesian",
                                    82: "Tagalog",
                                    83: "Malay (Roman script)",
                                    84: "Malay (Arabic script)",
                                    85: "Amharic",
                                    86: "Tigrinya",
                                    87: "Galla",
                                    88: "Somali",
                                    89: "Swahili",
                                    90: "Kinyarwanda/Ruanda",
                                    91: "Rundi",
                                    92: "Nyanja/Chewa",
                                    93: "Malagasy",
                                    94: "Esperanto",
                                    128: "Welsh",
                                    129: "Basque",
                                    130: "Catalan",
                                    131: "Latin",
                                    132: "Quechua",
                                    133: "Guarani",
                                    134: "Aymara",
                                    135: "Tatar",
                                    136: "Uighur",
                                    137: "Dzongkha",
                                    138: "Javanese (Roman script)",
                                    139: "Sundanese (Roman script)",
                                    140: "Galician",
                                    141: "Afrikaans",
                                    142: "Breton",
                                    143: "Inuktitut",
                                    144: "Scottish Gaelic",
                                    145: "Manx Gaelic",
                                    146: "Irish Gaelic (with dot above)",
                                    147: "Tongan",
                                    148: "Greek (polytonic)",
                                    149: "Greenlandic",
                                    150: "Azerbaijani (Roman script)",
                                },
                                3: constants.MICROSOFT_LCIDS,
                            }.get(platform_id, {}).get(language_id, "Unknown") + f" (0x{hex(language_id)[2:].zfill(4)})"

                            name_id = self.buf.ru16()
                            entry["name"] = {
                                0: "Copyright notice",
                                1: "Font Family",
                                2: "Font Subfamily",
                                3: "Unique subfamily identification",
                                4: "Full name of the font",
                                5: "Version of the name table",
                                6: "PostScript name of the font",
                                7: "Trademark notice",
                                8: "Manufacturer name",
                                9: "Designer; name of the designer of the typeface",
                                10: "Description of the typeface",
                                11: "URL of the font vendor",
                                12: "URL of the font designer",
                                13: "License description",
                                14: "License information URL",
                                15: "Reserved",
                                16: "Preferred Family",
                                17: "Preferred Subfamily",
                                18: "Compatible Full",
                                19: "Sample text",
                                20: "Defined by OpenType",
                                21: "Defined by OpenType",
                                22: "Defined by OpenType",
                                23: "Defined by OpenType",
                                24: "Defined by OpenType",
                                25: "Variations PostScript Name Prefix",
                            }.get(name_id, "Unknown") + f" (0x{hex(name_id)[2:].zfill(4)})"

                            text_length = self.buf.ru16()
                            entry["length"] = text_length
                            text_offset = self.buf.ru16()
                            entry["offset"] = text_offset

                            with self.buf:
                                self.buf.seek(offset + string_offset + text_offset)
                                text_length = ((text_length + 1) >> 1) << 1
                                entry["text"] = self.buf.rs(
                                    text_length,
                                    "utf-16be" if (platform_id in (0, 3)) else "latin-1",
                                )

                            table["data"]["entries"].append(entry)
                    case "post":
                        table["data"]["format"] = str(self.buf.ru16()) + "." + str(self.buf.ru16())
                        table["data"]["italic-angle"] = str(self.buf.ru16()) + "." + str(self.buf.ru16())
                        table["data"]["underline-position"] = self.buf.ri16()
                        table["data"]["underline-thickness"] = self.buf.ri16()
                        table["data"]["is-fixed-pitch"] = self.buf.ru32()
                        table["data"]["min-mem-type42"] = self.buf.ru32()
                        table["data"]["max-mem-type42"] = self.buf.ru32()
                        table["data"]["min-mem-type1"] = self.buf.ru32()
                        table["data"]["max-mem-type1"] = self.buf.ru32()
                    case "cmap":
                        table["data"]["version"] = self.buf.ru16()
                        table["data"]["subtable-count"] = self.buf.ru16()
                    case "gasp":
                        table["data"]["version"] = self.buf.ru16()
                        table["data"]["range-count"] = self.buf.ru16()
                    case "meta":
                        base = self.buf.tell()

                        table["data"]["version"] = self.buf.ru32()
                        table["data"]["flags"] = self.buf.ru32()
                        table["data"]["reserved"] = self.buf.ru32()
                        table["data"]["tag-count"] = self.buf.ru32()

                        table["data"]["tags"] = []
                        for i in range(0, table["data"]["tag-count"]):
                            tag = {}
                            tag["type"] = self.buf.rs(4)
                            tag["offset"] = self.buf.ru32()
                            tag["length"] = self.buf.ru32()

                            with self.buf:
                                self.buf.seek(tag["offset"] + base)
                                tag["data"] = utils.decode(self.buf.read(tag["length"]))

                            table["data"]["tags"].append(tag)
                    case "PCLT":
                        table["data"]["major-version"] = self.buf.ru16()
                        table["data"]["minor-version"] = self.buf.ru16()
                        table["data"]["font-vendor"] = self.buf.rs(1)
                        table["data"]["font-number"] = self.buf.ru24()
                        table["data"]["pitch"] = self.buf.ru16()
                        table["data"]["x-height"] = self.buf.ru16()
                        table["data"]["style"] = self.buf.ru16()
                        table["data"]["type-family"] = self.buf.ru16()
                        table["data"]["cap-height"] = self.buf.ru16()
                        table["data"]["symbol-set"] = self.buf.ru16()
                        table["data"]["typeface"] = self.buf.rs(16)
                        table["data"]["character-complement"] = self.buf.rh(8)
                        table["data"]["file-name"] = self.buf.rs(6)
                        table["data"]["stroke-weight"] = self.buf.ru8()
                        table["data"]["width-type"] = self.buf.ru8()
                        table["data"]["serif-style"] = self.buf.ru8()
                        table["data"]["reserved"] = self.buf.ru8()
                    case "DSIG":
                        table["data"] = self.read_dsig()
                    case "Wasm":
                        table["data"] = chew(self.buf.readunit())
                    case "FFTM":
                        table["data"]["version"] = self.buf.ru32()
                        table["data"]["fontforge-timestamp"] = utils.mp4_time_to_iso(self.buf.ru64())
                        table["data"]["creation-timestamp"] = utils.mp4_time_to_iso(self.buf.ru64())
                        table["data"]["modification-timestamp"] = utils.mp4_time_to_iso(self.buf.ru64())
                    case "glyf" | "hmtx" | "loca" | "GDEF" | "GPOS" | "GSUB" | "hdmx" | "VDMX" | "JSTF" | "LTSH":
                        # not really parsable as it's the raw glyph data
                        pass
                    case _:
                        table["unknown"] = True

            meta["tables"].append(table)

        for table in meta["tables"]:
            if table["offset"] + table["length"] > self.buf.tell():
                self.buf.seek(table["offset"])
                self.buf.skip(table["length"])

        if self.buf.available() > 4 and self.buf.pu64() & 0xffffffffff00fffe == 0x0000000100000000:
            meta["tables"].append({"tag": "DSIG", "data": self.read_dsig()})

        if self.buf.tell() % 4 != 0:
            self.buf.skip(4 - (self.buf.tell() % 4))

        return meta


@module.register
class Woff2Module(module.RuminantModule):
    dev = True
    desc = "WOFF2 font files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"wOF2"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "woff2"

        self.buf.skip(4)
        meta["header"] = {}
        meta["header"]["sfnt-version"] = self.buf.ru32()
        meta["header"]["length"] = self.buf.ru32()

        self.buf.pasunit(meta["header"]["length"] - 12)

        meta["header"]["table-count"] = self.buf.ru16()
        meta["header"]["reserved"] = self.buf.ru16()
        meta["header"]["sfnt-size"] = self.buf.ru32()
        meta["header"]["compressed-size"] = self.buf.ru32()
        temp = self.buf.ru16()
        meta["header"]["version"] = f"{temp}.{self.buf.ru16()}"
        meta["header"]["meta-offset"] = self.buf.ru32()
        meta["header"]["meta-size"] = self.buf.ru32()
        meta["header"]["priv-offset"] = self.buf.ru32()
        meta["header"]["priv-size"] = self.buf.ru32()

        self.buf.sapunit()

        return meta
