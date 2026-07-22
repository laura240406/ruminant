from . import chew
from .. import module, utils, constants, ruminant_types
from ..buf import Buf, UnitException
import zlib
import datetime
import gzip


@module.register
class IRBModule(module.RuminantModule):
    desc = "IRB chunks inserted into JPEG files by Adobe Photoshop."

    RESOURCE_IDS = {
        1000: "Number of channels, rows, columns, depth, and mode (obsolete)",
        1001: "Macintosh print manager print info record",
        1002: "Macintosh page format information (obsolete)",
        1003: "Indexed color table (obsolete)",
        1005: "Resolution info (obsolete)",
        1006: "Names of alpha channels",
        1007: "Display info (obsolete)",
        1008: "Caption string",
        1009: "Border information",
        1010: "Background color",
        1011: "Print flags",
        1012: "Grayscale/multichannel halftoning info",
        1013: "Color halftoning info",
        1014: "Duotone halftoning info",
        1015: "Grayscale/multichannel transfer function",
        1016: "Color transfer functions",
        1017: "Duotone transfer functions",
        1018: "Duotone image info",
        1019: "Effective black and white values",
        1021: "EPS options",
        1022: "Quick mask info",
        1024: "Layer state info",
        1025: "Working path",
        1026: "Layers group info",
        1028: "IPTC-NAA record",
        1029: "Image mode for JPEG",
        1030: "JPEG quality",
        1032: "Grid and guides",
        1033: "Thumbnail (raw RGB)",
        1034: "Copyright flag",
        1035: "URL",
        1036: "Thumbnail (JPEG compressed)",
        1037: "Global angle",
        1038: "Color samplers resource (obsolete)",
        1039: "ICC profile",
        1040: "Watermark",
        1041: "ICC untagged profile",
        1042: "Effects visible",
        1043: "Spot Halftone",
        1044: "Document-specific IDs seed number",
        1045: "Unicode alpha names",
        1046: "Indexed color table count",
        1047: "Transparency index",
        1049: "Global altitude",
        1050: "Slices",
        1051: "Workflow URL",
        1052: "Jump to XPEP",
        1053: "Alpha identifiers",
        1054: "URL list",
        1057: "Version info",
        1058: "EXIF data",
        1059: "EXIF data",
        1060: "XMP metadata",
        1061: "Caption digest",
        1062: "Print scale",
        1064: "Pixel aspect ratio",
        1065: "Layer comps",
        1066: "Alternate duotone colors",
        1067: "Alternate spot colors",
        1069: "Layer selection ID(s)",
        1070: "HDR toning information",
        1071: "Print info",
        1072: "Layer group(s) enabled ID",
        1073: "Color samplers resource",
        1074: "Measurement scale",
        1075: "Timeline information",
        1076: "Sheet disclosure",
        1077: "Display info",
        1078: "Onion skins",
        1080: "Count information",
        1082: "Print information",
        1083: "Print style",
        1084: "Macintosh NSPrintInfo",
        1085: "Windows DEVMODE",
        1086: "Auto save file path",
        1087: "Auto save format",
        1088: "Path selection state",
        2999: "Name of clipping path",
        3000: "Origin path info",
        7000: "Image Ready variables",
        7001: "Image Ready data sets",
        7002: "Image Ready default selected state",
        7003: "Image Ready 7 rollover expanded state",
        7004: "Image Ready rollover expanded state",
        7005: "Image Ready save layer settings",
        7006: "Image Ready version",
        8000: "Lightroom workflow",
        10000: "Print flags information",
    }

    for i in range(2000, 2998):
        RESOURCE_IDS[i] = "Path information"

    for i in range(4000, 5000):
        RESOURCE_IDS[i] = "Plug-In resource(s)"

    COLOR_SPACES = {
        0: "RGB",
        1: "HSB",
        2: "CMYK",
        7: "Lab",
        8: "Grayscale",
        9: "Wide CMYK",
        10: "HSL",
        11: "HSB (Alt)",
        12: "Multichannel",
        13: "Duotone",
        14: "Lab (Alt)",
    }

    # not vetted yet, could be horribly wrong
    RECORD_DATASET_NAMES = {
        1: {
            0: "Model Version",
            5: "Destination",
            20: "File Format",
            22: "File Format Version",
            30: "Service Identifier",
            40: "Envelope Number",
            50: "Product ID",
            60: "Envelope Priority",
            70: "Date Sent",
            80: "Time Sent",
            90: "Coded Character Set",
            100: "UNO (Unique Name of Object)",
            120: "ARM Identifier",
            122: "ARM Version",
        },
        2: {
            0: "Version Number",
            3: "Object Type Reference",
            5: "Object Name",
            7: "Edit Status",
            8: "Editorial Update",
            10: "Urgency",
            12: "Subject Reference",
            15: "Category",
            20: "Supplemental Category",
            22: "Fixture Identifier",
            25: "Keywords",
            26: "Content Location Code",
            27: "Content Location Name",
            30: "Release Date",
            35: "Release Time",
            37: "Expiration Date",
            38: "Expiration Time",
            40: "Special Instructions",
            42: "Action Advised",
            45: "Reference Service",
            47: "Reference Date",
            50: "Reference Number",
            55: "Date Created",
            60: "Time Created",
            62: "Digital Creation Date",
            63: "Digital Creation Time",
            65: "Originating Program",
            70: "Program Version",
            75: "Object Cycle",
            80: "By-line",
            85: "By-line Title",
            90: "City",
            92: "Sublocation",
            95: "Province/State",
            100: "Country/Primary Location Code",
            101: "Country/Primary Location Name",
            103: "Original Transmission Reference",
            105: "Headline",
            110: "Credit",
            115: "Source",
            116: "Copyright Notice",
            118: "Contact",
            120: "Caption/Abstract",
            122: "Caption Writer/Editor",
            130: "Image Type",
            131: "Image Orientation",
            135: "Language Identifier",
            150: "Audio Type",
            151: "Audio Sampling Rate",
            152: "Audio Sampling Resolution",
            153: "Audio Duration",
            154: "Audio Outcue",
            184: "Job ID",
            185: "Master Document ID",
            186: "Short Document ID",
            187: "Unique Document ID",
            188: "Owner ID",
        },
        3: {
            0: "Record Version",
            10: "Picture Number",
            20: "Pixels Per Line",
            30: "Number Of Lines",
            40: "Pixel Size In Scanning Direction",
            50: "Pixel Size Perpendicular To Scanning Direction",
            55: "Supplement Type",
            60: "Colour Representation",
            64: "Interchange Colour Space",
            65: "Colour Sequence",
            66: "ICC Input Colour Profile",
            70: "Colour Calibration Matrix Table",
            80: "Lookup Table",
            84: "Number Of Index Entries",
            85: "Colour Palette",
            86: "Number Of Bits Per Sample",
            90: "Sampling Structure",
            100: "Scanning Direction",
            102: "Image Rotation",
            110: "Data Compression Method",
            120: "Quantisation Method",
            125: "End Points",
            130: "Excursion Tolerance",
            135: "Bits Per Component",
            140: "Maximum Density Range",
            145: "Gamma Compensated Value",
        },
    }

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(18) == b"Photoshop 3.0\x008BIM" or buf.peek(4) == b"8BIM"

    def read_key(self):
        length = self.buf.ru32()
        if length > 0:
            return self.buf.rs(length)
        else:
            return self.buf.rs(4)

    def read_unicode(self):
        return self.buf.read(self.buf.ru32() * 2).decode("utf-16be").rstrip("\x00")

    def read_item(self, typ):
        match typ:
            case "bool":
                return bool(self.buf.ru8()), True
            case "Objc":
                return self.read_descriptor()
            case "doub":
                return self.buf.rf64(), True
            case "UntF":
                return {"type": self.buf.rs(4), "value": self.buf.rf64()}, True
            case "enum":
                return {"type": self.read_key(), "enum": self.read_key()}, True
            case "TEXT":
                return self.read_unicode(), True
            case "long":
                return self.buf.ru32(), True
            case "VlLs":
                count = self.buf.ru32()
                typ = self.buf.rs(4)

                lis = []
                for i in range(0, count):
                    value, success = self.read_item(typ)

                    if not success:
                        return lis, False

                    lis.append(value)

                return lis, True
            case _:
                return {"unknown": typ}, False

    def read_descriptor(self, top=False):
        desc = {}

        if top:
            desc["version"] = self.buf.ru32()
        desc["name"] = self.read_unicode()
        desc["class-id"] = self.read_key()
        desc["item-count"] = self.buf.ru32()

        desc["items"] = []
        for i in range(0, desc["item-count"]):
            item = {}
            item["key"] = self.read_key()
            item["type"] = self.buf.rs(4)
            desc["items"].append(item)

            item["data"], success = self.read_item(item["type"])
            if not success:
                return desc, False

        return desc, True

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "irb"
        meta["data"] = {}

        if self.buf.peek(1) == b"P":
            self.buf.skip(14)

        meta["data"]["blocks"] = []
        while self.buf.available():
            header = self.buf.read(4)
            if header != b"8BIM":
                break

            block: dict = {}

            resource_id = self.buf.ru16()
            block["resource-id"] = self.RESOURCE_IDS.get(resource_id, "Unknown") + f" (0x{hex(resource_id)[2:].zfill(4)})"
            name_length = self.buf.ru8()
            block["resource-name"] = self.buf.rs(name_length)
            if name_length % 2 == 0:
                self.buf.skip(1)

            data_length = self.buf.ru32()
            block["data-length"] = data_length

            self.buf.setunit((data_length + 1) & 0xfffffffe)

            block["data"] = {}
            try:
                match resource_id:
                    case 1036:
                        block["data"]["format"] = self.buf.ru32()
                        block["data"]["width"] = self.buf.ru32()
                        block["data"]["height"] = self.buf.ru32()
                        block["data"]["width-bytes"] = self.buf.ru32()
                        block["data"]["total-size"] = self.buf.ru32()
                        block["data"]["compressed-size"] = self.buf.ru32()
                        block["data"]["bit-depth"] = self.buf.ru16()
                        block["data"]["planes"] = self.buf.ru16()

                        with self.buf.sub(block["data"]["compressed-size"]):
                            block["data"]["image"] = chew(self.buf)
                    case 1005:
                        block["data"]["horizontal-dpi"] = self.buf.rfp32()
                        horizontal_unit = self.buf.ru16()
                        block["data"]["horizontal-unit"] = {
                            "raw": horizontal_unit,
                            "name": {
                                1: "inches",
                                2: "centimeters",
                                3: "points",
                                4: "picas",
                                5: "columns",
                            }.get(horizontal_unit, "unknown"),
                        }
                        block["data"]["horizontal-scale"] = self.buf.ru16()

                        block["data"]["vertical-dpi"] = self.buf.rfp32()
                        vertical_unit = self.buf.ru16()
                        block["data"]["vertical-unit"] = {
                            "raw": vertical_unit,
                            "name": {
                                1: "Inches",
                                2: "Centimeters",
                                3: "Points",
                                4: "Picas",
                                5: "Columns",
                            }.get(vertical_unit, "Unknown"),
                        }
                        block["data"]["vertical-scale"] = self.buf.ru16()
                    case 1010:
                        color_space = self.buf.ru16()
                        block["data"]["color-space"] = {
                            "raw": color_space,
                            "name": self.COLOR_SPACES.get(color_space, "Unknown"),
                        }
                        block["data"]["components"] = [self.buf.ru16() for _ in range(0, 4)]
                    case 1011:
                        flags = self.buf.ru16()
                        block["data"]["flags"] = {
                            "raw": flags,
                            "show-image": bool(flags & 1),
                        }
                    case 1037:
                        block["data"]["angle"] = self.buf.ru32()
                    case 1044:
                        block["data"]["seed"] = self.buf.rh(4)
                    case 1049:
                        block["data"]["altitude"] = self.buf.ru32()
                    case 1028:
                        block["data"]["records"] = []
                        while self.buf.unit is not None and self.buf.unit > 2:
                            self.buf.skip(1)
                            record = {}

                            record_number = self.buf.ru8()
                            record["record-number"] = utils.unraw(
                                record_number,
                                1,
                                {
                                    1: "Envelope Record",
                                    2: "Application Record",
                                    3: "Pre‑ObjectData Descriptor Record",
                                    4: "ObjectData Descriptor Record",
                                    5: "Pre‑Data Descriptor Record",
                                    6: "Data Descriptor Record",
                                    7: "Pre‑ObjectData Descriptor Record",
                                    8: "Object Record",
                                    9: "Post‑Object Descriptor Record",
                                },
                            )

                            dataset_number = self.buf.ru8()
                            record["dataset-number"] = utils.unraw(
                                dataset_number,
                                1,
                                self.RECORD_DATASET_NAMES.get(record_number, {}),
                            )

                            data_length = self.buf.ru16()
                            if data_length & 0x8000:
                                data_length = int.from_bytes(self.buf.read(data_length & 0x7fff), "big")
                            record["data-length"] = data_length

                            record["data"] = {}
                            match (record_number, dataset_number):
                                case (2, 0):
                                    record["data"]["version"] = self.buf.ru16()
                                case (2, _):
                                    record["data"]["text"] = self.buf.rs(data_length)
                                case _:
                                    record["data"]["blob"] = self.buf.rh(data_length)

                            block["data"]["records"].append(record)
                    case 1061:
                        block["data"]["digest"] = self.buf.rh(16)
                    case 1035:
                        block["data"]["url"] = self.buf.rs(self.buf.unit)
                    case 1062:
                        block["data"]["style"] = utils.unraw(
                            self.buf.ru16(),
                            2,
                            {0: "centered", 1: "size to fit", 3: "user defined"},
                        )
                        block["data"]["x"] = self.buf.rf32()
                        block["data"]["y"] = self.buf.rf32()
                        block["data"]["scale"] = self.buf.rf32()
                    case 1006:
                        block["data"]["name"] = self.buf.rs(self.buf.ru8())
                    case 1045:
                        block["data"]["name"] = self.buf.rs(self.buf.ru32() * 2, encoding="utf-16be")
                    case 10000:
                        block["data"]["version"] = self.buf.ru16()
                        block["data"]["center-crop-marks"] = self.buf.ru8()
                        block["data"]["reserved"] = self.buf.ru8()
                        block["data"]["bleed-width"] = self.buf.ru32()
                        block["data"]["bleed-width-scale"] = self.buf.ru16()
                    case 1024:
                        block["data"]["index"] = self.buf.ru16()
                    case 1057:
                        block["data"]["version"] = self.buf.ru32()
                        block["data"]["has-real-merged-data"] = bool(self.buf.ru8())
                        block["data"]["writer"] = self.buf.read(self.buf.ru32() * 2).decode("utf-16be").rstrip("\x00")
                        block["data"]["reader"] = self.buf.read(self.buf.ru32() * 2).decode("utf-16be").rstrip("\x00")
                        block["data"]["file-version"] = self.buf.ru32()
                    case 1064:
                        block["data"]["version"] = self.buf.ru32()
                        block["data"]["x-over-y"] = self.buf.rf64()
                    case 1050:
                        block["data"]["version"] = self.buf.ru32()
                        match block["data"]["version"]:
                            case 6:
                                block["data"]["bounding-rect"] = [self.buf.ru32() for i in range(0, 4)]
                                block["data"]["name"] = self.read_unicode()
                                block["data"]["slice-count"] = self.buf.ru32()

                                block["data"]["slices"] = []
                                for i in range(0, block["data"]["slice-count"]):
                                    slic: dict = {}
                                    slic["id"] = self.buf.ru32()
                                    slic["group-id"] = self.buf.ru32()
                                    slic["origin"] = self.buf.ru32()
                                    if slic["origin"]:
                                        slic["associated-layer-id"] = self.buf.ru32()
                                    slic["name"] = self.read_unicode()
                                    slic["type"] = self.buf.rs(4)
                                    slic["rect"] = [self.buf.ru32() for i in range(0, 4)]
                                    slic["url"] = self.read_unicode()
                                    slic["target"] = self.read_unicode()
                                    slic["message"] = self.read_unicode()
                                    slic["alt-text"] = self.read_unicode()
                                    slic["cell-text-is-html"] = bool(self.buf.ru8())
                                    slic["cell-text"] = self.read_unicode()
                                    slic["horizontal-alignment"] = self.buf.ru32()
                                    slic["vertical-alignment"] = self.buf.ru32()
                                    slic["color"] = self.buf.rh(4)
                                    slic["descriptor"], success = self.read_descriptor(True)
                                    if not success:
                                        slic["unknown"] = True

                                    block["data"]["slices"].append(slic)
                            case _:
                                block["data"]["unknown"] = True
                    case 1034:
                        block["data"]["is-copyrighted"] = bool(self.buf.ru8())
                    case 1058:
                        with self.buf.subunit():
                            block["data"]["exif"] = chew(self.buf)

                        self.buf.skipunit()
                    case 1060:
                        block["data"]["xmp"] = utils.xml_to_dict(self.buf.read(self.buf.unit))
                    case 1039:
                        with self.buf.subunit():
                            block["data"]["profile"] = chew(self.buf)

                        self.buf.skipunit()
                    case 1025:
                        block["data"]["paths"] = []

                        little = False
                        while self.buf.unit is not None and self.buf.unit >= 26:
                            path = {}

                            selector = self.buf.ru16()
                            if little or selector > 0xff:
                                selector >>= 8
                                little = True

                            path["selector"] = utils.unraw(
                                selector,
                                2,
                                {
                                    0x0000: "Closed subpath length record",
                                    0x0001: "Closed subpath Bezier knot, linked",
                                    0x0002: "Closed subpath Bezier knot, unlinked",
                                    0x0003: "Open subpath length record",
                                    0x0004: "Open subpath Bezier knot, linked",
                                    0x0005: "Open subpath Bezier knot, unlinked",
                                    0x0006: "Path fill rule record",
                                    0x0007: "Clipboard record",
                                    0x0008: "Initial fill rule record",
                                },
                                True,
                            )

                            self.buf.pasunit(24)

                            path["payload"] = {}
                            match selector:
                                case 0x0006:
                                    pass
                                case 0x0008:
                                    path["payload"]["start-with-all-pixels"] = bool(self.buf.ru16())
                                case 0x0000 | 0x0003:
                                    path["payload"]["point-count"] = self.buf.ru16l() if little else self.buf.ru16()
                                case 0x0001 | 0x0002 | 0x0004 | 0x0005:
                                    path["payload"]["preceding"] = (self.buf.ri32l() if little else self.buf.ri32()) / 16777216
                                    path["payload"]["anchor"] = (self.buf.ri32l() if little else self.buf.ri32()) / 16777216
                                    path["payload"]["leaving"] = (self.buf.ri32l() if little else self.buf.ri32()) / 16777216
                                case _:
                                    path["payload"] = self.buf.rh(self.buf.unit)
                                    path["unknown"] = True

                            self.buf.sapunit()

                            block["data"]["paths"].append(path)
                    case 1013 | 1016 | 1026:
                        block["data"]["blob"] = self.buf.rh(self.buf.unit)
                    case 1082 | 1083:
                        block["data"]["descriptor"], success = self.read_descriptor(True)
                        if not success:
                            block["data"]["unknown"] = True
                    case _:
                        block["data"]["blob"] = self.buf.rh(self.buf.unit)
                        block["data"]["unknown"] = True
            except Exception:
                block["data"]["malformed"] = True

            meta["data"]["blocks"].append(block)
            self.buf.skipunit()
            self.buf.resetunit()

        return meta


@module.register
class ICCProfileModule(module.RuminantModule):
    desc = "ICC profile files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(12) == b"ICC_PROFILE\x00" or buf.peek(8)[4:] in (b"Lino", b"appl") or buf.peek(40)[36:] == b"acsp"

    def read_tag(self, offset, length):
        tag = {}

        with self.buf:
            self.buf.seek(offset)
            typ = self.buf.rs(4)
            self.buf.skip(4)
            self.buf.setunit(length - 8)

            tag["data"] = {}
            tag["data"]["type"] = typ
            match typ:
                case "text":
                    tag["data"]["string"] = self.buf.readunit()[:-1].decode("ascii")
                case "desc":
                    desc_length = self.buf.ru32()
                    tag["data"]["string"] = self.buf.rs(desc_length - 1, "ascii")
                case "XYZ ":
                    tag["data"]["x"] = self.buf.rsfp32()
                    tag["data"]["y"] = self.buf.rsfp32()
                    tag["data"]["z"] = self.buf.rsfp32()
                case "curv":
                    tag["data"]["curve-entry-count"] = self.buf.ru32()
                case "view":
                    tag["data"]["illuminant"] = {
                        "x": self.buf.rsfp32(),
                        "y": self.buf.rsfp32(),
                        "z": self.buf.rsfp32(),
                    }
                    tag["data"]["surround"] = {
                        "x": self.buf.rsfp32(),
                        "y": self.buf.rsfp32(),
                        "z": self.buf.rsfp32(),
                    }
                    illuminant_type = self.buf.ru32()
                    tag["data"]["illuminant-type"] = {
                        "raw": illuminant_type,
                        "name": {
                            0: "Unknown",
                            1: "D50",
                            2: "D65",
                            3: "D93",
                            4: "F2",
                            5: "D55",
                            6: "A",
                            7: "Equi-Power (E)",
                            8: "F8",
                        }.get(illuminant_type, "Unknown"),
                    }
                case "meas":
                    standard_observer = self.buf.ru32()
                    tag["data"]["standard-observer"] = {
                        "raw": standard_observer,
                        "name": {
                            0: "Unknown",
                            1: "CIE 1931 standard colorimetric observer",
                            2: "CIE 1964 standard colorimetric observer",
                        }.get(standard_observer, "Unknown"),
                    }
                    tag["data"]["measurement-backing"] = {
                        "x": self.buf.rsfp32(),
                        "y": self.buf.rsfp32(),
                        "z": self.buf.rsfp32(),
                    }
                    measurement_geometry = self.buf.ru32()
                    tag["data"]["measurement-geometry"] = {
                        "raw": measurement_geometry,
                        "name": {
                            0: "Unknown",
                            1: "0°:45° or 45°:0°",
                            2: "0°:d or d:0°",
                        }.get(measurement_geometry, "Unknown"),
                    }
                    tag["data"]["measurement-flare"] = self.buf.rfp32()
                    standard_illuminant = self.buf.ru32()
                    tag["data"]["standard-illuminant"] = {
                        "raw": standard_illuminant,
                        "name": {
                            0: "Unknown",
                            1: "D50",
                            2: "D65",
                            3: "D93",
                            4: "F2",
                            5: "D55",
                            6: "A",
                            7: "Equi-Power (E)",
                            8: "F8",
                        }.get(standard_illuminant, "Unknown"),
                    }
                case "sig ":
                    tag["data"]["signature"] = self.buf.rs(4)
                case "mluc":
                    record_count = self.buf.ru32()
                    tag["data"]["record-count"] = record_count
                    record_size = self.buf.ru32()
                    tag["data"]["record-size"] = record_size

                    tag["data"]["records"] = []
                    for i in range(0, record_count):
                        record = {}
                        record["language-code"] = self.buf.rs(2)
                        record["country-code"] = self.buf.rs(2)
                        record["length"] = self.buf.ru32()
                        record["offset"] = self.buf.ru32()

                        with self.buf:
                            self.buf.resetunit()
                            self.buf.seek(record["offset"] + offset)
                            record["text"] = self.buf.rs(record["length"], "utf-16be")

                        tag["data"]["records"].append(record)
                case "para":
                    function_type = self.buf.ru16()
                    tag["data"]["function-type"] = function_type
                    self.buf.skip(2)

                    tag["data"]["params"] = {}
                    g = self.buf.rsfp32()
                    tag["data"]["params"]["g"] = g
                    if function_type > 0:
                        a = self.buf.rsfp32()
                        tag["data"]["params"]["a"] = a
                        b = self.buf.rsfp32()
                        tag["data"]["params"]["b"] = b
                    if function_type > 1:
                        c = self.buf.rsfp32()
                        tag["data"]["params"]["c"] = c
                    if function_type > 2:
                        d = self.buf.rsfp32()
                        tag["data"]["params"]["d"] = d
                    if function_type > 3:
                        e = self.buf.rsfp32()
                        tag["data"]["params"]["e"] = e
                        f = self.buf.rsfp32()
                        tag["data"]["params"]["f"] = f

                    tag["data"]["formula"] = {}
                    match function_type:
                        case 0:
                            tag["data"]["formula"]["X"] = f"Y = X ^ {g}"
                        case 1:
                            tag["data"]["formula"][f"X >= {-b / a}"] = f"Y = ({a} * X + {b}) ^ {g}"
                            tag["data"]["formula"][f"X < {-b / a}"] = "Y = 0"
                        case 2:
                            tag["data"]["formula"][f"X >= {d}"] = f"Y = ({a} * X + {b}) ^ {g} + {c}"
                            tag["data"]["formula"][f"X < {-b / a}"] = f"Y = {c}"
                        case 3:
                            tag["data"]["formula"][f"X >= {d}"] = f"Y = ({a} * X + {b}) ^ {g}"
                            tag["data"]["formula"][f"X < {-b / a}"] = f"Y = {c} * X"
                        case 4:
                            tag["data"]["formula"][f"X >= {d}"] = f"Y = ({a} * X + {b}) ^ {g} + {c}"
                            tag["data"]["formula"][f"X < {-b / a}"] = f"Y = {c} * X + {f}"
                        case _:
                            tag["data"]["formula"]["X >= ?"] = "Y = ?"
                            tag["data"]["formula"]["X < ?"] = "Y = ?"
                case "ucmI":
                    tag["data"]["parameter-length"] = self.buf.ru32()
                    tag["data"]["engine-version"] = f"{self.buf.ru8()}.{self.buf.ru8()}.{self.buf.ru16()}"
                    tag["data"]["profile-format-document-version"] = f"{self.buf.ru8()}.{self.buf.ru8()}.{self.buf.ru16()}"
                    tag["data"]["profile-version"] = f"{self.buf.ru8()}.{self.buf.ru8()}.{self.buf.ru16()}"
                    tag["data"]["profile-build-number"] = self.buf.ru32()
                    tag["data"]["interpolation-flag"] = self.buf.ru32()
                    tag["data"]["atob0-tag-override"] = self.buf.ru32()
                    tag["data"]["atob1-tag-override"] = self.buf.ru32()
                    tag["data"]["atob2-tag-override"] = self.buf.ru32()
                    tag["data"]["btoa0-tag-override"] = self.buf.ru32()
                    tag["data"]["btoa1-tag-override"] = self.buf.ru32()
                    tag["data"]["btoa2-tag-override"] = self.buf.ru32()
                    tag["data"]["preview0-tag-override"] = self.buf.ru32()
                    tag["data"]["preview1-tag-override"] = self.buf.ru32()
                    tag["data"]["preview2-tag-override"] = self.buf.ru32()
                    tag["data"]["gamut-tag-override"] = self.buf.ru32()
                    tag["data"]["atob0-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["atob1-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["atob2-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["btoa0-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["btoa1-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["btoa2-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["preview0-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["preview1-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["preview2-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["gamut-tag-optimization-flag"] = self.buf.ru32()
                    tag["data"]["creator-division"] = self.buf.rs(64, "latin-1").rstrip("\x00")
                    tag["data"]["support-division"] = self.buf.rs(64, "latin-1").rstrip("\x00")
                    tag["data"]["von-kries-flag"] = self.buf.ru32()
                case _:
                    tag["data"]["unkown"] = True

        return tag

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "icc-profile"
        meta["data"] = {}

        global_offset = 0
        if self.buf.peek(12) == b"ICC_PROFILE\x00":
            self.buf.skip(14)
            global_offset = 14

        length = self.buf.ru32()
        meta["data"]["length"] = length
        self.buf.setunit(length - 4)

        meta["data"]["cmm-type"] = self.buf.rs(4)
        meta["data"]["version"] = f"{self.buf.ru8()}.{self.buf.rh(3).rstrip('0')}"
        meta["data"]["class"] = self.buf.rs(4)
        meta["data"]["color-space"] = self.buf.rs(4)
        meta["data"]["profile-connection-space"] = self.buf.rs(4)
        year, month, day, hour, minute, second = [self.buf.ru16() for _ in range(0, 6)]
        meta["data"]["date"] = (
            str(year).zfill(4)
            + "-"
            + str(month).zfill(2)
            + "-"
            + str(day).zfill(2)
            + "T"
            + str(hour).zfill(2)
            + ":"
            + str(minute).zfill(2)
            + ":"
            + str(second).zfill(2)
        )
        meta["data"]["file-signature"] = self.buf.rs(4)
        meta["data"]["platform"] = self.buf.rs(4)
        meta["data"]["flags"] = self.buf.rh(4)
        meta["data"]["device-manufacturer"] = self.buf.rs(4)
        meta["data"]["device-model"] = self.buf.rs(4)
        meta["data"]["device-attributes"] = self.buf.rh(8)
        render_intent = self.buf.ru32()
        meta["data"]["render-intent"] = {
            "raw": render_intent,
            "name": {
                0: "Perceptual",
                1: "Relative Colorimetric",
                2: "Saturation",
                3: "Absolute Colorimetric",
            }.get(render_intent, "Unknown"),
        }
        meta["data"]["pcs-illuminant"] = [self.buf.rsfp32() for _ in range(0, 3)]
        meta["data"]["profile-creator"] = self.buf.rs(4)
        meta["data"]["profile-md5"] = self.buf.rh(16)
        meta["data"]["reserved"] = self.buf.rh(28)

        tag_count = self.buf.ru32()
        meta["data"]["tag-count"] = tag_count
        meta["data"]["tags"] = []
        for i in range(0, tag_count):
            tag = {}
            tag["name"] = self.buf.rs(4)
            tag["offset"] = self.buf.ru32()
            tag["length"] = self.buf.ru32()

            tag |= self.read_tag(tag["offset"] + global_offset, tag["length"])

            meta["data"]["tags"].append(tag)

        self.buf.readunit()

        return meta


@module.register
class JPEGModule(module.RuminantModule):
    desc = "JPEG files."

    HAS_PAYLOAD = [
        0xc0,  # SOF0: Baseline DCT
        0xc1,  # SOF1: Extended sequential DCT
        0xc2,  # SOF2: Progressive DCT
        0xc3,  # SOF3: Lossless sequential
        0xc5,  # SOF5: Differential sequential DCT
        0xc6,  # SOF6: Differential progressive DCT
        0xc7,  # SOF7: Differential lossless
        0xc9,  # SOF9: Extended sequential, arithmetic coding
        0xca,  # SOF10: Progressive, arithmetic coding
        0xcb,  # SOF11: Lossless, arithmetic coding
        0xcd,  # SOF13: Differential sequential, arithmetic coding
        0xce,  # SOF14: Differential progressive, arithmetic coding
        0xcf,  # SOF15: Differential lossless, arithmetic coding
        0xc4,  # DHT: Define Huffman Table
        0xdb,  # DQT: Define Quantization Table
        0xdd,  # DRI: Define Restart Interval
        0xda,  # SOS: Start of Scan
        0xe0,  # APP0
        0xe1,  # APP1
        0xe2,  # APP2
        0xe3,  # APP3
        0xe4,  # APP4
        0xe5,  # APP5
        0xe6,  # APP6
        0xe7,  # APP7
        0xe8,  # APP8
        0xe9,  # APP9
        0xea,  # APP10
        0xeb,  # APP11
        0xec,  # APP12
        0xed,  # APP13
        0xee,  # APP14
        0xef,  # APP15
        0xfe,  # COM: Comment
        0xf0,  # JPG0 (JPEG extensions, reserved)
        0xf1,  # JPG1
        0xf2,  # JPG2
        0xf3,  # JPG3
        0xf4,  # JPG4
        0xf5,  # JPG5
        0xf6,  # JPG6
        0xf7,  # JPG7
        0xf8,  # JPG8
        0xf9,  # JPG9
        0xfa,  # JPG10
        0xfb,  # JPG11
        0xfc,  # JPG12
        0xfd,  # JPG13
    ]

    MARKER_NAME = {
        0xd8: "SOI",
        0xd9: "EOI",
        0xc0: "SOF0",
        0xc1: "SOF1",
        0xc2: "SOF2",
        0xc3: "SOF3",
        0xc5: "SOF5",
        0xc6: "SOF6",
        0xc7: "SOF7",
        0xc9: "SOF9",
        0xca: "SOF10",
        0xcb: "SOF11",
        0xcd: "SOF13",
        0xce: "SOF14",
        0xcf: "SOF15",
        0xc4: "DHT",
        0xdb: "DQT",
        0xdd: "DRI",
        0xda: "SOS",
        0xfe: "COM",
        0xe0: "APP0",
        0xe1: "APP1",
        0xe2: "APP2",
        0xe3: "APP3",
        0xe4: "APP4",
        0xe5: "APP5",
        0xe6: "APP6",
        0xe7: "APP7",
        0xe8: "APP8",
        0xe9: "APP9",
        0xea: "APP10",
        0xeb: "APP11",
        0xec: "APP12",
        0xed: "APP13",
        0xee: "APP14",
        0xef: "APP15",
        0xf0: "JPG0",
        0xf1: "JPG1",
        0xf2: "JPG2",
        0xf3: "JPG3",
        0xf4: "JPG4",
        0xf5: "JPG5",
        0xf6: "JPG6",
        0xf7: "JPG7",
        0xf8: "JPG8",
        0xf9: "JPG9",
        0xfa: "JPG10",
        0xfb: "JPG11",
        0xfc: "JPG12",
        0xfd: "JPG13",
        0xd0: "RST0",
        0xd1: "RST1",
        0xd2: "RST2",
        0xd3: "RST3",
        0xd4: "RST4",
        0xd5: "RST5",
        0xd6: "RST6",
        0xd7: "RST7",
        0x01: "TEM",
    }

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(3) == b"\xff\xd8\xff"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "jpeg"

        meta["chunks"] = []
        should_break = False
        slack = b""
        while self.buf.available() and not should_break:
            chunk: dict = {}

            assert self.buf.ru8() == 0xff, "wrong marker prefix"
            typ = self.buf.ru8()
            chunk["type"] = self.MARKER_NAME.get(typ, "UNK") + f" (0x{hex(typ)[2:].zfill(2)})"

            if typ in self.HAS_PAYLOAD:
                length = self.buf.ru16() - 2
            else:
                length = 0

            if typ != 0xda and length > 0:
                with self.buf:
                    self.buf.skip(length)

                    while self.buf.pu8() != 0xff and self.buf.available():
                        self.buf.skip(1)
                        length += 1

            self.buf.pushunit()
            self.buf.setunit(length)
            chunk["length"] = length

            chunk["data"] = {}
            if typ == 0xe0 and self.buf.peek(5) == b"JFIF\x00":
                self.buf.skip(5)
                chunk["data"]["version"] = str(self.buf.ru8()) + "." + str(self.buf.ru8())
                units = self.buf.ru8()
                chunk["data"]["units"] = {
                    "raw": units,
                    "name": {
                        0: "No units",
                        1: "Pixels per inch",
                        2: "Pixels per centimeter",
                    }.get(units, "Unknown"),
                }
                chunk["data"]["horizontal-pixel-density"] = self.buf.ru16()
                chunk["data"]["vertical-pixel-density"] = self.buf.ru16()
                chunk["data"]["thumbnail-width"] = self.buf.ru8()
                chunk["data"]["thumbnail-height"] = self.buf.ru8()
                chunk["data"]["thumbnail-data-length"] = self.buf.unit
            elif typ == 0xe1 and self.buf.peek(6) == b"Exif\x00\x00":
                self.buf.skip(6)
                with self.buf.subunit():
                    chunk["data"]["tiff"] = chew(self.buf)
            elif typ == 0xe1 and self.buf.peek(9) == b"<?xpacket":
                chunk["data"]["xmp"] = utils.xml_to_dict(self.buf.readunit())
            elif typ == 0xe1 and (self.buf.peek(4) == b"http" or len(slack) > 0):
                conforming = False

                if len(slack) == 0:
                    self.buf.rzs()
                    chunk["data"]["xmp"] = utils.read_xml(self.buf)
                    while self.buf.available() > 0 and self.buf.peek(1) != b">":
                        self.buf.skip(1)

                    if self.buf.peek(1) == b">":
                        self.buf.skip(1)
                elif self.buf.peek(34) == b"http://ns.adobe.com/xmp/extension/":
                    self.buf.skip(35)
                    chunk["data"]["extended-xmp"] = [{}]
                    chunk["data"]["extended-xmp"][0]["conforming"] = True
                    chunk["data"]["extended-xmp"][0]["uuid"] = self.buf.rs(32)
                    chunk["data"]["extended-xmp"][0]["length"] = self.buf.ru32()
                    chunk["data"]["extended-xmp"][0]["offset"] = self.buf.ru32()
                    chunk["data"]["extended-xmp"][0]["data"] = utils.xml_to_dict(self.buf.rs(self.buf.unit))
                    conforming = True

                if not conforming:
                    slack += self.buf.read(self.buf.unit)
                    buf = Buf(slack)

                    chunk["data"]["extended-xmp"] = []
                    while buf.available() > 0:
                        with buf:
                            buf.skip(32)
                            if buf.ru32() > buf.available() + 4:
                                break

                        exmp: dict = {}
                        exmp["conforming"] = False
                        exmp["uuid"] = buf.rs(32)
                        exmp["length"] = buf.ru32()
                        exmp["offset"] = buf.ru32()

                        with open("e.xml", "wb") as f:
                            f.write(buf.peek(exmp["length"] + 40))

                        exmp["data"] = utils.xml_to_dict(buf.read(exmp["length"] + 40), True)
                        chunk["data"]["extended-xmp"].append(exmp)

                    slack = buf.read(buf.available())
            elif typ == 0xe2 and self.buf.peek(12) == b"ICC_PROFILE\x00":
                with self.buf.subunit():
                    chunk["data"]["icc-profile"] = chew(self.buf)
            elif typ == 0xe2 and self.buf.peek(4) == b"MPF\x00":
                self.buf.skip(4)
                with self.buf.subunit():
                    chunk["data"]["tiff"] = chew(self.buf)
            elif typ == 0xe2 and self.buf.peek(27) == b"urn:iso:std:iso:ts:21496:-1":
                self.buf.skip(32)
                chunk["data"]["hdr-gainmap-length"] = self.buf.unit
            elif typ == 0xea and self.buf.peek(4) == b"AROT":
                self.buf.skip(6)
                chunk["data"]["entry-count"] = self.buf.ru32()
                chunk["data"]["entries"] = [self.buf.ru32l() for i in range(0, chunk["data"]["entry-count"])]
            elif typ == 0xeb and self.buf.peek(8) == b"JP\x13\x00\x00\x00\x00\x00":
                with self.buf.subunit():
                    self.buf.skip(8)
                    chunk["data"]["jumbf"] = chew(self.buf)
            elif typ == 0xec and self.buf.peek(5) == b"Ducky":
                self.buf.skip(5)

                ducky_type = self.buf.ru16()
                chunk["data"]["ducky-type"] = {
                    1: "Quality",
                    2: "Comment",
                    3: "Copyright",
                }.get(ducky_type, "Unknown") + f" (0x{hex(ducky_type)[2:].zfill(4)})"

                match ducky_type:
                    case 1:
                        self.buf.skip(2)
                        chunk["data"]["value"] = self.buf.ru32()
                    case 2 | 3:
                        length = self.buf.ru32()
                        chunk["data"]["value"] = self.buf.rs(length)
                    case _:
                        chunk["data"]["value"] = self.buf.readunit().hex()
                        chunk["data"]["unknown"] = True
            elif typ == 0xed and self.buf.peek(18) == b"Photoshop 3.0\x008BIM":
                with self.buf.subunit():
                    chunk["data"]["iptc"] = chew(self.buf)
            elif typ == 0xed and self.buf.peek(9) == b"Adobe_CM\x00":
                self.buf.skip(9)
                chunk["data"]["adobe-cm-payload"] = self.buf.readunit().hex()
            elif typ == 0xee and self.buf.peek(5) == b"Adobe":
                chunk["data"]["identifier"] = self.buf.rs(5)
                chunk["data"]["pre-defined"] = self.buf.rh(1)
                chunk["data"]["flags0"] = self.buf.rh(2)
                chunk["data"]["flags1"] = self.buf.rh(2)
                chunk["data"]["transform"] = self.buf.ru8()
            elif typ & 0xf0 == 0xe0:
                chunk["data"]["payload"] = self.buf.readunit().hex()
            elif typ in (0xc0, 0xc2):
                chunk["data"]["sample-precision"] = self.buf.ru8()
                chunk["data"]["height"] = self.buf.ru16()
                chunk["data"]["width"] = self.buf.ru16()
                component_count = self.buf.ru8()
                chunk["data"]["component-count"] = component_count
                chunk["data"]["components"] = []
                for i in range(0, component_count):
                    component: dict = {}

                    component["id"] = self.buf.ru8()

                    sampling_factors = self.buf.ru8()
                    component["sampling-factors"] = {
                        "raw": sampling_factors,
                        "horizontal": (sampling_factors & 0xf0) >> 4,
                        "vertical": sampling_factors & 0x0f,
                    }

                    component["quantization-table-id"] = self.buf.ru8()

                    chunk["data"]["components"].append(component)
            elif typ == 0xda:
                component_count = self.buf.ru8()
                chunk["data"]["component-count"] = component_count
                chunk["data"]["components"] = []
                for i in range(0, component_count):
                    component = {}

                    component["id"] = self.buf.ru8()

                    huffman_table_selector = self.buf.ru8()
                    component["huffman-table-selector"] = {
                        "raw": huffman_table_selector,
                        "dc": (huffman_table_selector & 0xf0) >> 4,
                        "ac": huffman_table_selector & 0x0f,
                    }

                    chunk["data"]["components"].append(component)

                chunk["data"]["spectral-selection-start"] = self.buf.ru8()
                chunk["data"]["spectral-selection-end"] = self.buf.ru8()
                chunk["data"]["successive-approximation"] = self.buf.ru8()

                image_length = self.buf.tell()
                self.buf.resetunit()
                self.buf.search(b"\xff\xd9")
                self.buf.setunit(0)

                chunk["data"]["image-length"] = self.buf.tell() - image_length
            elif typ == 0xfe:
                chunk["data"]["comment"] = utils.decode(self.buf.readunit())
            elif typ == 0xdb:
                chunk["tables"] = []

                while self.buf.hasunit():
                    table: dict = {}

                    temp = self.buf.ru8()

                    table["precision"] = 8 << (temp >> 4)
                    table["id"] = temp & 0x0f
                    table["data"] = self.buf.rh(64 << (temp >> 4))

                    if table["data"] in constants.JPEG_QUANTIZATION_TABLES:
                        table["match"] = constants.JPEG_QUANTIZATION_TABLES[table["data"]]

                    chunk["tables"].append(table)
            elif typ == 0xc4:
                temp = self.buf.ru8()
                chunk["data"]["id"] = temp & 0x0f
                chunk["data"]["type"] = "ac" if (temp & 0x10) else "dc"
                chunk["data"]["symbol-count"] = list(self.buf.read(16))
            elif typ == 0xd9:
                should_break = True

            meta["chunks"].append(chunk)

            self.buf.skipunit()
            self.buf.popunit()

        if self.buf.available() > 8:
            with self.buf:
                self.buf.seek(self.buf.size() - 4)
                has_seft = self.buf.read(4) == b"SEFT"

            if has_seft:
                meta["seft"] = {}

                length = self.buf.size()

                self.buf.seek(length - 8)
                headers_block_length = self.buf.ru32l()
                headers_block_start_offset = length - (headers_block_length + 8)
                self.buf.seek(headers_block_start_offset + 4)
                meta["seft"]["version"] = self.buf.ru32l()
                record_count = self.buf.ru32l()
                meta["seft"]["record-count"] = record_count

                meta["seft"]["records"] = []
                for i in range(0, record_count):
                    record: dict = {}
                    record["padding"] = self.buf.ru16l()
                    record["type"] = self.buf.ru16l()
                    offset = self.buf.ru32l()
                    record["offset"] = offset
                    record_length = self.buf.ru32l()
                    record["length"] = record_length
                    record["content"] = {}

                    with self.buf:
                        self.buf.seek(headers_block_start_offset - offset)
                        record["content"]["padding"] = self.buf.ru16l()
                        record["content"]["type"] = self.buf.ru16l()
                        key_length = self.buf.ru32l()
                        record["content"]["key-length"] = key_length
                        value_length = record_length - key_length - 8
                        record["content"]["value-length"] = value_length
                        record["content"]["name"] = self.buf.rs(key_length)
                        record["content"]["value"] = self.buf.rs(value_length, "latin-1")

                    meta["seft"]["records"].append(record)

                self.buf.skip(8)

        return meta


@module.register
class PNGModule(module.RuminantModule):
    desc = "PNG files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(8) == b"\x89PNG\r\n\x1a\n"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "png"

        color_type = None
        headerless = False

        self.buf.seek(8)
        meta["chunks"] = []
        while self.buf.available():
            length = self.buf.ru32()
            self.buf.pushunit()
            self.buf.setunit(length + 4)

            chunk_type = self.buf.read(4)

            chunk: dict = {
                "chunk-type": chunk_type.decode("utf-8"),
                "length": length,
                "flags": {
                    "critical": chunk_type[0] & 32 == 0,
                    "private": chunk_type[1] & 32 == 1,
                    "conforming": chunk_type[2] & 32 == 0,
                    "safe-to-copy": chunk_type[3] & 32 == 1,
                },
            }

            data = self.buf.peek(length + 4)
            data, crc = data[:-4], data[-4:]
            target_crc = zlib.crc32(chunk_type + data)

            chunk["crc"] = {
                "value": crc.hex(),
                "correct": int.from_bytes(crc, "big") == target_crc & 0xffffffff,
            }

            if not chunk["crc"]["correct"]:
                chunk["crc"]["actual"] = target_crc.to_bytes(4, "big").hex()

            chunk["data"] = {}
            match chunk_type.decode("latin-1"):
                case "IHDR":
                    chunk["data"]["width"] = self.buf.ru32()
                    chunk["data"]["height"] = self.buf.ru32()
                    chunk["data"]["bit-depth"] = self.buf.ru8()
                    color_type = self.buf.ru8()
                    chunk["data"]["color-type"] = color_type
                    chunk["data"]["compression"] = self.buf.ru8()
                    chunk["data"]["filter-method"] = self.buf.ru8()
                    chunk["data"]["interlace-method"] = self.buf.ru8()
                case "eXIf":
                    with self.buf.sub(length):
                        chunk["data"]["tiff"] = chew(self.buf)
                case "pHYs":
                    chunk["data"]["width-pixels-per-unit"] = self.buf.ru32()
                    chunk["data"]["height-pixels-per-unit"] = self.buf.ru32()
                    unit = self.buf.ru8()
                    chunk["data"]["unit"] = {
                        "raw": unit,
                        "name": {1: "Meters"}.get(unit, "Unknown"),
                    }
                case "iCCP":
                    chunk["data"]["profile-name"] = self.buf.rzs()

                    compression_method = self.buf.ru8()
                    match compression_method:
                        case 0:
                            chunk["data"]["compression-method"] = {
                                "raw": 0,
                                "name": "DEFLATE",
                            }
                            chunk["data"]["profile"] = chew(
                                b"ICC_PROFILE\x00\x00\x00"
                                + (
                                    zlib.decompress(self.buf.readunit(), -zlib.MAX_WBITS)
                                    if headerless
                                    else zlib.decompress(self.buf.readunit())
                                )
                            )
                        case _:
                            chunk["data"]["compression-method"] = {
                                "raw": compression_method,
                                "name": "Unknown",
                            }
                case "cHRM":
                    chunk["data"]["white"] = [self.buf.ru32() / 100000 for _ in range(0, 2)]
                    chunk["data"]["red"] = [self.buf.ru32() / 100000 for _ in range(0, 2)]
                    chunk["data"]["green"] = [self.buf.ru32() / 100000 for _ in range(0, 2)]
                    chunk["data"]["blue"] = [self.buf.ru32() / 100000 for _ in range(0, 2)]
                case "tEXt" | "zTXt" | "iTXt":
                    chunk["data"]["keyword"] = self.buf.rzs()

                    chunk["data"]["text"] = ""
                    match chunk_type.decode("latin-1"):
                        case "tEXt":
                            chunk["data"]["text"] = self.buf.readunit()
                        case "zTXt":
                            compression_method = self.buf.ru8()

                            match compression_method:
                                case 0:
                                    chunk["data"]["compression-method"] = {
                                        "raw": 0,
                                        "name": "DEFLATE",
                                    }
                                    chunk["data"]["text"] = (
                                        zlib.decompress(self.buf.readunit(), -zlib.MAX_WBITS)
                                        if headerless
                                        else zlib.decompress(self.buf.readunit())
                                    )
                                case _:
                                    chunk["data"]["compression-method"] = {
                                        "raw": compression_method,
                                        "name": "Unknown",
                                    }

                        case "iTXt":
                            compressed = bool(self.buf.ru8())
                            chunk["data"]["compressed"] = compressed
                            compression_method = self.buf.ru8()
                            chunk["data"]["language-tag"] = self.buf.rzs()
                            chunk["data"]["translated-keyword"] = self.buf.rzs()

                            match compression_method:
                                case 0:
                                    if compressed:
                                        chunk["data"]["compression-method"] = {
                                            "raw": 0,
                                            "name": "DEFLATE",
                                        }
                                        chunk["data"]["text"] = (
                                            zlib.decompress(self.buf.readunit(), -zlib.MAX_WBITS)
                                            if headerless
                                            else zlib.decompress(self.buf.readunit())
                                        )
                                    else:
                                        chunk["data"]["compression-method"] = {
                                            "raw": 0,
                                            "name": "Uncompressed",
                                        }
                                        chunk["data"]["text"] = self.buf.readunit()
                                case _:
                                    chunk["data"]["compression-method"] = {
                                        "raw": compression_method,
                                        "name": "Unknown",
                                    }

                    try:
                        chunk["data"]["text"] = chunk["data"]["text"].decode("utf-8")
                    except UnicodeDecodeError:
                        try:
                            chunk["data"]["text"] = chunk["data"]["text"].decode("utf-16")
                        except UnicodeDecodeError:
                            chunk["data"]["text"] = chunk["data"]["text"].decode("latin-1")

                    match chunk["data"]["keyword"]:
                        case "XML:com.adobe.xmp":
                            chunk["data"]["text"] = utils.xml_to_dict(chunk["data"]["text"])
                        case "Raw profile type APP1":
                            chunk["data"]["profile-type"] = chunk["data"]["text"].split("\n")[1]
                            chunk["data"]["text"] = chew(bytes.fromhex(chunk["data"]["text"].split("\n")[3]))
                        case "Raw profile type exif":
                            chunk["data"]["text"] = chew(bytes.fromhex("".join(chunk["data"]["text"].split("\n")[3:])))
                case "bKGD":
                    match self.buf.unit:
                        case 1:
                            chunk["data"]["index"] = self.buf.ru8()
                        case 2:
                            chunk["data"]["gray"] = self.buf.ru16()
                        case 6:
                            chunk["data"]["red"] = self.buf.ru16()
                            chunk["data"]["green"] = self.buf.ru16()
                            chunk["data"]["blue"] = self.buf.ru16()
                case "tIME":
                    chunk["data"]["date"] = datetime.datetime(
                        self.buf.ru16(),
                        self.buf.ru8(),
                        self.buf.ru8(),
                        self.buf.ru8(),
                        self.buf.ru8(),
                        self.buf.ru8(),
                        tzinfo=datetime.timezone.utc,
                    ).isoformat()
                case "gAMA":
                    chunk["data"]["gamma"] = self.buf.ru32() / 100000
                case "sRGB":
                    render_intent = self.buf.ru8()
                    chunk["data"]["render-intent"] = {
                        "raw": render_intent,
                        "name": {
                            0: "Perceptual",
                            1: "Relative Colorimetric",
                            2: "Saturation",
                            3: "Absolute Colorimetric",
                        }.get(render_intent, "Unknown"),
                    }
                case "orNT":
                    orientation = self.buf.ru8()
                    chunk["data"]["orientation"] = {
                        "raw": "orientation",
                        "name": {
                            1: "Top Left",
                            2: "Top Right",
                            3: "Bottom Right",
                            4: "Bottom Left",
                            5: "Left Top",
                            6: "Right Top",
                            7: "Right Bottom",
                            8: "Left Bottom",
                        }.get(orientation, "Unknown"),
                    }
                case "sBIT":
                    match color_type:
                        case 0:
                            chunk["data"]["significant-bits"] = self.buf.ru8()
                        case 4:
                            chunk["data"]["significant-bits"] = [self.buf.ru8() for i in range(0, 2)]
                        case 2 | 3:
                            chunk["data"]["significant-bits"] = [self.buf.ru8() for i in range(0, 3)]
                        case 6:
                            chunk["data"]["significant-bits"] = [self.buf.ru8() for i in range(0, 4)]
                case "iDOT":
                    # see https://www.hackerfactor.com/blog/index.php?/archives/895-Connecting-the-iDOTs.html
                    chunk["data"]["height-divisor"] = self.buf.ru32()
                    chunk["data"]["reserved"] = self.buf.ru32()
                    chunk["data"]["divided-height"] = self.buf.ru32()
                    chunk["data"]["predefined"] = self.buf.ru32()
                    chunk["data"]["first-half-height"] = self.buf.ru32()
                    chunk["data"]["second-half-height"] = self.buf.ru32()
                    chunk["data"]["idat-restart-offset"] = self.buf.ru32()
                case "caBX":
                    with self.buf.subunit():
                        chunk["data"]["jumbf"] = chew(self.buf)
                case "cICP":
                    chunk["data"]["color-primaries"] = self.buf.ru8()
                    chunk["data"]["transfer-function"] = self.buf.ru8()
                    chunk["data"]["matrix-coefficients"] = self.buf.ru8()
                    chunk["data"]["video-full-range-flag"] = self.buf.ru8()
                case "acTL":
                    chunk["data"]["frame-count"] = self.buf.ru32()
                    chunk["data"]["loop-count"] = self.buf.ru32()
                case "fcTL":
                    chunk["data"]["sequence-number"] = self.buf.ru32()
                    chunk["data"]["width"] = self.buf.ru32()
                    chunk["data"]["height"] = self.buf.ru32()
                    chunk["data"]["x-offset"] = self.buf.ru32()
                    chunk["data"]["y-offset"] = self.buf.ru32()
                    chunk["data"]["delay-num"] = self.buf.ru16()
                    chunk["data"]["delay-den"] = self.buf.ru16()
                    chunk["data"]["dispose-op"] = self.buf.ru8()
                    chunk["data"]["blend-op"] = self.buf.ru8()
                case "fdAT":
                    chunk["data"]["sequence-number"] = self.buf.ru32()
                case "CgBI":
                    headerless = True
                    chunk["data"]["payload"] = self.buf.rh(self.buf.unit)
                case "cLLi" | "cLLI":
                    chunk["data"]["max-cll"] = self.buf.ru32()
                    chunk["data"]["max-fall"] = self.buf.ru32()
                case "mDCv" | "mDCV":
                    chunk["data"]["color-primaries"] = [(self.buf.ru16(), self.buf.ru16()) for _ in range(0, 3)]
                    chunk["data"]["white-point-chromaticity"] = self.buf.ru32()
                    chunk["data"]["max-luminance"] = self.buf.ru32()
                    chunk["data"]["min-luminance"] = self.buf.ru32()
                case "IDAT" | "IEND" | "PLTE" | "tRNS" | "npOl" | "npTc":
                    pass
                case _:
                    chunk["data"]["unknown"] = True

            meta["chunks"].append(chunk)

            self.buf.skipunit()
            self.buf.skip(4)
            self.buf.popunit()

        return meta


@module.register
class TIFFModule(module.RuminantModule):
    desc = "TIFF files including EXIF metadata."

    TAG_IDS = {
        "tiff": {
            0: "GPSVersionID",
            1: "GPSLatitudeRef",
            2: "GPSLatitude",
            3: "GPSLongitudeRef",
            4: "GPSLongitude",
            5: "GPSAltitudeRef",
            6: "GPSAltitude",
            7: "GPSTimeStamp",
            8: "GPSSatellites",
            9: "GPSStatus",
            10: "GPSMeasureMode",
            11: "GPSDOP",
            12: "GPSSpeedRef",
            13: "GPSSpeed",
            14: "GPSTrackRef",
            15: "GPSTrack",
            16: "GPSImgDirectionRef",
            17: "GPSImgDirection",
            18: "GPSMapDatum",
            19: "GPSDestLatitudeRef",
            20: "GPSDestLatitude",
            21: "GPSDestLongitudeRef",
            22: "GPSDestLongitude",
            23: "GPSDestBearingRef",
            24: "GPSDestBearing",
            25: "GPSDestDistanceRef",
            26: "GPSDestDistance",
            27: "GPSProcessingMethod",
            28: "GPSAreaInformation",
            29: "GPSDateStamp",
            30: "GPSDifferential",
            31: "GPSHPositioningError",
            254: "NewSubfileType",
            255: "SubfileType",
            256: "ImageWidth",
            257: "ImageLength",
            258: "BitsPerSample",
            259: "Compression",
            262: "PhotometricInterpretation",
            263: "Threshholding",
            264: "CellWidth",
            265: "CellLength",
            266: "FillOrder",
            269: "DocumentName",
            270: "ImageDescription",
            271: "Make",
            272: "Model",
            273: "StripOffsets",
            274: "Orientation",
            277: "SamplesPerPixel",
            278: "RowsPerStrip",
            279: "StripByteCounts",
            280: "MinSampleValue",
            281: "MaxSampleValue",
            282: "XResolution",
            283: "YResolution",
            284: "PlanarConfiguration",
            285: "PageName",
            286: "XPosition",
            287: "YPosition",
            288: "FreeOffsets",
            289: "FreeByteCounts",
            290: "GrayResponseUnit",
            291: "GrayResponseCurve",
            292: "T4Options",
            293: "T6Options",
            296: "ResolutionUnit",
            297: "PageNumber",
            301: "TransferFunction",
            305: "Software",
            306: "DateTime",
            315: "Artist",
            316: "HostComputer",
            317: "Predictor",
            318: "WhitePoint",
            319: "PrimaryChromaticities",
            320: "ColorMap",
            321: "HalftoneHints",
            322: "TileWidth",
            323: "TileLength",
            324: "TileOffset",
            325: "TileByteCounts",
            330: "SubIFDPointer",
            332: "InkSet",
            333: "InkNames",
            334: "NumberOfInks",
            336: "DotRange",
            337: "TargetPrinter",
            338: "ExtraSamples",
            339: "SampleFormat",
            340: "SMinSampleValue",
            341: "SMaxSampleValue",
            342: "TransferRange",
            512: "JPEGProc",
            513: "JPEGInterchangeFormat",
            514: "JPEGInterchangeFormatLngth",
            515: "JPEGRestartInterval",
            517: "JPEGLosslessPredictors",
            518: "JPEGPointTransforms",
            519: "JPEGQTables",
            520: "JPEGDCTables",
            521: "JPEGACTables",
            529: "YCbCrCoefficients",
            530: "YCbCrSubSampling",
            531: "YCbCrPositioning",
            532: "ReferenceBlackWhite",
            33421: "CFARepeatPatternDim",
            33422: "CFAPattern",
            33432: "Copyright",
            33434: "ExposureTime",
            33437: "FNumber",
            34665: "ExifIFDPointer",
            34850: "ExposureProgram",
            34852: "SpectralSensitivity",
            34853: "GPSInfoIFDPointer",
            34855: "PhotographicSensitivity",
            34856: "OECF",
            34864: "SensitivityType",
            34865: "StandardOutputSensitivity",
            34866: "RecommendedExposureIndex",
            34867: "ISOSpeed",
            34868: "ISOSpeedLatitudeyyy",
            34869: "ISOSpeedLatitudezzz",
            36864: "ExifVersion",
            36867: "DateTimeOriginal",
            36868: "DateTimeDigitized",
            36880: "OffsetTime",
            36881: "OffsetTimeOriginal",
            36882: "OffsetTimeDigitized",
            37121: "ComponentsConfiguration",
            37122: "CompressedBitsPerPixel",
            37377: "ShutterSpeedValue",
            37378: "ApertureValue",
            37379: "BrightnessValue",
            37380: "ExposureBiasValue",
            37381: "MaxApertureValue",
            37382: "SubjectDistance",
            37383: "MeteringMode",
            37384: "LightSource",
            37385: "Flash",
            37386: "FocalLength",
            37396: "SubjectArea",
            37500: "MakerNote",
            37510: "UserComment",
            37520: "SubSecTime",
            37521: "SubSecTimeOriginal",
            37522: "SubSecTimeDigitized",
            45056: "MPFVersion",
            45057: "NumberOfImages",
            45058: "MPImageList",
            45059: "ImageUIDList",
            45060: "TotalFrames",
            45313: "MPIndividualNum",
            45569: "PanOrientation",
            45570: "PanOverlapH",
            45571: "PanOverlapV",
            45572: "BaseViewpointNum",
            45573: "ConvergenceAngle",
            45574: "BaselineLength",
            45575: "VerticalDivergence",
            45576: "AxisDistanceX",
            45577: "AxisDistanceY",
            45578: "AxisDistanceZ",
            45579: "YawAngle",
            45580: "PitchAngle",
            45581: "RollAngle",
            40960: "FlashpixVersion",
            40961: "ColorSpace",
            40962: "PixelXDimension",
            40963: "PixelYDimension",
            40964: "RelatedSoundFile",
            40965: "InteroperabilityIFDPointer",
            41483: "FlashEnergy",
            41484: "SpatialFrequencyResponse",
            41486: "FocalPlaneXResolution",
            41487: "FocalPlaneYResolution",
            41488: "FocalPlaneResolutionUnit",
            41492: "SubjectLocation",
            41493: "ExposureIndex",
            41495: "SensingMethod",
            41728: "FileSource",
            41729: "SceneType",
            41730: "CFAPattern",
            41985: "CustomRendered",
            41986: "ExposureMode",
            41987: "WhiteBalance",
            41988: "DigitalZoomRatio",
            41989: "FocalLengthIn35mmFilm",
            41990: "SceneCaptureType",
            41991: "GainControl",
            41992: "Contrast",
            41993: "Saturation",
            41994: "Sharpness",
            41995: "DeviceSettingDescription",
            41996: "SubjectDistanceRange",
            42016: "ImageUniqueID",
            42032: "CameraOwnerName",
            42033: "BodySerialNumber",
            42034: "LensSpecification",
            42035: "LensMake",
            42036: "LensModel",
            42037: "LensSerialNumber",
            42080: "CompositeImage",
            42240: "Gamma",
            50341: "PrintImageMatching",
            50706: "DNGVersion",
            50707: "DNGBackwardVersion",
            50708: "UniqueCameraModel",
            50710: "CFAPlaneColor",
            50711: "CFALayout",
            50713: "BlackLevelRepeatDim",
            50714: "BlackLevel",
            50717: "WhiteLevel",
            50718: "DefaultScale",
            50719: "DefaultCropOrigin",
            50720: "DefaultCropSize",
            50721: "ColorMatrix1",
            50722: "ColorMatrix2",
            50727: "AnalogBalance",
            50728: "AsShotNeutral",
            50730: "BaselineExposure",
            50731: "BaselineNoise",
            50732: "BaselineSharpness",
            50733: "BayerGreenSplit",
            50734: "LinearResponseLimit",
            50738: "AntiAliasStrength",
            50739: "ShadowScale",
            50741: "MakerNoteSafety",
            50778: "CalibrationIlluminant1",
            50779: "CalibrationIlluminant2",
            50780: "BestQualityScale",
            50781: "RawDataUniqueID",
            50829: "ActiveArea",
            50938: "ProfileHueSatMapData1",
            50939: "ProfileHueSatMapData2",
            50941: "ProfileEmbedPolicy",
            50942: "ProfileCopyright",
            50964: "ForwardMatrix1",
            50965: "ForwardMatrix2",
            50981: "ProfileLookTableDims",
            50982: "ProfileLookTableData",
            51009: "OpcodeList2",
            51022: "OpcodeList3",
            51041: "NoiseProfile",
            51111: "NewRawImageDigest",
            50932: "ProfileCalibrationSignature",
            50936: "ProfileName",
            50937: "ProfileHueSatMapDims",
            59932: "Padding",
            59933: "OffsetSchema",
        },
        # see lib/Image/ExifTool/FujiFilm.pm in exiftool
        "fuji": {
            0: "Version",
            16: "InternalSerialNumber",
            4096: "Quality",
            4097: "Sharpness",
            4098: "WhiteBalance",
            4099: "Saturation",
            4100: "Contrast",
            4101: "ColorTemperature",
            4102: "Contrast",
            4106: "WhiteBalanceFineTune",
            4107: "NoiseReduction",
            4110: "NoiseReduction",
            4111: "Clarity",
            4112: "FujiFlashMode",
            4113: "FlashExposureComp",
            4128: "Macro",
            4129: "FocusMode",
            4130: "AFMode",
            4139: "PrioritySettings",
            4141: "FocusSettings",
            4142: "AFCSettings",
            4131: "FocusPixel",
            4144: "SlowSync",
            4145: "PictureMode",
            4146: "ExposureCount",
            4147: "EXRAuto",
            4148: "EXRMode",
            4160: "ShadowTone",
            4161: "HighlightTone",
            4164: "DigitalZoom",
            4165: "LensModulationOptimizer",
            4167: "GrainEffectRoughness",
            4168: "ColorChromeEffect",
            4169: "BWAdjustment",
            4171: "BWMagentaGreen",
            4172: "GrainEffectSize",
            4173: "CropMode",
            4174: "ColorChromeFXBlue",
            4176: "ShutterType",
            4352: "AutoBracketing",
            4353: "SequenceNumber",
            4355: "DriveSettings",
            4357: "PixelShiftShots",
            4358: "PixelShiftOffset",
            4435: "PanoramaAngle",
            4436: "PanoramaDirection",
            4609: "AdvancedFilter",
            4624: "ColorMode",
            4864: "BlurWarning",
            4865: "FocusWarning",
            4866: "ExposureWarning",
            4868: "GEImageSize",
            5120: "DynamicRange",
            5121: "FilmMode",
            5122: "DynamicRangeSetting",
            5123: "DevelopmentDynamicRange",
            5124: "MinFocalLength",
            5125: "MaxFocalLength",
            5126: "MaxApertureAtMinFocal",
            5127: "MaxApertureAtMaxFocal",
            5131: "AutoDynamicRange",
            5154: "ImageStabilization",
            5157: "SceneRecognition",
            5169: "Rating",
            5174: "ImageGeneration",
            5176: "ImageCount",
            5187: "DRangePriority",
            5188: "DRangePriorityAuto",
            5189: "DRangePriorityFixed",
            5190: "FlickerReduction",
            5191: "FujiModel",
            5192: "FujiModel2",
            5197: "RollAngle",
            14339: "VideoRecordingMode",
            14340: "PeripheralLighting",
            14342: "VideoCompression",
            14368: "FrameRate",
            14369: "FrameWidth",
            14370: "FrameHeight",
            14372: "FullHDHighSpeedRec",
            16389: "FaceElementSelected",
            16640: "FacesDetected",
            16643: "FacePositions",
            16896: "NumFaceElements",
            16897: "FaceElementTypes",
            16899: "FaceElementPositions",
            17026: "FaceRecInfo",
            32768: "FileSource",
            32770: "OrderNumber",
            32771: "FrameNumber",
            45585: "Parallax",
        },
        "sony": {
            258: "Quality",
            260: "FlashExposureComp",
            261: "Teleconverter",
            274: "WhiteBalanceFineTune",
            277: "WhiteBalance",
            4096: "MultiBurstMode",
            4097: "MultiBurstImageWidth",
            4098: "MultiBurstImageHeight",
            8193: "PreviewImage",
            8194: "Rating",
            8196: "Contrast",
            8197: "Saturation",
            8198: "Sharpness",
            8199: "Brightness",
            8200: "LongExposureNoiseReduction",
            8201: "HighISONoiseReduction",
            8202: "AutoHDR",
            8203: "MultiFrameNoiseReduction",
            8206: "PictureEffect",
            8207: "SoftSkinEffect",
            8209: "VignettingCorrection",
            8210: "LateralChromaticAberration",
            8211: "DistortionCorrectionSetting",
            8212: "WBShiftABGM",
            8214: "AutoPortraitFramed",
            8215: "FlashAction",
            8218: "ElectronicFrontCurtainShutter",
            8219: "FocusMode2",
            8220: "AFAreaModeSetting",
            8221: "FlexibleSpotPosition",
            8222: "AFPointSelected",
            8224: "AFPointsUsed",
            8225: "AFTracking",
            8226: "FocalPlaneAFPointsUsed",
            8227: "MultiFrameNREffect",
            8230: "WBShiftABGMPrecise",
            8231: "FocusLocation",
            8232: "VariableLowPassFilter",
            8233: "RAWFileType",
            8234: "Tag202a",
            8235: "PrioritySetInAWB",
            8236: "MeteringMode2",
            8237: "ExposureStandardAdjustment",
            8238: "Quality2",
            8239: "PixelShiftInfo",
            8241: "SerialNumber",
            8242: "Shadows",
            8243: "Highlights",
            8244: "Fade",
            8245: "SharpnessRange",
            8246: "Clarity",
            8247: "FocusFrameSize",
            8249: "JPEGHEIFSwitch",
            37888: "Tag9400",
            45056: "FileFormat",
            45057: "SonyModelID",
            45088: "CreativeStyle",
            45089: "ColorTemperature",
            45090: "ColorCompensationFilter",
            45091: "SceneMode",
            45092: "ZoneMatching",
            45093: "DynamicRangeOptimizer",
            45094: "ImageStabilization",
            45095: "LensID",
            45097: "ColorMode",
            45098: "LensSpec",
            45099: "FullImageSize",
            45100: "PreviewImageSize",
            45120: "Macro",
            45121: "ExposureMode",
            45122: "FocusMode",
            45123: "AFMode",
            45124: "AFIlluminator",
            45127: "JPEGQuality",
            45128: "FlashLevel",
            45129: "ReleaseMode",
            45130: "SequenceNumber",
            45131: "AntiBlur",
            45134: "FocusMode3",
            45135: "DynamicRangeOptimizer2",
            45136: "HighISONoiseReduction2",
            45138: "IntelligentAuto",
            45140: "WhiteBalance2",
        },
    }

    FIELD_TYPES = {
        1: "Byte",
        2: "ASCII string",
        3: "Short",
        4: "Long",
        5: "Rational",
        6: "Signed byte",
        7: "Undefined",
        8: "Signed short",
        9: "Signed long",
        10: "Signed rational",
        11: "Float",
        12: "Double",
    }

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) in (b"II*\x00", b"MM\x00*", b"Exif") or buf.peek(8) in (
            b"FUJIFILM",
            b"SONY DSC",
        )

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "tiff"

        le = None
        base = 0
        mode = "tiff"
        shallow = 0

        if self.buf.peek(4) == b"Exif":
            self.buf.skip(6)
            base += 6
        elif self.buf.peek(8) == b"FUJIFILM":
            self.buf.skip(8)
            le = True
            mode = "fuji"
        elif self.buf.peek(8) == b"SONY DSC":
            self.buf.skip(12)
            le = True
            shallow = 1
            mode = "sony"

        if le is None:
            header = self.buf.read(4)
            le = header[0] == 0x49

        meta["endian"] = "little" if le else "big"

        meta["data"] = {}
        meta["data"]["tags"] = []

        offset_queue: list[int] = []
        thumbnail_offset = None
        thumbnail_length = None
        thumbnail_tag = None
        while True:
            if not shallow:
                if self.buf.available() > 0:
                    offset = self.buf.ru32l() if le else self.buf.ru32()
                else:
                    offset = 0

                if offset == 0:
                    if len(offset_queue):
                        offset = offset_queue.pop()
                    else:
                        break

                self.buf.seek(offset + base)
                if self.buf.available() == 0:
                    continue
            else:
                if shallow == 2:
                    break

                shallow += 1

            entry_count = self.buf.ru16l() if le else self.buf.ru16()

            try:
                for i in range(0, entry_count):
                    tag: dict = {}

                    tag_id = self.buf.ru16l() if le else self.buf.ru16()
                    tag["id"] = self.TAG_IDS[mode].get(tag_id, "Unknown") + f" (0x{hex(tag_id)[2:].zfill(4)})"
                    field_type = self.buf.ru16l() if le else self.buf.ru16()
                    tag["type"] = self.FIELD_TYPES.get(field_type, "Unknown") + f" (0x{hex(field_type)[2:].zfill(4)})"
                    count = self.buf.ru32l() if le else self.buf.ru32()
                    tag["count"] = count
                    offset_field_offset = self.buf.tell() - base
                    tag_offset = self.buf.ru32l() if le else self.buf.ru32()
                    tag["offset-or-value"] = tag_offset

                    tag["values"] = []
                    with self.buf:
                        if (
                            (field_type in (1, 2, 7) and count <= 4)
                            or (field_type in (3, 8, 11) and count <= 2)
                            or (field_type in (4, 9, 12) and count <= 1)
                        ):
                            self.buf.seek(offset_field_offset + base)
                        else:
                            self.buf.seek(tag_offset + base)

                        ivalue: int
                        dvalue: dict
                        for i in range(0, count):
                            match field_type:
                                case 1:
                                    tag["values"].append(self.buf.ru8l() if le else self.buf.ru8())
                                case 2:
                                    string = b""
                                    while self.buf.peek(1)[0]:
                                        string += self.buf.read(1)

                                    self.buf.skip(1)
                                    tag["values"].append(string.decode("latin-1"))
                                    count -= len(string) + 1
                                    if count <= 0:
                                        break
                                case 3:
                                    tag["values"].append(self.buf.ru16l() if le else self.buf.ru16())
                                case 4:
                                    ivalue = self.buf.ru32l() if le else self.buf.ru32()
                                    tag["values"].append(ivalue)

                                    if "IFD" in tag["id"]:
                                        offset_queue.append(ivalue)
                                case 5:
                                    dvalue = {}
                                    dvalue["numerator"] = self.buf.ru32l() if le else self.buf.ru32()
                                    dvalue["denominator"] = self.buf.ru32l() if le else self.buf.ru32()
                                    dvalue["rational-approx"] = (
                                        dvalue["numerator"] / dvalue["denominator"] if dvalue["denominator"] else "NaN"
                                    )
                                    tag["values"].append(dvalue)
                                case 6:
                                    tag["values"].append(self.buf.ri8l() if le else self.buf.ri8())
                                case 7:
                                    tag["values"].append(self.buf.rh(count))
                                    break
                                case 8:
                                    tag["values"].append(self.buf.ri16l() if le else self.buf.ri16())
                                case 9:
                                    tag["values"].append(self.buf.ri32l() if le else self.buf.ri32())
                                case 10:
                                    dvalue = {}
                                    dvalue["numerator"] = self.buf.ri32l() if le else self.buf.ri32()
                                    dvalue["denominator"] = self.buf.ri32l() if le else self.buf.ri32()
                                    dvalue["rational-approx"] = (
                                        dvalue["numerator"] / dvalue["denominator"] if dvalue["denominator"] else "NaN"
                                    )
                                    tag["values"].append(dvalue)
                                case 11:
                                    tag["values"].append(self.buf.rf32l() if le else self.buf.rf32())
                                case 12:
                                    tag["values"].append(self.buf.rf64l() if le else self.buf.rf64())
                                case _:
                                    tag["unknown"] = True

                    match mode:
                        case "tiff":
                            match tag_id:
                                case 513:
                                    thumbnail_offset = tag["values"][0]
                                    thumbnail_tag = tag
                                case 514:
                                    thumbnail_length = tag["values"][0]
                                case 37500:
                                    tag["parsed"] = chew(bytes.fromhex(tag["values"][0]))
                                    del tag["values"]
                                case 37510:
                                    blob = bytes.fromhex(tag["values"][0])
                                    encoding, blob = (
                                        blob[:8].decode("latin-1").rstrip("\x00"),
                                        blob[8:],
                                    )

                                    tag["parsed"] = {"encoding": encoding}
                                    match encoding:
                                        case "ASCII":
                                            tag["parsed"]["text"] = blob.decode("latin-1")
                                            del tag["values"]
                                        case "UNICODE":
                                            tag["parsed"]["text"] = blob.decode("utf-16be")
                                            del tag["values"]
                                        case _:
                                            tag["parsed"]["unknown"] = True
                                case 2 | 36864 | 40960 | 45056:
                                    if len(tag["values"]) == 1 and type(tag["values"][0]) is str:
                                        temp = bytes.fromhex(tag["values"][0]).decode("latin-1")
                                        tag["parsed"] = (
                                            temp[:2].lstrip("0") + "." + (temp[2:].rstrip("0") if temp[2:] != "00" else "0")
                                        )

                                        if tag_id == 2:
                                            tag["id"] = "Version (0x0002)"

                                        del tag["values"]
                                case 45058:
                                    tag["parsed"] = {}
                                    buf = Buf(bytes.fromhex(tag["values"][0]))

                                    itemp = buf.ru32l()
                                    flags = (itemp >> 27) & 0x1f
                                    tag["parsed"]["flags"] = {
                                        "raw": flags,
                                        "representative": bool(flags & 0x02),
                                        "dependent-child": bool(flags & 0x04),
                                        "dependend-parent": bool(flags & 0x08),
                                    }
                                    tag["parsed"]["format"] = utils.unraw((itemp >> 24) & 0x07, 1, {0: "JPEG"})
                                    tag["parsed"]["type"] = utils.unraw(
                                        itemp & 0xffffff,
                                        3,
                                        {
                                            0x000000: "Undefined",
                                            0x010001: "Large Thumbnail (VGA equivalent)",
                                            0x010002: "Large Thumbnail (full HD equivalent)",
                                            0x010003: "Large Thumbnail (4K equivalent)",
                                            0x010004: "Large Thumbnail (8K equivalent)",
                                            0x010005: "Large Thumbnail (16K equivalent)",
                                            0x020001: "Multi-frame Panorama",
                                            0x020002: "Multi-frame Disparity",
                                            0x020003: "Multi-angle",
                                            0x030000: "Baseline MP Primary Image",
                                            0x040000: "Original Preservation Image",
                                            0x050000: "Gain Map Image",
                                        },
                                    )
                                    tag["parsed"]["image-start"] = buf.ru32l()
                                    tag["parsed"]["image-end"] = buf.ru32l()
                                    tag["parsed"]["dependent-image-entries"] = [buf.ru16l() for i in range(0, 2)]
                                    del tag["values"]
                        case "sony":
                            match tag_id:
                                case 8234:
                                    tag["parsed"] = {}
                                    buf = Buf(bytes.fromhex(tag["values"][0]))

                                    tag["parsed"]["used"] = buf.ru8()
                                    tag["parsed"]["area"] = [buf.ru16() for i in range(0, 2)]
                                    tag["parsed"]["points"] = [[buf.ru16() for i in range(0, 2)] for j in range(0, 15)]

                                    del tag["values"]

                    if thumbnail_tag is not None and thumbnail_offset is not None and thumbnail_length is not None:
                        with self.buf:
                            self.buf.seek(thumbnail_offset + base)

                            with self.buf.sub(thumbnail_length):
                                thumbnail_tag["parsed"] = chew(self.buf)

                        thumbnail_tag = None
                        thumbnail_offset = None
                        thumbnail_length = None

                    meta["data"]["tags"].append(tag)
            except Exception:
                pass

        self.buf.skip(self.buf.available())

        return meta


@module.register
class GifModule(module.RuminantModule):
    desc = "GIF files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(3) == b"GIF"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "gif"

        self.buf.skip(3)

        meta["version"] = self.buf.rs(3)

        meta["header"] = {}
        meta["header"]["width"] = self.buf.ru16l()
        meta["header"]["height"] = self.buf.ru16l()

        gct = self.buf.ru8()
        meta["header"]["gct-size"] = 2 ** ((gct >> 5) + 1) * 3
        meta["header"]["is-sorted"] = bool((gct >> 4) & 1)
        meta["header"]["color-resolution"] = (gct >> 1) & 0x07
        meta["header"]["gct-present"] = bool(gct & 1)
        meta["header"]["background-color-index"] = self.buf.ru8()
        meta["header"]["pixel-aspect-ratio"] = self.buf.ru8()

        if meta["header"]["gct-present"]:
            self.buf.skip(meta["header"]["gct-size"])

        meta["blocks"] = []
        running = True
        while running:
            block: dict = {}
            block["offset"] = self.buf.tell()

            typ = self.buf.ru8()
            match typ:
                case 0x2c:
                    block["type"] = "image-descriptor"
                    block["data"] = {}
                    block["data"]["left"] = self.buf.ru16()
                    block["data"]["top"] = self.buf.ru16()
                    block["data"]["width"] = self.buf.ru16()
                    block["data"]["height"] = self.buf.ru16()

                    lct = self.buf.ru8()
                    block["data"]["lct-present"] = bool(lct & 0x80)
                    block["data"]["is-interlaced"] = bool(lct & 0x40)
                    block["data"]["is-sorted"] = bool(lct & 0x20)
                    block["data"]["reserved"] = (lct >> 3) & 0x03
                    block["data"]["lct-size"] = 2 ** ((lct & 0x07) + 1) * 3

                    if block["data"]["lct-present"]:
                        self.buf.skip(block["data"]["lct-size"])

                    block["data"]["lzw-minimum-code-size"] = self.buf.ru8()
                    block["subdata-length"] = len(self.read_subblocks())
                case 0x21:
                    block["type"] = "extension"
                    label = self.buf.ru8()
                    block["label"] = label
                    block["size"] = self.buf.ru8()

                    processed_subdata = False
                    match label:
                        case 0xf9:
                            block["extension"] = "gce"

                            flags = self.buf.ru8()
                            block["data"] = {
                                "reserved": flags >> 5,
                                "disposal-method": (flags >> 2) & 0x07,
                                "user-input-flag": bool(flags & 0x02),
                                "transparent-color-flag": bool(flags & 0x01),
                                "delay-time": self.buf.ru16(),
                                "transparent-color-index": self.buf.ru8(),
                            }
                        case 0xfe:
                            block["extension"] = "comment"
                            block["data"] = utils.decode(self.read_subblocks())
                            processed_subdata = True
                        case 0xff:
                            block["extension"] = "application"
                            block["application"] = self.buf.rs(block["size"])

                            match block["application"]:
                                case "NETSCAPE2.0":
                                    data = self.read_subblocks()
                                    block["data"] = {
                                        "id": data[0],
                                        "loop": int.from_bytes(data[1:], "big"),
                                    }

                                    processed_subdata = True
                                case "XMP DataXMP":
                                    data = b""
                                    while self.buf.pu8() != 0x01:
                                        data += self.buf.read(1)

                                    while self.buf.pu8() != 0:
                                        self.buf.skip(1)

                                    self.buf.skip(2)

                                    block["data"] = utils.xml_to_dict(data.decode("utf-8"))

                                    processed_subdata = True
                                case _:
                                    block["unknown"] = True
                        case _:
                            block["data"] = self.buf.rh(block["size"])
                            block["unknown"] = True

                    if not processed_subdata:
                        if self.buf.peek(1)[0]:
                            block["subdata"] = self.read_subblocks().hex()
                        else:
                            self.buf.skip(1)
                case 0x3b:
                    block["type"] = "end"
                    running = False
                case _:
                    raise ValueError(f"Unknown GIF block type {typ}")

            meta["blocks"].append(block)

        return meta

    def read_subblocks(self):
        data = b""

        while True:
            length = self.buf.ru8()
            if length == 0:
                return data

            data += self.buf.read(length)


@module.register
class HdrpMakernoteModule(module.RuminantModule):
    desc = "Google HDR+ Makernote data, reverse engineered by me :D."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"HDRP"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "hdrp-makernote"

        self.buf.skip(4)
        meta["version"] = self.buf.ru8()

        mcontent = bytearray(self.buf.read(self.buf.available()))
        key = 0x2515606b4a7791cd

        # really sneaky to use xorshift
        # too bad you can just google the magic multiplier
        for i in range(0, len(mcontent)):
            if i % 8 == 0:
                key ^= (key >> 12) & 0xffffffffffffffff
                key ^= (key << 25) & 0xffffffffffffffff
                key ^= (key >> 27) & 0xffffffffffffffff
                key = (key * 0x2545f4914f6cdd1d) & 0xffffffffffffffff

            mcontent[i] ^= (key >> (8 * (i % 8))) & 0xff

        content = gzip.decompress(mcontent)

        buf = Buf(content)

        if buf.peek(7) == b"Payload" or buf.peek(3) == b"dng" or buf.peek(22) == b"shot_makernote_version":
            meta["data"] = buf.rs(buf.available()).split("\n")
        else:
            if meta["version"] == 3:
                meta["data"] = utils.read_protobuf(buf, len(content), escape=True, decode=constants.HDRP_V3_PROTO)
            else:
                meta["data"] = utils.read_protobuf(buf, len(content), escape=True, decode=constants.HDRP_V2_PROTO)

        return meta


@module.register
class PsdModule(IRBModule):
    desc = "Adobe Photoshop files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"8BPS"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "psd"

        self.buf.skip(4)
        meta["header"] = {}
        meta["header"]["version"] = self.buf.ru16()
        self.old = meta["header"]["version"] == 1
        meta["header"]["reserved"] = self.buf.rh(6)
        meta["header"]["channels"] = self.buf.ru16()
        meta["header"]["width"] = self.buf.ru32()
        meta["header"]["height"] = self.buf.ru32()
        meta["header"]["depth"] = self.buf.ru16()
        meta["header"]["color-mode"] = utils.unraw(
            self.buf.ru16(),
            2,
            {
                0: "Bitmap",
                1: "Grayscale",
                2: "Indexed",
                3: "RGB",
                4: "CMYK",
                7: "Multichannel",
                8: "Duotone",
                9: "Lab",
            },
        )

        meta["color-mode-data-length"] = self.buf.ru32()
        self.buf.skip(meta["color-mode-data-length"])

        meta["image-resources-length"] = self.buf.ru32()
        with self.buf.sub(meta["image-resources-length"]):
            meta["image-resources"] = chew(self.buf)
        self.buf.skip(meta["image-resources-length"])

        meta["layers"] = {}
        self.buf.pushunit()
        self.buf.setunit(self.buf.ru32() if self.old else self.buf.ru64())

        self.buf.pushunit()
        self.buf.setunit(self.buf.ru32() if self.old else self.buf.ru64())
        meta["layers"]["record-count"] = self.buf.ri16()
        meta["layers"]["records"] = []

        for i in range(0, abs(meta["layers"]["record-count"])):
            record: dict = {}
            record["rect"] = [self.buf.ru32() for i in range(0, 4)]
            record["channel-count"] = self.buf.ru16()
            record["channels"] = [
                {
                    "id": utils.unraw(
                        self.buf.ri16(),
                        1,
                        {
                            0: "Red",
                            1: "Green",
                            2: "Blue",
                            -1: "Transparency mask",
                            -2: "User supplied layer mask",
                            -3: "Real user supplied layer mask",
                        },
                    ),
                    "length": self.buf.ru32() if self.old else self.buf.ru64(),
                }
                for i in range(0, record["channel-count"])
            ]
            self.buf.skip(4)
            record["key"] = self.buf.rs(4)
            record["opacity"] = self.buf.ru8()
            record["clipping"] = utils.unraw(self.buf.ru8(), 1, {0: "Base", 1: "Non-base"})
            flags = self.buf.ru8()
            record["flags"] = {
                "raw": flags,
                "transparency-protected": bool(flags & (1 << 0)),
                "visible": bool(flags & (1 << 1)),
                "obsolete": bool(flags & (1 << 2)),
                "bit4-valid": bool(flags & (1 << 3)),
                "pixel-data-irrelevant": bool(flags & (1 << 4)),
            }
            record["filter"] = self.buf.ru8()

            self.buf.pushunit()
            self.buf.setunit(self.buf.ru32())

            self.buf.skip(self.buf.ru32())
            self.buf.skip(self.buf.ru32())
            record["name"] = self.buf.rs(self.buf.ru8())

            self.buf.skipunit()
            self.buf.popunit()

            meta["layers"]["records"].append(record)

        self.buf.skipunit()
        self.buf.popunit()

        self.buf.skip(self.buf.ru32())

        meta["layers"]["effects"] = []
        while self.buf.unit is not None and self.buf.unit > 4:
            effect = {}
            self.buf.skip(4)
            effect["key"] = self.buf.rs(4)

            self.buf.pushunit()
            self.buf.setunit(
                self.buf.ru32()
                if (
                    self.old
                    or effect["key"]
                    not in [
                        "LMsk",
                        "Lr16",
                        "Lr32",
                        "Layr",
                        "Mt16",
                        "Mt32",
                        "Mtrn",
                        "Alph",
                        "FMsk",
                        "lnk2",
                        "FEid",
                        "FXid",
                        "PxSD",
                    ]
                )
                else self.buf.ru64()
            )

            match effect["key"]:
                case "Patt" | "Pat2" | "Pat3":
                    effect["data"] = []
                    while self.buf.hasunit():
                        self.buf.pushunit()
                        self.buf.setunit(self.buf.ru32())

                        pattern: dict = {}
                        pattern["version"] = self.buf.ru32()
                        pattern["image-mode"] = utils.unraw(
                            self.buf.ru32(),
                            4,
                            {
                                0: "Bitmap",
                                1: "Grayscale",
                                2: "Indexed",
                                3: "RGB",
                                4: "CMYK",
                                7: "Multichannel",
                                8: "Duotone",
                                9: "Lab",
                            },
                        )
                        pattern["points"] = [self.buf.ru16() for i in range(0, 2)]
                        pattern["name"] = self.buf.rs(self.buf.ru32())
                        pattern["id"] = self.buf.rs(self.buf.ru8())

                        effect["data"].append(pattern)

                        self.buf.skipunit()
                        self.buf.popunit()
                case "FMsk":
                    effect["data"] = {
                        "colorspace": self.buf.rh(10),
                        "opacity": self.buf.ru16(),
                    }
                case "cinf":
                    effect["data"] = {
                        "version": self.buf.ru32(),
                        "descriptor": self.read_descriptor(),
                    }
                case _:
                    effect["unknown"] = True

            self.buf.skipunit()
            self.buf.popunit()

            meta["layers"]["effects"].append(effect)

        self.buf.skipunit()
        self.buf.popunit()

        meta["image-data-compression"] = utils.unraw(
            self.buf.ru16(),
            2,
            {
                0: "Raw image data",
                1: "RLE",
                2: "ZIP without prediction",
                3: "ZIP with prediction",
            },
        )

        self.buf.skip(self.buf.available())

        return meta


@module.register
class JpegXlModule(module.RuminantModule):
    dev = True
    desc = "JPEG XL files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(2) == b"\xff\x0a"

    def ru32(self, d0, d1, d2, d3, o0=0, o1=0, o2=0, o3=0):
        index = self.buf.rbl(2)
        d = (d0, d1, d2, d3)[index]
        o = (o0, o1, o2, o3)[index]

        if d <= 0:
            return o - d
        else:
            return self.buf.rbl(d) + o

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "jpeg-xl"

        self.buf.skip(2)

        meta["header"] = {}
        meta["header"]["size"] = {}
        meta["header"]["size"]["div8"] = bool(self.buf.rbl(1))
        if meta["header"]["size"]["div8"]:
            meta["header"]["size"]["h-div8"] = self.buf.rbl(5) + 1
            meta["header"]["size"]["height"] = meta["header"]["size"]["h-div8"] * 8
        else:
            meta["header"]["size"]["h-div8"] = 0
            meta["header"]["size"]["height"] = self.ru32(9, 13, 18, 30, 1, 1, 1, 1)
        meta["header"]["size"]["ratio"] = self.buf.rbl(3)

        meta["header"]["size"]["w-div8"] = 0
        meta["header"]["size"]["width"] = (
            meta["header"]["size"]["height"]
            * [0, 1, 6, 4, 3, 16, 5, 2][meta["header"]["size"]["ratio"]]
            // [1, 1, 5, 3, 2, 9, 4, 1][meta["header"]["size"]["ratio"]]
        )

        if not meta["header"]["size"]["ratio"]:
            if meta["header"]["size"]["div8"]:
                meta["header"]["size"]["w-div8"] = self.buf.rbl(5) + 1
                meta["header"]["size"]["width"] = meta["header"]["size"]["w-div8"] * 8
            else:
                meta["header"]["size"]["width"] = self.ru32(9, 13, 18, 30, 1, 1, 1, 1)

        meta["metadata"] = {}
        meta["metadata"]["all-default"] = bool(self.buf.rbl(1))

        if not meta["metadata"]["all-default"]:
            meta["metadata"]["extra-fields"] = bool(self.buf.rbl(1))

            if meta["metadata"]["extra-fields"]:
                meta["metadata"]["orientation"] = self.buf.rbl(3) + 1
                meta["metadata"]["have-intr-size"] = bool(self.buf.rbl(1))
            else:
                meta["metadata"]["orientation"] = 1
        else:
            meta["metadata"]["extra-fields"] = False
            meta["metadata"]["orientation"] = 1
            meta["metadata"]["have-intr-size"] = False
            meta["metadata"]["have-preview"] = False
            meta["metadata"]["have-animation"] = False
            meta["metadata"]["modular-16bit-buffers"] = True
            meta["metadata"]["num-extra"] = 0
            meta["metadata"]["xyb-encoded"] = True

        self.buf.align()

        return meta


@module.register
class DicomModule(module.RuminantModule):
    desc = "DICOM files like the ones you get on a CD after an MRI."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(128 + 4)[128:] == b"DICM"

    def read_dataset(self):
        tag = {}

        group = self.buf.ru16l()
        element = self.buf.ru16l()
        ver = (group, element)
        tag["tag"] = f"({hex(group)[2:].zfill(4)},{hex(element)[2:].zfill(4)})"
        tag["name"] = constants.DICOM_NAMES.get(tag["tag"], "Unknown")

        if ver == (0xfffe, 0xe000):
            vr = "list"
            length = self.buf.ru32()
        else:
            if self.explicit:
                vr = self.buf.read(2).decode("latin-1")
                wide = vr in ("OB", "OW", "OF", "SQ", "UT", "UN")

                if wide:
                    self.buf.skip(2)

                if self.little:
                    length = self.buf.ru32l() if wide else self.buf.ru16l()
                else:
                    length = self.buf.ru32() if wide else self.buf.ru16()
            else:
                vr = None
                length = self.buf.ru32l()

        if length == 0xffffffff:
            length = self.buf.unit if self.buf.unit is not None else self.buf.available()

        if vr and vr != "list":
            if vr == "\x00\x00":
                vr = "UN"

            tag["vr"] = vr
        tag["length"] = length

        self.buf.pushunit()
        self.buf.setunit(length)

        match vr:
            case "UL":
                tag["value"] = self.buf.ru32l() if self.little else self.buf.ru32()
            case "OB" | "UN" | "OW":
                if ver == (2, 1):
                    tag["value"] = self.buf.ru16()
                else:
                    if tag["tag"] == "(7fe0,0010)":
                        while self.buf.peek(4) == b"\xfe\xff\x00\xe0":
                            self.buf.skip(8)

                    with self.buf.subunit():
                        tag["value"] = chew(self.buf)
            case "UI" | "SH" | "CS" | "DA" | "TM" | "LO" | "PN" | "IS" | "UT" | "AE" | "ST" | "AS" | "DS" | "LT" | "DT":
                tag["value"] = self.buf.rs(self.buf.unit)

                if vr == "DA":
                    tag["value"] = datetime.datetime.strptime(tag["value"], "%Y%m%d").strftime("%Y-%m-%d")
                elif vr == "DT":
                    try:
                        tag["value"] = datetime.datetime.strptime(tag["value"], "%Y%m%d%H%M%S.%f%z").strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    except ValueError:
                        tag["value"] = datetime.datetime.strptime(tag["value"], "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
                elif vr == "TM":
                    if "." in tag["value"]:
                        main, frac = tag["value"].split(".", 1)
                        frac = (frac + "000000")[:6]
                        tag["value"] = f"{main}.{frac}"
                        fmt = "%H%M%S.%f"
                    else:
                        fmt_map = {2: "%H", 4: "%H%M", 6: "%H%M%S"}
                        fmt = fmt_map.get(len(tag["value"]))
                        if not fmt:
                            raise ValueError(f"Invalid DICOM TM string: {tag['value']}")

                    tag["value"] = datetime.datetime.strptime(tag["value"], fmt).time().strftime("%H:%M:%S.%f")
                elif vr == "AS":
                    tag["value"] = {
                        "value": int(tag["value"][:3]),
                        "unit": {"D": "days", "M": "months", "Y": "years"}[tag["value"][3]],
                    }
                elif vr == "UI":
                    try:
                        tag["value"] = utils.lookup_oid([int(x) for x in tag["value"].split(".")])
                    except Exception:
                        pass
                else:
                    tag["value"] = tag["value"].rstrip(" ")

                    if "\\" in tag["value"]:
                        tag["value"] = tag["value"].split("\\")
            case "SQ":
                tag["value"] = []
                while self.buf.unit > 0:
                    if self.buf.peek(4) == b"\xfe\xff\xdd\xe0":
                        self.buf.skip(8)
                        self.buf.setunit(0)
                        break

                    try:
                        tag["value"].append(self.read_dataset())
                    except UnitException:
                        self.buf.setunit(0)
                        break
            case "list":
                tag["value"] = []
                while self.buf.unit > 0:
                    if self.buf.peek(4) == b"\xfe\xff\x0d\xe0":
                        self.buf.skip(8)
                        self.buf.setunit(0)
                        break

                    try:
                        tag["value"].append(self.read_dataset())
                    except UnitException:
                        self.buf.setunit(0)
                        break
            case "FD":
                tag["value"] = self.buf.rf64l() if self.little else self.buf.rf64()
            case "FL":
                tag["value"] = self.buf.rf32l() if self.little else self.buf.rf32()
            case "SL":
                tag["value"] = self.buf.ri64l() if self.little else self.buf.ri64()
            case "US":
                tag["value"] = self.buf.ru16l() if self.little else self.buf.ru16()
            case "SS":
                tag["value"] = self.buf.ri16l() if self.little else self.buf.ri16()
            case _:
                raise ValueError(f"Unknown VR {vr}, {tag}")

        match ver:
            case (0x0002, 0x0010):
                match tag["value"]["raw"]:
                    case "1.2.840.10008.1.2":
                        self.explicit = False
                        self.little = True
                    case "1.2.840.10008.1.2.1":
                        self.explicit = True
                        self.little = True
                    case "1.2.840.10008.1.2.2":
                        self.explicit = True
                        self.little = False
                    case _:
                        self.explicit = True
                        self.little = True

        self.buf.skipunit()
        self.buf.popunit()

        return tag

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "dicom"

        meta["preamble"] = chew(self.buf.read(128))
        self.buf.skip(4)

        self.explicit = True
        self.little = True

        meta["tags"] = []
        while self.buf.available() > 0:
            try:
                meta["tags"].append(self.read_dataset())
            except UnitException:
                break

        self.buf.skip(self.buf.available())

        return meta


@module.register
class ExrModule(module.RuminantModule):
    desc = "OpenEXR files"

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"v/1\x01"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "exr"

        self.buf.skip(4)
        temp = self.buf.ru32l()
        meta["version"] = temp & 0xff
        temp >>= 8
        meta["flags"] = {"raw": temp, "names": []}
        if temp & (1 << 0):
            meta["flags"]["names"].append("TILED")
        if temp & (1 << 1):
            meta["flags"]["names"].append("LONG_NAMES")
        if temp & (1 << 2):
            meta["flags"]["names"].append("DEEP")
        if temp & (1 << 3):
            meta["flags"]["names"].append("MULTIPART")

        meta["headers"] = []
        while self.buf.pu8() != 0x00:
            header = {}
            header["name"] = self.buf.rzs()
            header["type"] = self.buf.rzs()
            header["size"] = self.buf.ru32l()

            self.buf.pasunit(header["size"])

            match header["type"]:
                case "string":
                    header["payload"] = self.buf.rs(self.buf.unit)
                case "float":
                    header["payload"] = self.buf.rf32l()
                case "chlist":
                    header["payload"] = []
                    while self.buf.pu8() != 0:
                        channel = {}
                        channel["name"] = self.buf.rzs()
                        channel["pixel-type"] = utils.unraw(
                            self.buf.ru32l(),
                            4,
                            {
                                0x00000000: "16-bit float",
                                0x00000001: "32-bit float",
                                0x00000002: "32-bit unsigned integer",
                            },
                            True,
                        )
                        channel["is-linear"] = bool(self.buf.ru8())
                        channel["reserved"] = self.buf.rh(3)
                        channel["x-sampling"] = self.buf.ru32l()
                        channel["y-sampling"] = self.buf.ru32l()

                        header["payload"].append(channel)
                case "compression":
                    header["payload"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {
                            0x00: "NONE",
                            0x01: "RLE",
                            0x02: "ZIPS",
                            0x03: "ZIP",
                            0x04: "PIZ",
                            0x05: "PXR24",
                            0x06: "B44",
                            0x07: "B44A",
                            0x08: "DWAA",
                            0x09: "DWAB",
                        },
                        True,
                    )
                case "box2i":
                    header["payload"] = {
                        "xmin": self.buf.ru32l(),
                        "ymin": self.buf.ru32l(),
                        "xmax": self.buf.ru32l(),
                        "ymax": self.buf.ru32l(),
                    }
                case "lineOrder":
                    header["payload"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {0x00: "INCREASING_Y", 0x01: "DECREASING_Y", 0x02: "RANDOM_Y"},
                        True,
                    )
                case "stringvector":
                    header["payload"] = []
                    while self.buf.hasunit():
                        header["payload"].append(self.buf.rs(self.buf.ru32l()))
                case "v2f":
                    header["payload"] = [self.buf.rf32l(), self.buf.rf32l()]
                case _:
                    header["payload"] = self.buf.rh(self.buf.unit)
                    header["unknown"] = True

            self.buf.sapunit()

            meta["headers"].append(header)

        self.buf.skip(1)

        m = 0
        meta["chunk-count"] = 0
        while True:
            n = self.buf.ru64l()
            if n <= m or (n + 8) > self.buf.size():
                break

            m = n
            meta["chunk-count"] += 1

        self.buf.skip(16 if "TILED" in meta["flags"]["names"] else 8)
        self.buf.skip(self.buf.ru32l())

        return meta


@module.register
class IcoModule(module.RuminantModule):
    desc = "Microsoft ICO files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 6:
            return False

        if buf.pu32() not in (256, 512):
            return False

        with buf:
            buf.skip(4)
            count = buf.ru16l()

            if count == 0 or buf.available() < count * 16:
                return False

            max_offset = 0
            for i in range(0, count):
                buf.skip(3)
                if buf.ru8() != 0:
                    return False

                buf.skip(4)
                max_offset = max(max_offset, buf.ru32l() + buf.ru32l())

            if buf.size() < max_offset:
                return False

        return True

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "ico"

        self.buf.skip(2)
        meta["type"] = utils.unraw(self.buf.ru16l(), 2, {0x01: "ICO", 0x02: "CUR"}, True)

        meta["count"] = self.buf.ru16l()
        meta["entries"] = []
        for i in range(0, meta["count"]):
            entry = {}
            entry["width"] = self.buf.ru8()
            entry["height"] = self.buf.ru8()
            entry["color-count"] = self.buf.ru8()
            entry["reserved"] = self.buf.ru8()
            entry["planes"] = self.buf.ru16l()
            entry["bit-count"] = self.buf.ru16l()
            entry["bytes-in-res"] = self.buf.ru32l()
            entry["image-offset"] = self.buf.ru32l()

            meta["entries"].append(entry)

        max_offset = self.buf.tell()
        for entry in meta["entries"]:
            max_offset = max(max_offset, entry["image-offset"] + entry["bytes-in-res"])

            self.buf.seek(entry["image-offset"])
            with self.buf.sub(entry["bytes-in-res"]):
                entry["blob"] = chew(self.buf)

        self.buf.seek(max_offset)

        return meta


@module.register
class XcfModule(module.RuminantModule):
    dev = True
    desc = "GIMP XCF files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(9) == b"gimp xcf "

    def rp(self):
        return self.buf.ru64() if self.wide else self.buf.ru32()

    def read_properties(self):
        properties = []
        while True:
            prop = {}
            prop["type"] = utils.unraw(
                self.buf.ru32(),
                4,
                {
                    0x00000000: "END",
                    0x00000002: "ACTIVE_LAYER",
                    0x00000006: "OPACITY",
                    0x00000007: "MODE",
                    0x00000008: "VISIBLE",
                    0x00000009: "LINKED",
                    0x0000000a: "LOCK_ALPHA",
                    0x0000000b: "APPLY_MASK",
                    0x0000000c: "EDIT_MASK",
                    0x0000000d: "SHOW_MASK",
                    0x0000000f: "OFFSETS",
                    0x00000011: "COMPRESSION",
                    0x00000013: "RESOLUTION",
                    0x00000014: "TATTOO",
                    0x00000015: "PARASITES",
                    0x00000016: "UNIT",
                    0x0000001c: "LOCK_CONTENT",
                    0x00000020: "LOCK_POSITION",
                    0x00000021: "FLOAT_OPACITY",
                    0x00000022: "COLOR_TAG",
                    0x00000023: "COMPOSITE_MODE",
                    0x00000024: "COMPOSITE_SPACE",
                    0x00000025: "BLEND_SPACE",
                },
                True,
            )

            prop["length"] = self.buf.ru32()

            self.buf.pasunit(prop["length"])

            prop["value"] = {}
            match prop["type"]:
                case "COMPRESSION":
                    prop["value"]["compression"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {0x00: "None", 0x01: "RLE", 0x02: "zlib"},
                        True,
                    )
                case "RESOLUTION":
                    prop["value"]["horizontal-ppi"] = self.buf.rf32()
                    prop["value"]["vertical-ppi"] = self.buf.rf32()
                case "TATTOO":
                    prop["value"]["id"] = self.buf.ru32()
                case "UNIT":
                    prop["value"]["unit"] = utils.unraw(
                        self.buf.ru32(),
                        4,
                        {
                            0x00000001: "Inches",
                            0x00000002: "Millimeters",
                            0x00000003: "Points",
                            0x00000004: "Picas",
                        },
                        True,
                    )
                case "PARASITES":
                    prop["value"]["entries"] = []
                    while self.buf.unit > 0:
                        entry = {}
                        entry["name"] = self.buf.rs(self.buf.ru32())
                        entry["flags"] = self.buf.ru32()
                        entry["length"] = self.buf.ru32()

                        self.buf.pasunit(entry["length"])

                        match entry["name"]:
                            case "gimp-image-grid":
                                entry["value"] = self.buf.rs(self.buf.unit).split("\n")
                            case "gimp-image-metadata":
                                entry["value"] = utils.xml_to_dict(self.buf.rs(self.buf.unit))
                            case "jpeg-settings":
                                entry["value"] = self.buf.rh(self.buf.unit)
                            case _:
                                entry["value"] = self.buf.rh(self.buf.unit)
                                entry["unknown"] = True

                        self.buf.sapunit()

                        prop["value"]["entries"].append(entry)
                case "OPACITY":
                    prop["value"][prop["type"].lower().replace("_", "-")] = self.buf.ru32()
                case (
                    "VISIBLE"
                    | "LINKED"
                    | "LOCK_CONTENT"
                    | "LOCK_ALPHA"
                    | "LOCK_POSITION"
                    | "APPLY_MASK"
                    | "EDIT_MASK"
                    | "SHOW_MASK"
                ):
                    prop["value"][prop["type"].lower().replace("_", "-")] = bool(self.buf.ru32())
                case "FLOAT_OPACITY":
                    prop["value"]["opacity"] = self.buf.rf32()
                case "COLOR_TAG":
                    prop["value"]["color"] = utils.unraw(
                        self.buf.ru32(),
                        4,
                        {
                            0x00000000: "None",
                            0x00000001: "Blue",
                            0x00000002: "Green",
                            0x00000003: "Yellow",
                            0x00000004: "Orange",
                            0x00000005: "Brown",
                            0x00000006: "Red",
                            0x00000007: "Violet",
                            0x00000008: "Gray",
                        },
                        True,
                    )
                case "OFFSETS":
                    prop["value"]["xoffset"] = self.buf.ru32()
                    prop["value"]["yoffset"] = self.buf.ru32()
                case "MODE":
                    prop["value"]["mode"] = utils.unraw(
                        self.buf.ru32(),
                        4,
                        {
                            0x00000000: "Normal (legacy)",
                            0x00000001: "Dissolve (legacy)",
                            0x00000002: "Behind (legacy)",
                            0x00000003: "Multiply (legacy)",
                            0x00000004: "Screen (legacy)",
                            0x00000005: "Old broken Overlay",
                            0x00000006: "Difference (legacy)",
                            0x00000007: "Addition (legacy)",
                            0x00000008: "Subtract (legacy)",
                            0x00000009: "Darken only (legacy)",
                            0x0000000a: "Lighten only (legacy)",
                            0x0000000b: "Hue (HSV) (legacy)",
                            0x0000000c: "Saturation (HSV) (legacy)",
                            0x0000000d: "Color (HSL) (legacy)",
                            0x0000000e: "Value (HSV) (legacy)",
                            0x0000000f: "Divide (legacy)",
                            0x00000010: "Dodge (legacy)",
                            0x00000011: "Burn (legacy)",
                            0x00000012: "Hard Light (legacy)",
                            0x00000013: "Soft light (legacy)",
                            0x00000014: "Grain extract (legacy)",
                            0x00000015: "Grain merge (legacy)",
                            0x00000016: "Color erase (legacy)",
                            0x00000017: "Overlay",
                            0x00000018: "Hue (LCH)",
                            0x00000019: "Chroma (LCH)",
                            0x0000001a: "Color (LCH)",
                            0x0000001b: "Lightness (LCH)",
                            0x0000001c: "Normal",
                            0x0000001d: "Behind",
                            0x0000001e: "Multiply",
                            0x0000001f: "Screen",
                            0x00000020: "Difference",
                            0x00000021: "Addition",
                            0x00000022: "Subtract",
                            0x00000023: "Darken only",
                            0x00000024: "Lighten only",
                            0x00000025: "Hue (HSV)",
                            0x00000026: "Saturation (HSV)",
                            0x00000027: "Color (HSL)",
                            0x00000028: "Value (HSV)",
                            0x00000029: "Divide",
                            0x0000002a: "Dodge",
                            0x0000002b: "Burn",
                            0x0000002c: "Hard light",
                            0x0000002d: "Soft light",
                            0x0000002e: "Grain extract",
                            0x0000002f: "Grain merge",
                            0x00000030: "Vivid light",
                            0x00000031: "Pin light",
                            0x00000032: "Linear light",
                            0x00000033: "Hard mix",
                            0x00000034: "Exclusion",
                            0x00000035: "Linear burn",
                            0x00000036: "Luma/Luminance darken only",
                            0x00000037: "Luma/Luminance lighten only",
                            0x00000038: "Luminance",
                            0x00000039: "Color erase",
                            0x0000003a: "Erase",
                            0x0000003b: "Merge",
                            0x0000003c: "Split",
                            0x0000003d: "Pass through",
                        },
                        True,
                    )
                case "BLEND_SPACE" | "COMPOSITE_SPACE":
                    temp = self.buf.ri32()
                    prop["value"]["space"] = utils.unraw(
                        abs(temp),
                        4,
                        {
                            0x00000000: "None",
                            0x00000001: "RGB (linear)",
                            0x00000002: "RGB (from color profile)",
                            0x00000003: "LAB",
                            0x00000004: "RGB (perceptual)",
                        },
                        True,
                    )
                    prop["value"]["auto"] = temp < 0
                case "COMPOSITE_MODE":
                    temp = self.buf.ri32()
                    prop["value"]["mode"] = utils.unraw(
                        abs(temp),
                        4,
                        {
                            0x00000001: "Union",
                            0x00000002: "Clip to backdrop",
                            0x00000003: "Clip to layer",
                            0x00000004: "Intersection",
                        },
                        True,
                    )
                    prop["value"]["auto"] = temp < 0
                case "END" | "ACTIVE_LAYER":
                    pass
                case _:
                    prop["value"]["payload"] = self.buf.rh(self.buf.unit)
                    prop["unknown"] = True

            self.buf.sapunit()
            properties.append(prop)

            if prop["type"] == "END":
                break

        return properties

    def chew(self) -> ruminant_types.JSON:
        # https://developer.gimp.org/core/standards/xcf/#the-image-structure
        meta: dict = {}
        meta["type"] = "xcf"

        self.buf.skip(9)
        meta["version"] = self.buf.rs(5)

        self.wide = meta["version"][0] == "v" and int(meta["version"][1:]) >= 11

        meta["width"] = self.buf.ru32()
        meta["height"] = self.buf.ru32()
        meta["base-type"] = utils.unraw(
            self.buf.ru32(),
            4,
            {0x00000000: "RGB", 0x00000001: "Grayscale", 0x00000002: "Indexed color"},
            True,
        )
        meta["precision"] = utils.unraw(
            self.buf.ru32(),
            4,
            {
                0x00000000: "8-bit gamma integer",
                0x00000001: "16-bit gamma integer",
                0x00000002: "32-bit linear integer",
                0x00000003: "16-bit linear floating point",
                0x00000004: "32-bit linear floating point",
                0x00000064: "8-bit linear integer",
                0x00000096: "8-bit gamma integer",
                0x000000c8: "16-bit linear integer",
                0x000000fa: "16-bit gamma integer",
                0x0000012c: "32-bit linear integer",
                0x0000015e: "32-bit gamma integer",
                0x00000190: "16-bit linear floating point",
                0x000001c2: "16-bit gamma floating point",
                0x000001f4: "16-bit linear floating point",
                0x00000226: "16-bit gamma floating point",
                0x00000258: "32-bit linear floating point",
                0x0000028a: "32-bit gamma floating point",
                0x000002bc: "64-bit linear floating point",
                0x000002ee: "64-bit gamma floating point",
            },
            True,
        )

        meta["properties"] = self.read_properties()

        meta["layers"] = []
        while True:
            ptr = self.rp()
            if ptr == 0:
                break

            meta["layers"].append({"offset": ptr})

        meta["channels"] = []
        while True:
            ptr = self.rp()
            if ptr == 0:
                break

            meta["channels"].append({"offset": ptr})

        for layer in meta["layers"]:
            self.buf.seek(layer["offset"])

            layer["width"] = self.buf.ru32()
            layer["height"] = self.buf.ru32()
            layer["type"] = utils.unraw(self.buf.ru32(), 4, constants.GIMP_IMAGE_TYPES, True)
            layer["name"] = self.buf.rs(self.buf.ru32())
            layer["properties"] = self.read_properties()
            layer["hierachy-pointer"] = self.rp()
            layer["mask-pointer"] = self.rp()

        return meta


@module.register
class QoiModule(module.RuminantModule):
    desc = "qoi files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"qoif"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "qoi"

        self.buf.skip(4)
        meta["width"] = self.buf.ru32()
        meta["height"] = self.buf.ru32()
        meta["channels"] = utils.unraw(self.buf.ru8(), 1, {0x03: "RGB", 0x04: "RGBA"}, True)
        meta["colorspace"] = utils.unraw(self.buf.ru8(), 1, {0x00: "sRGB with linear alpha", 0x01: "all channels linear"}, True)

        op_rgb = 0
        op_rgba = 0
        op_index = 0
        op_diff = 0
        op_luma = 0
        op_run = 0

        pixels = meta["width"] * meta["height"]
        while pixels > 0:
            op = self.buf.ru8()

            match op:
                case 0b11111110:
                    self.buf.skip(3)
                    pixels -= 1
                    op_rgb += 1
                case 0b11111111:
                    self.buf.skip(4)
                    pixels -= 1
                    op_rgba += 1
                case _:
                    match op >> 6:
                        case 0b00:
                            pixels -= 1
                            op_index += 1
                        case 0b01:
                            pixels -= 1
                            op_diff += 1
                        case 0b10:
                            self.buf.skip(1)
                            pixels -= 1
                            op_luma += 1
                        case 0b11:
                            pixels -= (op & 0b00111111) + 1
                            op_run += 1

        meta["ops"] = {
            "RGB": op_rgb,
            "RGBA": op_rgba,
            "INDEX": op_index,
            "DIFF": op_diff,
            "LUMA": op_luma,
            "RUN": op_run,
            "total": op_rgb + op_rgba + op_index + op_diff + op_luma + op_run,
            "pixels": meta["width"] * meta["height"],
        }

        meta["has-footer"] = False
        if self.buf.available() >= 8 and self.buf.pu64() == 1:
            self.buf.skip(8)
            meta["has-footer"] = True

        return meta
