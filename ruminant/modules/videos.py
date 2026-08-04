import uuid
import struct
import datetime
import math
from .. import module, utils, ruminant_types, secrets
from ..buf import Buf
from . import chew


def mp4_decode_language(lang_bytes):
    lang_code = int.from_bytes(lang_bytes, byteorder="big") & 0x7fff

    c1 = ((lang_code >> 10) & 0x1f) + 0x60
    c2 = ((lang_code >> 5) & 0x1f) + 0x60
    c3 = (lang_code & 0x1f) + 0x60

    return chr(c1) + chr(c2) + chr(c3)


class FFMpreg(object):
    H264_NAL_UNIT_TYPES = {
        0x00: "Unspecified",
        0x01: "Coded slice of a non-IDR picture",
        0x02: "Coded slice data partition A",
        0x03: "Coded slice data partition B",
        0x04: "Coded slice data partition C",
        0x05: "Coded slice of an IDR picture",
        0x06: "Supplemental enhancement information",
        0x07: "Sequence parameter set",
        0x08: "Picture parameter set",
        0x09: "Access unit delimiter",
        0x0a: "End of sequence",
        0x0b: "End of stream",
        0x0c: "Filler data",
        0x0d: "Sequence parameter set extension",
        0x0e: "Prefix NAL unit",
        0x0f: "Subset sequence parameter set",
        0x10: "Reserved 16",
        0x11: "Reserved 17",
        0x12: "Reserved 18",
        0x13: "Coded slice of an auxiliary coded picture without partitioning",
        0x14: "Coded slice extension",
        0x15: "Reserved 21",
        0x16: "Reserved 22",
        0x17: "Reserved 23",
        0x18: "Unspecified 24",
        0x19: "Unspecified 25",
        0x1a: "Unspecified 26",
        0x1b: "Unspecified 27",
        0x1c: "Unspecified 28",
        0x1d: "Unspecified 29",
        0x1e: "Unspecified 30",
        0x1f: "Unspecified 31",
    }
    H265_NAL_UNIT_TYPES = {
        0x00: "TRAIL_N",
        0x01: "TRAIL_R",
        0x02: "TSA_N",
        0x03: "TSA_R",
        0x04: "STSA_N",
        0x05: "STSA_R",
        0x06: "RADL_N",
        0x07: "RADL_R",
        0x08: "RASL_N",
        0x09: "RASL_R",
        0x0a: "RSV_VCL_N10",
        0x0b: "RSV_VCL_R11",
        0x0c: "RSV_VCL_N12",
        0x0d: "RSV_VCL_R13",
        0x0e: "RSV_VCL_N14",
        0x0f: "RSV_VCL_R15",
        0x10: "BLA_W_LP",
        0x11: "BLA_W_RADL",
        0x12: "BLA_N_LP",
        0x13: "IDR_W_RADL",
        0x14: "IDR_N_LP",
        0x15: "CRA_NUT",
        0x16: "RSV_IRAP_VCL22",
        0x17: "RSV_IRAP_VCL23",
        0x18: "RSV_VCL24",
        0x19: "RSV_VCL25",
        0x1a: "RSV_VCL26",
        0x1b: "RSV_VCL27",
        0x1c: "RSV_VCL28",
        0x1d: "RSV_VCL29",
        0x1e: "RSV_VCL30",
        0x1f: "RSV_VCL31",
        0x20: "VPS_NUT",
        0x21: "SPS_NUT",
        0x22: "PPS_NUT",
        0x23: "AUD_NUT",
        0x24: "EOS_NUT",
        0x25: "EOB_NUT",
        0x26: "FD_NUT",
        0x27: "PREFIX_SEI_NUT",
        0x28: "SUFFIX_SEI_NUT",
        0x29: "RSV_NVCL41",
        0x2a: "RSV_NVCL42",
        0x2b: "RSV_NVCL43",
        0x2c: "RSV_NVCL44",
        0x2d: "RSV_NVCL45",
        0x2e: "RSV_NVCL46",
        0x2f: "RSV_NVCL47",
        0x30: "UNSPEC48",
        0x31: "UNSPEC49",
        0x32: "UNSPEC50",
        0x33: "UNSPEC51",
        0x34: "UNSPEC52",
        0x35: "UNSPEC53",
        0x36: "UNSPEC54",
        0x37: "UNSPEC55",
        0x38: "UNSPEC56",
        0x39: "UNSPEC57",
        0x3a: "UNSPEC58",
        0x3b: "UNSPEC59",
        0x3c: "UNSPEC60",
        0x3d: "UNSPEC61",
        0x3e: "UNSPEC62",
        0x3f: "UNSPEC63",
    }
    H266_NAL_UNIT_TYPES = {
        0x00: "TRAIL_NUT",
        0x01: "STSA_NUT",
        0x02: "RADL_NUT",
        0x03: "RASL_NUT",
        0x04: "RSV_VCL_4",
        0x05: "RSV_VCL_5",
        0x06: "RSV_VCL_6",
        0x07: "IDR_W_RADL",
        0x08: "IDR_N_LP",
        0x09: "CRA_NUT",
        0x0a: "GDR_NUT",
        0x0b: "RSV_IRAP_11",
        0x0c: "OPI_NUT",
        0x0d: "DCI_NUT",
        0x0e: "VPS_NUT",
        0x0f: "SPS_NUT",
        0x10: "PPS_NUT",
        0x11: "PREFIX_APS_NUT",
        0x12: "SUFFIX_APS_NUT",
        0x13: "PH_NUT",
        0x14: "AUD_NUT",
        0x15: "EOS_NUT",
        0x16: "EOB_NUT",
        0x17: "PREFIX_SEI_NUT",
        0x18: "SUFFIX_SEI_NUT",
        0x19: "FD_NUT",
        0x1a: "RSV_NVCL_26",
        0x1b: "RSV_NVCL_27",
        0x1c: "UNSPEC_28",
        0x1d: "UNSPEC_29",
        0x1e: "UNSPEC_30",
        0x1f: "UNSPEC_31",
    }
    AV1_OBU_TYPES = {
        0x00: "RESERVED",
        0x01: "SEQUENCE_HEADER",
        0x02: "TEMPORAL_DELIMITER",
        0x03: "FRAME_HEADER",
        0x04: "TILE_GROUP",
        0x05: "METADATA",
        0x06: "FRAME",
        0x07: "REDUNDANT_FRAME_HEADER",
        0x08: "TILE_LIST",
        0x09: "RESERVED",
        0x0a: "RESERVED",
        0x0b: "RESERVED",
        0x0c: "RESERVED",
        0x0d: "RESERVED",
        0x0e: "RESERVED",
        0x0f: "PADDING",
    }

    @staticmethod
    def read_h264_scaling_list(buf, count):
        last_scale = 8
        next_scale = 8

        lst = []
        for i in range(0, count):
            if next_scale != 0:
                delta_scale = buf.rue()

                next_scale = (last_scale + delta_scale + 256) % 256

            lst.append(last_scale if next_scale == 0 else next_scale)
            last_scale = lst[-1]

    @staticmethod
    def read_h264_hrd_parameters(buf):
        nal = {}
        nal["cpb-cnt-minus1"] = buf.rue()
        nal["bit-rate-scale"] = buf.rb(4)
        nal["cpb-size-scale"] = buf.rb(4)
        nal["list"] = [
            {"bit-rate-value-minus1": buf.rue(), "cpb-size-value-minus1": buf.rue(), "cbr-flag": buf.rb(1)}
            for i in range(0, nal["cpb-cnt-minus1"] + 1)
        ]
        nal["initial-cpb-removal-delay-length-minus1"] = buf.rb(5)
        nal["cpb-removal-delay-length-minus1"] = buf.rb(5)
        nal["dpb-output-delay-length-minus1"] = buf.rb(5)
        nal["time-offset-length"] = buf.rb(5)

        return nal

    @staticmethod
    def read_h264_nalu(buf: Buf, slim=False, state={}) -> dict:
        buf = Buf(
            buf
            .read(buf.unit)
            .replace(b"\x00\x00\x03\x00", b"\x00\x00\x00")
            .replace(b"\x00\x00\x03\x01", b"\x00\x00\x01")
            .replace(b"\x00\x00\x03\x02", b"\x00\x00\x02")
            .replace(b"\x00\x00\x03\x03", b"\x00\x00\x03")
        )

        nal = {}
        nal["length"] = buf.available()
        nal["forbidden-zero-bit"] = buf.rb(1)
        nal["ref-idc"] = buf.rb(2)
        # ISO/IEC 14496-10:2022 page 81
        nal["unit-type"] = utils.unraw(
            buf.rb(5),
            1,
            FFMpreg.H264_NAL_UNIT_TYPES,
            True,
        )

        match nal["unit-type"]:
            case "Sequence parameter set":
                # ISO/IEC 14496-10:2022 page 59
                nal["profile-idc"] = buf.ru8()
                nal["constraint-set-flags"] = [buf.rb(1) for i in range(0, 6)]
                nal["reserved"] = buf.rb(2)
                nal["level-idc"] = buf.ru8()
                nal["seq-parameter-set-id"] = buf.rue()

                if nal["profile-idc"] in (
                    44,
                    83,
                    86,
                    100,
                    110,
                    118,
                    122,
                    128,
                    134,
                    135,
                    138,
                    139,
                    144,
                    244,
                ):
                    nal["chroma-format-idc"] = buf.rue()
                    state["chroma-format-idc"] = nal["chroma-format-idc"]

                    if nal["chroma-format-idc"] == 3:
                        nal["separate-colour-plane-flag"] = buf.rb(1)

                    nal["bit-depth-luma-minus-eight"] = buf.rue()
                    nal["bit-depth-chroma-minus-eight"] = buf.rue()
                    nal["qpprime-y-zero-transform-bypass-flag"] = buf.rb(1)
                    nal["seq-scaling-matrix-present-flag"] = buf.rb(1)

                    if nal["seq-scaling-matrix-present-flag"]:
                        nal["seq-scaling-matrices"] = []
                        for i in range(0, 12 if nal["chroma-format-idc"] == 3 else 8):
                            matrix = []
                            if buf.rb(1):
                                matrix = FFMpreg.read_h264_scaling_list(buf, 16 if i < 6 else 64)

                            nal["seq-scaling-matrices"].append(matrix)

                nal["log2-max-frame-num-minus4"] = buf.rue()
                nal["pic-order-cnt-type"] = buf.rue()

                if nal["pic-order-cnt-type"] == 0:
                    nal["log2-max-pic-order-cnt-lsb-minus4"] = buf.rue()
                elif nal["pic-order-cnt-type"] == 1:
                    nal["delta-pic-order-always-zero-flag"] = buf.rb(1)
                    nal["offset-for-non-ref-pic"] = buf.rse()
                    nal["offset-for-top-to-bottom-field"] = buf.rse()
                    nal["num-ref-frames-in-pic-order-cnt-cycle"] = buf.rue()
                    nal["offsets-for-ref-frame"] = [buf.rse() for i in range(0, nal["num-ref-frames-in-pic-order-cnt-cycle"])]

                nal["max-num-ref-frames"] = buf.rue()
                nal["gaps-in-frame-num-value-allowed-flag"] = buf.rb(1)
                nal["pic-width-in-mbs-minus1"] = buf.rue()
                nal["pic-height-in-map-units-minus1"] = buf.rue()
                nal["frame-mbs-only-flag"] = buf.rb(1)

                if not nal["frame-mbs-only-flag"]:
                    nal["mb-adaptive-frame-field-flag"] = buf.rb(1)

                nal["direct-8x8-inference-flag"] = buf.rb(1)
                nal["frame-cropping-flag"] = buf.rb(1)

                if nal["frame-cropping-flag"]:
                    nal["frame-crop-left-offset"] = buf.rue()
                    nal["frame-crop-right-offset"] = buf.rue()
                    nal["frame-crop-top-offset"] = buf.rue()
                    nal["frame-crop-bottom-offset"] = buf.rue()

                nal["vui-parameters-present-flag"] = buf.rb(1)

                if nal["vui-parameters-present-flag"]:
                    nal["aspect-ratio-info-present-flag"] = buf.rb(1)

                    if nal["aspect-ratio-info-present-flag"]:
                        nal["aspect-ratio-idc"] = buf.rb(8)

                        if nal["aspect-ratio-idc"] == 0xff:
                            nal["sar-width"] = buf.rb(16)
                            nal["sar-height"] = buf.rb(16)

                    nal["overscan-info-present-flag"] = buf.rb(1)

                    if nal["overscan-info-present-flag"]:
                        nal["overscan-appropriate-flag"] = buf.rb(1)

                    nal["video-signal-type-present-flag"] = buf.rb(1)

                    if nal["video-signal-type-present-flag"]:
                        nal["video-format"] = buf.rb(3)
                        nal["video-full-range-flag"] = buf.rb(1)
                        nal["colour-description-present-flag"] = buf.rb(1)

                        if nal["colour-description-present-flag"]:
                            nal["colour-primaries"] = buf.rb(8)
                            nal["transfer-characteristics"] = buf.rb(8)
                            nal["matrix-coefficients"] = buf.rb(8)

                    nal["chroma-loc-info-present-flag"] = buf.rb(1)

                    if nal["chroma-loc-info-present-flag"]:
                        nal["chroma-sample-loc-type-top-field"] = buf.rue()
                        nal["chroma-sample-loc-type-bottom-field"] = buf.rue()

                    nal["timing-info-present-flag"] = buf.rb(1)

                    if nal["timing-info-present-flag"]:
                        nal["num-units-in-tick"] = buf.rb(32)
                        nal["time-scale"] = buf.rb(32)
                        nal["fixed-frame-rate-flag"] = buf.rb(1)

                    nal["nal-hrd-parameters-present-flag"] = buf.rb(1)

                    if nal["nal-hrd-parameters-present-flag"]:
                        nal["hrd-parameters"] = FFMpreg.read_h264_hdr_parameters(buf)

                    nal["vcl-hrd-parameters-present-flag"] = buf.rb(1)

                    if nal["vcl-hrd-parameters-present-flag"]:
                        nal["vcl-hrd-parameters"] = FFMpreg.read_h264_hdr_parameters(buf)

                    if nal["nal-hrd-parameters-present-flag"] or nal["vcl-hrd-parameters-present-flag"]:
                        nal["low-delay-hrd-flag"] = buf.rb(1)

                    nal["pic-struct-present-flag"] = buf.rb(1)
                    nal["bitstream-restriction-flag"] = buf.rb(1)

                    if nal["bitstream-restriction-flag"]:
                        nal["motion-vectors-over-pic-boundaries-flag"] = buf.rb(1)
                        nal["max-bytes-per-pic-denom"] = buf.rue()
                        nal["max-bits-per-mb-denom"] = buf.rue()
                        nal["log2-max-mv-length-horizontal"] = buf.rue()
                        nal["log2-max-mv-length-vertical"] = buf.rue()
                        nal["num-reorder-frames"] = buf.rue()
                        nal["max-dec-frame-buffering"] = buf.rue()

                buf.align()
            case "Picture parameter set":
                nal["pic-parameter-set-id"] = buf.rue()
                nal["seq-parameter-set-id"] = buf.rue()
                nal["entropy-coding-mode-flag"] = buf.rb(1)
                nal["bottom-field-pic-order-in-frame-present-flag"] = buf.rb(1)
                nal["num-slice-groups-minus-one"] = buf.rue()

                if nal["num-slice-groups-minus-one"] > 0:
                    nal["slice-group-map-type"] = buf.rue()

                    match nal["slice-group-map-type"]:
                        case 0:
                            nal["run-length-minus-one"] = [buf.rue() for i in range(0, nal["num-slice-groups-minus-one"] + 1)]
                        case 1:
                            nal["top-left-and-bottom-right"] = [
                                (buf.rue(), buf.rue()) for i in range(0, nal["num-slice-groups-minus-one"] + 1)
                            ]
                        case 3 | 4 | 5:
                            nal["slice-group-change-direction-flag-and-rate-minus-one"] = [
                                (buf.rb(1), buf.rue()) for i in range(0, nal["num-slice-groups-minus-one"] + 1)
                            ]
                        case 6:
                            nal["pic-size-in-map-units-minus-one"] = buf.rue()
                            v = math.ceil(math.log2(nal["num-slice-groups-minus-one"] + 1))
                            nal["slice-group-id"] = [buf.rb(v) for i in range(0, nal["pic-size-in-map-units-minus-one"] + 1)]

                nal["num-ref-idx-l0-default-active-minus-one"] = buf.rue()
                nal["num-ref-idx-l1-default-active-minus-one"] = buf.rue()
                nal["weighted-pred-flag"] = buf.rb(1)
                nal["weighted-bipred-idc"] = buf.rb(2)
                nal["pic-init-qp-minus26"] = buf.rse()
                nal["pic-init-qs-minus26"] = buf.rse()
                nal["chroma-qp-index-offset"] = buf.rse()
                nal["deblocking-filter-control-present-flag"] = buf.rb(1)
                nal["constrained-intra-pred-flag"] = buf.rb(1)
                nal["redundant-pic-cnt-present-flag"] = buf.rb(1)

                if buf.available() > 0 and not (buf._bits == 0 and buf.pu8() == 0x80):
                    nal["transform-8x8-mode-flag"] = buf.rb(1)
                    nal["pic-scaling-matrix-present-flag"] = buf.rb(1)

                    if nal["pic-scaling-matrix-present-flag"]:
                        nal["pic-scaling-matrices"] = []

                        for i in range(0, 6 + (6 if state.get("chroma-format-idc") == 3 else 2)):
                            matrix = []
                            if buf.rb(1):
                                matrix = []
                                if buf.rb(1):
                                    matrix = FFMpreg.read_h264_scaling_list(buf, 16 if i < 6 else 64)

                            nal["pic-scaling-matrices"].append(matrix)

                        nal["second-chroma-qp-index-offset"] = buf.rse()

                buf.align()
            case "Supplemental enhancement information":
                t = 0
                while True:
                    b = buf.ru8()
                    t += b
                    if b != 0xff:
                        break

                l = 0
                while True:
                    b = buf.ru8()
                    l += b
                    if b != 0xff:
                        break

                nal["type"] = utils.unraw(t, 1, {0x05: "user_data_unregistered"}, True)
                nal["length"] = l

                buf.pasunit(l)

                if buf.peek(16).hex() == "dc45e9bde6d948b7962cd820d923eeef":
                    nal["uuid"] = buf.ruuid()
                    nal["libx264-banner"] = buf.rs(buf.unit)
                elif buf.peek(16).hex() == "59948b2811ec45af967519d41feaa94d":
                    nal["uuid"] = buf.ruuid()
                    nal["h264-vaapi-banner"] = buf.rs(buf.unit)
                else:
                    nal["payload"] = buf.rh(buf.unit)

                buf.sapunit()
            case _:
                if not slim:
                    nal["payload"] = buf.rh(buf.unit)
                nal["unknown"] = True

        return nal

    @staticmethod
    def read_av1_obu(buf: Buf, state={}) -> dict:
        obu = {}
        obu["forbidden-bit"] = buf.rb(1)
        obu["type"] = utils.unraw(
            buf.rb(4),
            1,
            FFMpreg.AV1_OBU_TYPES,
            True,
        )
        obu["extension-flag"] = buf.rb(1)
        obu["has-size-flag"] = buf.rb(1)
        obu["reserved1"] = buf.rb(1)

        if obu["extension-flag"]:
            obu["temporal-id"] = buf.rb(3)
            obu["spatial-id"] = buf.rb(2)
            obu["reserved2"] = buf.rb(3)

        if obu["has-size-flag"]:
            length = buf.ruleb()
        else:
            length = buf.unit if buf.unit is not None else buf.available()

        obu["length"] = length

        buf.pasunit(length)

        match obu["type"]:
            case "SEQUENCE_HEADER":
                # https://aomediacodec.github.io/av1-spec/#sequence-header-obu-syntax
                obu["seq-profile"] = buf.rb(3)
                obu["still-picture"] = buf.rb(1)
                obu["reduced-still-picture-header"] = buf.rb(1)

                if obu["reduced-still-picture-header"]:
                    obu["operating-points"] = [
                        {
                            "operating-point-idc": 0,
                            "seq-level-idx": buf.rb(5),
                        }
                    ]
                else:
                    obu["timing-info-present"] = buf.rb(1)

                    if obu["timing-info-present"]:
                        obu["num-units-in-display-tick"] = buf.rb(32)
                        obu["time-scale"] = buf.rb(32)
                        obu["equal-picture-interval"] = buf.rb(1)

                        if obu["equal-picture-interval"]:
                            obu["num-ticks-per-picture-minus-one"] = buf.ruvlc()

                        obu["decoder-model-info-present-flag"] = buf.rb(1)
                        if obu["decoder-model-info-present-flag"]:
                            obu["buffer-delay-length-minus-one"] = buf.rb(5)
                            obu["num-units-in-decoding-tick"] = buf.rb(32)
                            obu["buffer-removal-time-length-minus-one"] = buf.rb(5)
                            obu["frame-presentation-time-length-minus-one"] = buf.rb(5)

                    obu["initial-display-delay-present-flag"] = buf.rb(1)
                    obu["operating-points-cnt-minus-one"] = buf.rb(5)

                    obu["operating-points"] = []
                    for i in range(0, obu["operating-points-cnt-minus-one"] + 1):
                        op = {}
                        op["operating-point-idc"] = buf.rb(12)
                        op["seq-level-idx"] = buf.rb(5)

                        if op["seq-level-idx"] > 7:
                            op["seq-tier"] = buf.rb(1)

                        if obu.get("decoder-model-info-present-flag"):
                            op["decoder-model-present-for-this-op"] = buf.rb(1)

                            if op["decoder-model-present-for-this-op"]:
                                n = obu["buffer-delay-length-minus-one"] + 1
                                op["decoder-buffer-delay"] = buf.rb(n)
                                op["encoder-buffer-delay"] = buf.rb(n)
                                op["low-delay-mode-flag"] = buf.rb(1)

                        if obu.get("initial-display-delay-present-flag"):
                            op["initial-display-delay-present-for-this-op"] = buf.rb(1)

                            if op["initial-display-delay-present-for-this-op"]:
                                op["initial-display-delay-minus-one"] = buf.rb(4)

                        obu["operating-points"].append(op)

                obu["frame-width-bits-minus-one"] = buf.rb(4)
                obu["frame-height-bits-minus-one"] = buf.rb(4)
                obu["max-frame-width-minus-one"] = buf.rb(obu["frame-width-bits-minus-one"] + 1)
                obu["max-frame-height-minus-one"] = buf.rb(obu["frame-height-bits-minus-one"] + 1)

                if not obu["reduced-still-picture-header"]:
                    obu["frame-id-numbers-present-flag"] = buf.rb(1)

                if obu.get("frame-id-numbers-present-flag"):
                    obu["delta-frame-id-length-minus-two"] = buf.rb(4)
                    obu["additional-frame-id-length-minus-one"] = buf.rb(3)

                obu["use-128x128-superblock"] = buf.rb(1)
                obu["enable-filter-intra"] = buf.rb(1)
                obu["enable-intra-edge-filter"] = buf.rb(1)

                if not obu["reduced-still-picture-header"]:
                    obu["enable-interintra-compound"] = buf.rb(1)
                    obu["enable-masked-compound"] = buf.rb(1)
                    obu["enable-warped-motion"] = buf.rb(1)
                    obu["enable-dual-filter"] = buf.rb(1)
                    obu["enable-order-hint"] = buf.rb(1)

                    if obu.get("enable-order-hint"):
                        obu["enable-jnt-comp"] = buf.rb(1)
                        obu["enable-ref-frame-mvs"] = buf.rb(1)

                    obu["seq-choose-screen-content-tools"] = buf.rb(1)

                    if obu["seq-choose-screen-content-tools"]:
                        obu["seq-force-screen-content-tools"] = 2
                    else:
                        obu["seq-force-screen-content-tools"] = buf.rb(1)

                    if obu.get("seq-force-screen-content-tools", 0) > 0:
                        obu["seq-choose-integer-mv"] = buf.rb(1)

                        if obu["seq-choose-integer-mv"]:
                            obu["seq-force-integer-mv"] = 2
                        else:
                            obu["seq-force-integer-mv"] = buf.rb(1)
                    else:
                        obu["seq-force-integer-mv"] = 2

                    if obu.get("enable-order-hint"):
                        obu["order-hint-bits-minus-1"] = buf.rb(3)
                else:
                    obu["seq-force-screen-content-tools"] = 2
                    obu["seq-force-integer-mv"] = 2

                obu["enable-superres"] = buf.rb(1)
                obu["enable-cdef"] = buf.rb(1)
                obu["enable-restoration"] = buf.rb(1)

                obu["high-bitdepth"] = buf.rb(1)

                if obu["seq-profile"] == 2 and obu["high-bitdepth"]:
                    obu["twelve-bit"] = buf.rb(1)
                    bit_depth = 12 if obu.get("twelve-bit") else 10
                else:
                    bit_depth = 10 if obu["high-bitdepth"] else 8

                if obu["seq-profile"] == 1:
                    obu["monochrome"] = 0
                else:
                    obu["monochrome"] = buf.rb(1)

                obu["color-description-present-flag"] = buf.rb(1)

                if obu["color-description-present-flag"]:
                    obu["color-primaries"] = buf.rb(8)
                    obu["transfer-characteristics"] = buf.rb(8)
                    obu["matrix-coefficients"] = buf.rb(8)

                if obu.get("monochrome"):
                    obu["color-range"] = buf.rb(1)
                    obu["subsampling-x"] = 1
                    obu["subsampling-y"] = 1
                else:
                    if (
                        obu.get("color-primaries") == 1
                        and obu.get("transfer-characteristics") == 13
                        and obu.get("matrix-coefficients") == 0
                    ):
                        obu["color-range"] = 1
                        obu["subsampling-x"] = 0
                        obu["subsampling-y"] = 0
                    else:
                        obu["color-range"] = buf.rb(1)

                        if obu["seq-profile"] == 0:
                            obu["subsampling-x"] = 1
                            obu["subsampling-y"] = 1
                        elif obu["seq-profile"] == 1:
                            obu["subsampling-x"] = 0
                            obu["subsampling-y"] = 0
                        else:
                            if bit_depth == 12:
                                obu["subsampling-x"] = buf.rb(1)
                                if obu["subsampling-x"]:
                                    obu["subsampling-y"] = buf.rb(1)
                                else:
                                    obu["subsampling-y"] = 0
                            else:
                                obu["subsampling-x"] = 1
                                obu["subsampling-y"] = 0

                        if obu.get("subsampling-x") and obu.get("subsampling-y"):
                            obu["chroma-sample-position"] = buf.rb(2)

                    obu["separate-uv-delta-q"] = buf.rb(1)

                obu["film-grain-params-present"] = buf.rb(1)

                buf.align()
            case "TEMPORAL_DELIMITER":
                pass
            case _:
                obu["unknown"] = True

        buf.sapunit()

        return obu

    @staticmethod
    def read_h265_profile_tier_level(buf, profile_present_flag, max_num_sub_layers_minus_one):
        nal = {}

        if profile_present_flag:
            nal["general-profile-space"] = buf.rb(2)
            nal["general-tier-flag"] = buf.rb(1)
            nal["general-profile-idc"] = buf.rb(5)
            nal["general-profile-compatibility-flags"] = buf.rb(32)
            nal["general-progressive-source-flag"] = buf.rb(1)
            nal["general-interlaced-source-flag"] = buf.rb(1)
            nal["general-non-packed-constraint-flag"] = buf.rb(1)
            nal["general-frame-only-constraint-flag"] = buf.rb(1)

            if (
                nal["general-profile-idc"] in (4, 5, 6, 7, 8, 9, 10, 11)
                or nal["general-profile-compatibility-flags"] & 0x0ff00000
            ):
                nal["general-max-12bit-constraint-flag"] = buf.rb(1)
                nal["general-max-10bit-constraint-flag"] = buf.rb(1)
                nal["general-max-8bit-constraint-flag"] = buf.rb(1)
                nal["general-max-422chroma-constraint-flag"] = buf.rb(1)
                nal["general-max-420chroma-constraint-flag"] = buf.rb(1)
                nal["general-max-monochrome-constraint-flag"] = buf.rb(1)
                nal["general-intra-constraint-flag"] = buf.rb(1)
                nal["general-one-picture-only-constraint-flag"] = buf.rb(1)
                nal["general-lower-bit-rate-constraint-flag"] = buf.rb(1)
                nal["general-reserved-zero-34bits"] = buf.rb(34)
            else:
                nal["general-reserved-zero-43bits"] = buf.rb(43)

            if nal["general-profile-idc"] in (1, 2, 3, 4, 5) or nal["general-profile-compatibility-flags"] & 0x7c000000:
                nal["general-inbld-flag"] = buf.rb(1)
            else:
                nal["general-reserved-zero-bit"] = buf.rb(1)

        nal["general-level-idc"] = buf.rb(8)

        nal["sub-layer-profile-level-present-flags"] = [(buf.rb(1), buf.rb(1)) for i in range(0, max_num_sub_layers_minus_one)]

        if max_num_sub_layers_minus_one > 0:
            nal["reserved-zero-2bits"] = buf.rb(2 * (8 - max_num_sub_layers_minus_one))

        nal["sub-layers"] = []

        for i in range(0, max_num_sub_layers_minus_one):
            sub = {}
            if nal["sub-layer-profile-level-present-flags"][i][0]:
                sub["sub-layer-profile-space"] = buf.rb(2)
                sub["sub-layer-tier-flag"] = buf.rb(1)
                sub["sub-layer-profile-idc"] = buf.rb(5)
                sub["sub-layer-profile-compatibility-flags"] = buf.rb(32)
                sub["sub-layer-progressive-source-flag"] = buf.rb(1)
                sub["sub-layer-interlaced-source-flag"] = buf.rb(1)
                sub["sub-layer-non-packed-constraint-flag"] = buf.rb(1)
                sub["sub-layer-frame-only-constraint-flag"] = buf.rb(1)

                if (
                    sub["sub-layer-profile-idc"] in (4, 5, 6, 7, 8, 9, 10, 11)
                    or sub["sub-layer-profile-compatibility-flags"] & 0x0ff00000
                ):
                    sub["sub-layer-max-12bit-constraint-flag"] = buf.rb(1)
                    sub["sub-layer-max-10bit-constraint-flag"] = buf.rb(1)
                    sub["sub-layer-max-8bit-constraint-flag"] = buf.rb(1)
                    sub["sub-layer-max-422chroma-constraint-flag"] = buf.rb(1)
                    sub["sub-layer-max-420chroma-constraint-flag"] = buf.rb(1)
                    sub["sub-layer-max-monochrome-constraint-flag"] = buf.rb(1)
                    sub["sub-layer-intra-constraint-flag"] = buf.rb(1)
                    sub["sub-layer-one-picture-only-constraint-flag"] = buf.rb(1)
                    sub["sub-layer-lower-bit-rate-constraint-flag"] = buf.rb(1)
                    sub["sub-layer-reserved-zero-34bits"] = buf.rb(34)
                else:
                    sub["sub-layer-reserved-zero-43bits"] = buf.rb(43)

                if sub["sub-layer-profile-idc"] in (1, 2, 3, 4, 5) or sub["sub-layer-profile-compatibility-flags"] & 0x7c000000:
                    sub["sub-layer-inbld-flag"] = buf.rb(1)
                else:
                    sub["sub-layer-reserved-zero-bit"] = buf.rb(1)

            if nal["sub-layer-profile-level-present-flags"][i][1]:
                sub["sub-layer-level-idc"] = buf.rb(8)

            nal["sub-layers"].append(sub)

        return nal

    @staticmethod
    def read_h265_hrd_parameters(buf, cprms_present_flag, max_sub_layers_minus_one):
        nal = {}

        if cprms_present_flag:
            nal["nal-hrd-parameters-present-flag"] = buf.rb(1)
            nal["vcl-hrd-parameters-present-flag"] = buf.rb(1)

            if nal["nal-hrd-parameters-present-flag"] or nal["vcl-hrd-parameters-present-flag"]:
                nal["sub-pic-hrd-params-present-flag"] = buf.rb(1)

                if nal["sub-pic-hrd-params-present-flag"]:
                    nal["tick-divisor-minus2"] = buf.rb(8)
                    nal["du-cpb-removal-delay-increment-length-minus1"] = buf.rb(5)
                    nal["sub-pic-cpb-params-in-pic-timing-sei-flag"] = buf.rb(1)
                    nal["dpb-output-delay-du-length-minus1"] = buf.rb(5)

                nal["bit-rate-scale"] = buf.rb(4)
                nal["cpb-size-scale"] = buf.rb(4)

                if nal.get("sub-pic-hrd-params-present-flag"):
                    nal["cpb-size-du-scale"] = buf.rb(4)

                nal["initial-cpb-removal-delay-length-minus1"] = buf.rb(5)
                nal["au-cpb-removal-delay-length-minus1"] = buf.rb(5)
                nal["dpb-output-delay-length-minus1"] = buf.rb(5)

        for i in range(max_sub_layers_minus_one + 1):
            if "fixed-pic-rate-general-flag" not in nal:
                nal["fixed-pic-rate-general-flag"] = {}
            nal["fixed-pic-rate-general-flag"][i] = buf.rb(1)

            if not nal["fixed-pic-rate-general-flag"][i]:
                if "fixed-pic-rate-within-cvs-flag" not in nal:
                    nal["fixed-pic-rate-within-cvs-flag"] = {}
                nal["fixed-pic-rate-within-cvs-flag"][i] = buf.rb(1)

            if nal.get("fixed-pic-rate-within-cvs-flag", {}).get(i, nal["fixed-pic-rate-general-flag"][i]):
                if "elemental-duration-in-tc-minus1" not in nal:
                    nal["elemental-duration-in-tc-minus1"] = {}
                nal["elemental-duration-in-tc-minus1"][i] = buf.rue()
            else:
                if "low-delay-hrd-flag" not in nal:
                    nal["low-delay-hrd-flag"] = {}
                nal["low-delay-hrd-flag"][i] = buf.rb(1)

            if not nal.get("low-delay-hrd-flag", {}).get(i, 0):
                if "cpb-cnt-minus1" not in nal:
                    nal["cpb-cnt-minus1"] = {}
                nal["cpb-cnt-minus1"][i] = buf.rue()

            if nal.get("nal-hrd-parameters-present-flag"):
                for j in range(nal.get("cpb-cnt-minus1", {}).get(i, 0) + 1):
                    if "bit-rate-value-minus1" not in nal:
                        nal["bit-rate-value-minus1"] = {}
                    nal["bit-rate-value-minus1"][j] = buf.rue()

                    if "cpb-size-value-minus1" not in nal:
                        nal["cpb-size-value-minus1"] = {}
                    nal["cpb-size-value-minus1"][j] = buf.rue()

                    if nal.get("sub-pic-hrd-params-present-flag"):
                        if "cpb-size-du-value-minus1" not in nal:
                            nal["cpb-size-du-value-minus1"] = {}
                        nal["cpb-size-du-value-minus1"][j] = buf.rue()

                        if "bit-rate-du-value-minus1" not in nal:
                            nal["bit-rate-du-value-minus1"] = {}
                        nal["bit-rate-du-value-minus1"][j] = buf.rue()

                    if "cbr-flag" not in nal:
                        nal["cbr-flag"] = {}
                    nal["cbr-flag"][j] = buf.rb(1)

            if nal.get("vcl-hrd-parameters-present-flag"):
                for j in range(nal.get("cpb-cnt-minus1", {}).get(i, 0) + 1):
                    if "bit-rate-value-minus1" not in nal:
                        nal["bit-rate-value-minus1"] = {}
                    nal["bit-rate-value-minus1"][j] = buf.rue()

                    if "cpb-size-value-minus1" not in nal:
                        nal["cpb-size-value-minus1"] = {}
                    nal["cpb-size-value-minus1"][j] = buf.rue()

                    if nal.get("sub-pic-hrd-params-present-flag"):
                        if "cpb-size-du-value-minus1" not in nal:
                            nal["cpb-size-du-value-minus1"] = {}
                        nal["cpb-size-du-value-minus1"][j] = buf.rue()

                        if "bit-rate-du-value-minus1" not in nal:
                            nal["bit-rate-du-value-minus1"] = {}
                        nal["bit-rate-du-value-minus1"][j] = buf.rue()

                    if "cbr-flag" not in nal:
                        nal["cbr-flag"] = {}
                    nal["cbr-flag"][j] = buf.rb(1)

        return nal

    @staticmethod
    def read_h265_nalu(buf: Buf, state={}) -> dict:
        buf = Buf(
            buf
            .read(buf.unit)
            .replace(b"\x00\x00\x03\x00", b"\x00\x00\x00")
            .replace(b"\x00\x00\x03\x01", b"\x00\x00\x01")
            .replace(b"\x00\x00\x03\x02", b"\x00\x00\x02")
            .replace(b"\x00\x00\x03\x03", b"\x00\x00\x03")
        )

        nal = {}
        nal["length"] = buf.available()
        nal["forbidden-zero-bit"] = buf.rb(1)
        nal["unit-type"] = utils.unraw(
            buf.rb(6),
            1,
            FFMpreg.H265_NAL_UNIT_TYPES,
            True,
        )
        nal["nuh-layer-id"] = buf.rb(6)
        nal["nuh-temporal-id-plus-one"] = buf.rb(3)

        match nal["unit-type"]:
            case "PREFIX_SEI_NUT" | "SUFFIX_SEI_NUT":
                nal["seis"] = []

                while buf.available() > 1:
                    typ = 0
                    while True:
                        part = buf.ru8()
                        typ += part

                        if part != 0xff:
                            break

                    length = 0
                    while True:
                        part = buf.ru8()
                        length += part

                        if part != 0xff:
                            break

                    sei = {}
                    sei["type"] = utils.unraw(
                        typ,
                        1,
                        {
                            0x00: "buffering_period",
                            0x04: "user_data_registered_itu_t_t35",
                            0x05: "user_data_unregistered",
                            0x89: "mastering_display_colour_volume",
                            0x90: "content_light_level_info",
                        },
                        True,
                    )
                    sei["length"] = length

                    buf.pasunit(length)

                    match sei["type"]:
                        case "user_data_unregistered":
                            sei["uuid"] = buf.ruuid()

                            match sei["uuid"]:
                                case "2ca2de09-b517-47db-bb55-a4fe7fc2fc4e":
                                    sei["string"] = buf.rs(buf.unit)
                                case _:
                                    sei["payload"] = buf.rh(buf.unit)
                        case "mastering_display_colour_volume":
                            sei["display-primaries"] = [(buf.ru16(), buf.ru16()) for i in range(0, 3)]
                            sei["white-point"] = (buf.ru16(), buf.ru16())
                            sei["max-display-mastering-luminance"] = buf.ru32()
                            sei["min-display-mastering-luminance"] = buf.ru32()
                        case "content_light_level_info":
                            sei["max-content-light-level"] = buf.ru16()
                            sei["max-pic-average-light-level"] = buf.ru16()
                        case _:
                            sei["payload"] = buf.rh(min(buf.unit if buf.unit is not None else 2**64, buf.available()))
                            sei["unknown"] = True

                    buf.sapunit()

                    nal["seis"].append(sei)
            case "AUD_NUT":
                nal["pic-type"] = utils.unraw(buf.rb(3), 1, {0x00: "I", 0x01: "P/I", 0x02: "B/P/I"}, True)
                buf.align()
            case "VPS_NUT":
                nal["video-parameter-set-id"] = buf.rb(4)
                nal["base-layer-internal-flag"] = buf.rb(1)
                nal["base-layer-available-flag"] = buf.rb(1)
                nal["max-layers-minus1"] = buf.rb(6)
                nal["max-sub-layers-minus1"] = buf.rb(3)
                nal["temporal-id-nesting-flag"] = buf.rb(1)
                nal["reserved"] = buf.ru16()
                nal["profile-tier-level"] = FFMpreg.read_h265_profile_tier_level(buf, 1, nal["max-sub-layers-minus1"])
                nal["sub-layer-ordering-info-present-flag"] = buf.rb(1)
                nal["sub-layer-ordering-infos"] = [
                    {
                        "max-dec-pic-buffering-minus1": buf.rue(),
                        "max-num-reorder-pics": buf.rue(),
                        "max-latency-increase-plus1": buf.rue(),
                    }
                    for i in range(0, nal["max-sub-layers-minus1"] + 1 if nal["sub-layer-ordering-info-present-flag"] else 1)
                ]
                nal["max-layer-id"] = buf.rb(6)
                nal["num-layer-sets-minus1"] = buf.rue()
                nal["layer-id-included-flags"] = [
                    buf.rb(nal["max-layer-id"] + 1) for i in range(0, nal["num-layer-sets-minus1"])
                ]
                nal["timing-info-present-flag"] = buf.rb(1)

                if nal["timing-info-present-flag"]:
                    nal["num-units-in-tick"] = buf.rb(32)
                    nal["time-scale"] = buf.rb(32)
                    nal["poc-proportional-to-timing-flag"] = buf.rb(1)

                    if nal["poc-proportional-to-timing-flag"]:
                        nal["num-ticks-poc-diff-one-minus1"] = buf.rue()

                    nal["num-hrd-parameters"] = buf.rue()

                    nal["hrd-parameters"] = []
                    for i in range(0, nal["num-hrd-parameters"]):
                        hrd = {}
                        hrd["hrd-layer-set-idx"] = buf.rue()

                        if i > 0:
                            hrd["cprms-present-flag"] = buf.rb(1)

                        hrd |= FFMpreg.read_h265_hrd_parameters(
                            buf, hrd.get("cprms-present-flag", 1), nal["max-sub-layers-minus1"]
                        )

                nal["extension-flag"] = buf.rb(1)
                if nal["extension-flag"]:
                    i = buf.rb(buf.available() * 8 - buf._bits)

                    while i and not i & 1:
                        i >>= 1

                    nal["extension-data-flag"] = i >> 1

                buf.align()
            case _:
                nal["unknown"] = True

        return nal

    @staticmethod
    def read_h266_nalu(buf: Buf, state={}) -> dict:
        buf = Buf(
            buf
            .read(buf.unit)
            .replace(b"\x00\x00\x03\x00", b"\x00\x00\x00")
            .replace(b"\x00\x00\x03\x01", b"\x00\x00\x01")
            .replace(b"\x00\x00\x03\x02", b"\x00\x00\x02")
            .replace(b"\x00\x00\x03\x03", b"\x00\x00\x03")
        )

        nal = {}
        nal["length"] = buf.available()
        nal["forbidden-zero-bit"] = buf.rb(1)
        nal["nuh-reserved-zero-bit"] = buf.rb(1)
        nal["nuh-layer-id"] = buf.rb(6)
        nal["unit-type"] = utils.unraw(buf.rb(5), 1, FFMpreg.H266_NAL_UNIT_TYPES, True)
        nal["nuh-temporal-id-plus-one"] = buf.rb(3)

        match nal["unit-type"]:
            case "AUD_NUT":
                nal["irap-or-gdr-flag"] = buf.rb(1)
                nal["pic-type"] = utils.unraw(buf.rb(3), 1, {0x00: "I", 0x01: "P/I", 0x02: "B/P/I"}, True)

        return nal


@module.register
class IsoModule(module.RuminantModule):
    desc = "ISO Base Media files.\nThis includes may file formats like MP4, HEIC/HEIF, AVIF or JPEG2000."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(8)[4:] in (b"ftyp", b"styp", b"jP  ", b"jumb")

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}

        self.mode = None

        meta["type"] = "iso"
        meta["atoms"] = []
        while self.buf.available() >= 8:
            meta["atoms"].append(self.read_atom())

        try:
            with self.buf:
                meta["streams"] = self.parse_mdat(meta["atoms"])
        except Exception as e:
            if module.debug:
                raise e

            pass

        return meta

    def read_version(self, atom):
        version = self.buf.ru8()
        atom["data"]["version"] = version
        atom["data"]["flags"] = self.buf.ru24()
        return version

    def read_more(self, atom):
        atom["data"]["atoms"] = []

        bak = self.buf.backup()

        while self.buf.unit >= 8:
            atom["data"]["atoms"].append(self.read_atom())

        self.buf.restore(bak)
        self.buf.skipunit()

    def read_atom(self, root_context=None):
        offset = self.buf.tell()

        length = self.buf.ru32()
        if length == 0:
            pos = self.buf.tell()
            self.buf.seek(0, 2)
            length = self.buf.tell()
            self.buf.seek(pos)
        typ = self.buf.rs(4, "latin-1")

        if length == 1:
            length = self.buf.ru64() - 8

        atom = {"type": typ, "offset": offset, "length": length, "data": {}}

        length -= 8
        self.buf.pushunit()
        self.buf.setunit(length)

        if typ == "":
            pass
        elif typ in (
            "moov",
            "trak",
            "mdia",
            "minf",
            "dinf",
            "stbl",
            "udta",
            "mvex",
            "moof",
            "traf",
            "gsst",
            "gstd",
            "sinf",
            "schi",
            "cprt",
            "trkn",
            "aART",
            "iprp",
            "ipco",
            "tapt",
            "tref",
            "gmhd",
            "jp2h",
            "asoc",
            "jumb",
            "wave",
            "book",
            "sv3d",
            "proj",
        ) or (typ[0] == "©" and self.buf.peek(8)[4:8] == b"data"):
            self.read_more(atom)
        elif typ in ("ftyp", "styp"):
            atom["data"]["major-brand"] = self.buf.rs(4, "utf-8")
            atom["data"]["minor-version"] = self.buf.ru32()
            atom["data"]["compatible-brands"] = []

            while self.buf.unit > 0:
                atom["data"]["compatible-brands"].append(self.buf.rs(4, "utf-8"))

            if atom["data"]["major-brand"] == "jp2 ":
                self.mode = "jp2"
        elif typ == "uuid":
            atom["data"]["uuid"] = str(uuid.UUID(bytes=self.buf.read(16)))
            atom["data"]["user-data"] = self.buf.rs(self.buf.unit)
            try:
                atom["data"]["user-data"] = utils.xml_to_dict(atom["data"]["user-data"])
            except Exception:
                pass
        elif typ == "mvhd":
            version = self.read_version(atom)

            if version == 0:
                creation_time = self.buf.ru32()
                modification_time = self.buf.ru32()
                timescale = self.buf.ru32()
                duration = self.buf.ru32()
            elif version == 1:
                creation_time = self.buf.ru64()
                modification_time = self.buf.ru64()
                timescale = self.buf.ru32()
                duration = self.buf.ru64()

            if version in (0, 1):
                atom["data"]["creation-time"] = utils.mp4_time_to_iso(creation_time)
                atom["data"]["modification-time"] = utils.mp4_time_to_iso(modification_time)
                atom["data"]["timescale"] = timescale
                atom["data"]["duration"] = duration

                atom["data"]["rate"] = self.buf.rfp32()
                atom["data"]["volume"] = self.buf.rfp16()
                atom["data"]["reserved"] = self.buf.rh(10)
                atom["data"]["matrix"] = self.buf.rh(36)
                atom["data"]["pre-defined"] = self.buf.rh(24)
                atom["data"]["next-track-id"] = self.buf.ru32()
        elif typ == "tkhd":
            version = self.buf.ru8()
            atom["data"]["version"] = version
            flags = self.buf.ru24()
            atom["data"]["flags"] = {
                "raw": flags,
                "enabled": bool(flags & 1),
                "movie": bool(flags & 2),
                "preview": bool(flags & 4),
            }

            if version == 0:
                creation_time = self.buf.ru32()
                modification_time = self.buf.ru32()
                track_ID = self.buf.ru32()
                reserved1 = self.buf.rh(4)
                duration = self.buf.ru32()

            if version == 1:
                creation_time = self.buf.ru64()
                modification_time = self.buf.ru64()
                track_ID = self.buf.ru32()
                reserved1 = self.buf.rh(4)
                duration = self.buf.ru64()

            if version in (0, 1):
                atom["data"]["creation-time"] = utils.mp4_time_to_iso(creation_time)
                atom["data"]["modification-time"] = utils.mp4_time_to_iso(modification_time)
                atom["data"]["track-id"] = track_ID
                atom["data"]["reserved1"] = reserved1
                atom["data"]["duration"] = duration

                atom["data"]["reserved2"] = self.buf.rh(8)
                atom["data"]["layer"] = self.buf.ru16()
                atom["data"]["alternate-group"] = self.buf.ru16()
                atom["data"]["volume"] = self.buf.rfp16()
                atom["data"]["reserved3"] = self.buf.rh(2)
                atom["data"]["matrix"] = self.buf.rh(36)
                atom["data"]["width"] = self.buf.rfp32()
                atom["data"]["height"] = self.buf.rfp32()
        elif typ == "edts":
            atom["data"] = self.read_atom()
        elif typ == "elst":
            version = self.read_version(atom)
            entry_count = self.buf.ru32()
            atom["data"]["entry-count"] = entry_count

            atom["data"]["entries"] = []
            for i in range(0, entry_count & 0x00ffffff):
                entry = {}
                if version == 0:
                    entry["segment-duration"] = self.buf.ru32()
                    entry["media-time"] = self.buf.ru32()
                elif version == 1:
                    entry["segment-duration"] = self.buf.ru64()
                    entry["media-time"] = self.buf.ru64()

                entry["media-rate-integer"] = self.buf.ru16()
                entry["media-rate-fraction"] = self.buf.ru16()
                atom["data"]["entries"].append(entry)
        elif typ == "mdhd":
            version = self.read_version(atom)

            if version == 0:
                creation_time = self.buf.ru32()
                modification_time = self.buf.ru32()
                timescale = self.buf.ru32()
                duration = self.buf.ru32()
            elif version == 1:
                creation_time = self.buf.ru64()
                modification_time = self.buf.ru64()
                timescale = self.buf.ru32()
                duration = self.buf.ru64()

            if version in (0, 1):
                atom["data"]["creation-time"] = utils.mp4_time_to_iso(creation_time)
                atom["data"]["modification-time"] = utils.mp4_time_to_iso(modification_time)
                atom["data"]["timescale"] = timescale
                atom["data"]["duration"] = duration

                atom["data"]["language"] = mp4_decode_language(self.buf.read(2))
                atom["data"]["pre-defined"] = self.buf.rh(2)
        elif typ == "hdlr":
            self.read_version(atom)
            atom["data"]["pre-defined"] = self.buf.rh(4)
            atom["data"]["handler-type"] = self.buf.rs(4)
            atom["data"]["reserved"] = self.buf.rh(12)
            atom["data"]["name"] = self.buf.readunit().decode("utf-8").rstrip("\x00")
        elif typ == "vmhd":
            self.read_version(atom)
            atom["data"]["graphicsmode"] = self.buf.ru16()
            atom["data"]["opcolor"] = [self.buf.ru16() for _ in range(0, 3)]
        elif typ in ("dref", "stsd"):
            self.read_version(atom)
            entry_count = self.buf.ru32()

            atom["data"]["atoms"] = []
            for i in range(0, entry_count):
                atom["data"]["atoms"].append(self.read_atom())
        elif typ == "url ":
            version = self.buf.ru8()
            atom["data"]["version"] = version
            flags = self.buf.ru24()
            atom["data"]["flags"] = {"raw": flags, "local": bool(flags & 1)}

            atom["data"]["location"] = self.buf.readunit()[:-1].decode("utf-8")
        elif typ == "avcC":
            atom["data"]["configuration-version"] = self.buf.ru8()
            atom["data"]["avc-profile-indication"] = self.buf.ru8()
            atom["data"]["profile-compatibility"] = self.buf.ru8()
            atom["data"]["avc-level-indication"] = self.buf.ru8()
            atom["data"]["reserved1"] = self.buf.rb(6)
            atom["data"]["length-size-minus-one"] = self.buf.rb(2)

            atom["data"]["reserved2"] = self.buf.rb(3)
            atom["data"]["sequence-parameter-set-count"] = self.buf.rb(5)
            atom["data"]["sequence-parameter-sets"] = []
            for i in range(0, atom["data"]["sequence-parameter-set-count"]):
                self.buf.pasunit(self.buf.ru16())
                atom["data"]["sequence-parameter-sets"].append(FFMpreg.read_h264_nalu(self.buf))
                self.buf.sapunit()

            atom["data"]["picture-parameter-set-count"] = self.buf.ru8()
            atom["data"]["picture-parameter-sets"] = []
            for i in range(0, atom["data"]["picture-parameter-set-count"]):
                self.buf.pasunit(self.buf.ru16())
                atom["data"]["picture-parameter-sets"].append(FFMpreg.read_h264_nalu(self.buf))
                self.buf.sapunit()

            if atom["data"]["avc-profile-indication"] not in (66, 77, 88):
                atom["data"]["reserved3"] = self.buf.rb(6)
                atom["data"]["chroma-format"] = self.buf.rb(2)
                atom["data"]["reserved4"] = self.buf.rb(5)
                atom["data"]["bit-depth-luma-minus-eight"] = self.buf.rb(3)
                atom["data"]["reserved5"] = self.buf.rb(5)
                atom["data"]["bit-depth-chroma-minus-eight"] = self.buf.rb(3)

                if self.buf.unit > 0:
                    atom["data"]["picture-parameter-set-ext-count"] = self.buf.ru8()
                    atom["data"]["picture-parameter-set-exts"] = []
                    for i in range(0, atom["data"]["picture-parameter-set-ext-count"]):
                        self.buf.pasunit(self.buf.ru16())
                        atom["data"]["picture-parameter-set-exts"].append(FFMpreg.read_h264_nalu(self.buf))
                        self.buf.sapunit()
        elif typ == "colr":
            if self.mode == "jp2":
                atom["data"]["method"] = self.buf.ru8()
                atom["data"]["precedence"] = self.buf.ru8()
                atom["data"]["approx"] = self.buf.ru8()
                atom["data"]["colour"] = self.buf.rh(self.buf.unit)
            else:
                atom["data"]["color-type"] = self.buf.rs(4)

                match atom["data"]["color-type"]:
                    case "nclc":
                        atom["data"]["color-primaries"] = self.buf.ru16()
                        atom["data"]["transfer-characteristics"] = self.buf.ru16()
                        atom["data"]["matrix-coefficients"] = self.buf.ru16()
                    case "rICC" | "prof":
                        atom["data"]["icc-profile-data"] = chew(b"ICC_PROFILE\x00\x00\x00" + self.buf.readunit())
                    case "nclx":
                        atom["data"]["color-primaries"] = self.buf.ru16()
                        atom["data"]["transfer-characteristics"] = self.buf.ru16()
                        atom["data"]["matrix-coefficients"] = self.buf.ru16()
                        atom["data"]["flags"] = utils.unpack_flags(self.buf.ru8(), ((7, "full-range"),))
        elif typ == "pasp":
            atom["data"]["h-spacing"] = self.buf.ru32()
            atom["data"]["v-spacing"] = self.buf.ru32()
        elif typ == "btrt":
            atom["data"]["buffer-size"] = self.buf.ru32()
            atom["data"]["max-bitrate"] = self.buf.ru32()
            atom["data"]["avg-bitrate"] = self.buf.ru32()
        elif typ in ("stts", "stss", "ctts", "stsc", "stco", "co64"):
            self.read_version(atom)
            atom["data"]["entry-count"] = self.buf.ru32()
        elif typ == "stsz":
            self.read_version(atom)
            atom["data"]["sample-size"] = self.buf.ru32()
            atom["data"]["sample-count"] = self.buf.ru32()
        elif typ == "sgpd":
            atom["data"]["version"] = self.buf.ru8()
            atom["data"]["flags"] = utils.unpack_flags(self.buf.ru24(), ((0, "variable-length"),))

            atom["data"]["grouping-type"] = self.buf.rs(4)

            default_length = 0
            if atom["data"]["version"] == 1 and "variable-length" not in atom["data"]["flags"]["names"]:
                default_length = self.buf.ru32()

            entry_count = self.buf.ru32()
            atom["data"]["entry-count"] = entry_count

            atom["data"]["entries"] = []
            for i in range(0, entry_count):
                length = default_length
                if length == 0:
                    length = self.buf.ru32()

                atom["data"]["entries"].append(self.buf.rh(length))
        elif typ == "sbgp":
            self.read_version(atom)
            atom["data"]["grouping-type"] = self.buf.rs(4)

            entry_count = self.buf.ru32()
            atom["data"]["entry-count"] = entry_count

            atom["data"]["entries"] = []
            for i in range(0, entry_count):
                atom["data"]["entries"].append({
                    "sample-count": self.buf.ru32(),
                    "group-description-index": self.buf.ru32(),
                })
        elif typ == "smhd":
            self.read_version(atom)
            atom["data"]["balance"] = self.buf.rfp16()
            atom["data"]["reserved"] = self.buf.ru16()
        elif typ == "esds":
            self.read_version(atom)
            atom["data"]["descriptor"] = self.read_esds()
        elif typ == "data":
            atom["data"]["type"] = self.buf.ru32()
            self.buf.skip(4)

            match atom["data"]["type"]:
                case 0x00000001:
                    atom["data"]["payload"] = self.buf.rs(self.buf.unit)
                case 0x00000002:
                    atom["data"]["payload"] = self.buf.rs(self.buf.unit, "utf-16")
                case _:
                    with self.buf.subunit():
                        atom["data"]["payload"] = chew(self.buf)
        elif typ in ("free", "skip"):
            atom["data"]["non-zero"] = sum(self.buf.peek(self.buf.unit)) > 0
            if atom["data"]["non-zero"]:
                if self.buf.peek(3) == b"Iso":
                    atom["data"]["gpac-string"] = self.buf.readunit().decode("utf-8").rstrip("\x00")
                else:
                    with self.buf.subunit():
                        atom["data"]["content"] = chew(self.buf)
        elif typ == "sdtp":
            self.read_version(atom)
            atom["data"]["sample-dep-type-count"] = len(self.buf.readunit())
        elif typ == "vpcC":
            atom["data"]["profile"] = self.buf.ru8()
            atom["data"]["level"] = self.buf.ru8()
            atom["data"]["bit-depth"] = self.buf.ru8()
            atom["data"]["chroma-subsampling"] = self.buf.ru8()
            atom["data"]["video-full-range-flag"] = self.buf.ru8()
            atom["data"]["reserved"] = self.buf.rh(3)
        elif typ == "trex":
            self.read_version(atom)
            atom["data"]["track-id"] = self.buf.ru32()
            atom["data"]["default-sample-description-index"] = self.buf.ru32()
            atom["data"]["default-sample-duration"] = self.buf.ru32()
            atom["data"]["default-sample-size"] = self.buf.ru32()
            atom["data"]["default-sample-flags"] = self.buf.ru32()
        elif typ == "sidx":
            version = self.read_version(atom)
            atom["data"]["reference-id"] = self.buf.ru32()
            atom["data"]["earliest-presentation-time"] = int.from_bytes(self.buf.read(4 if version == 0 else 8), "big")
            atom["data"]["first-offset"] = int.from_bytes(self.buf.read(4 if version == 0 else 8), "big")
            atom["data"]["reserved"] = self.buf.rh(2)
            atom["data"]["reference-count"] = self.buf.ru16()
        elif typ == "mfhd":
            self.read_version(atom)
            atom["data"]["sequence-number"] = self.buf.ru32()
        elif typ == "tfhd":
            atom["data"]["version"] = self.buf.ru8()
            atom["data"]["flags"] = utils.unpack_flags(
                self.buf.ru24(),
                (
                    (0, "base-data-offset-present"),
                    (1, "sample-description-index-present"),
                    (3, "default-sample-duration-present"),
                    (4, "default-sample-size-present"),
                    (5, "default-sample-flags-present"),
                    (16, "no-samples"),
                    (17, "base-is-moof"),
                ),
            )
            atom["data"]["track-id"] = self.buf.ru32()

            if "base-data-offset-present" in atom["data"]["flags"]["names"]:
                atom["data"]["base-data-offset"] = self.buf.ru64()
            if "sample-description-index-present" in atom["data"]["flags"]["names"]:
                atom["data"]["sample-description-index"] = self.buf.ru32()
            if "default-sample-duration-present" in atom["data"]["flags"]["names"]:
                atom["data"]["default-sample-duration"] = self.buf.ru32()
            if "default-sample-size-present" in atom["data"]["flags"]["names"]:
                atom["data"]["default-sample-size"] = self.buf.ru32()
            if "default-sample-flags-present" in atom["data"]["flags"]["names"]:
                atom["data"]["default-sample-flags"] = self.buf.ru32()
        elif typ == "tfdt":
            version = self.read_version(atom)
            atom["data"]["base-media-decode-time"] = int.from_bytes(self.buf.read(4 if version == 0 else 8), "big")
        elif typ == "trun":
            atom["data"]["version"] = self.buf.ru8()
            atom["data"]["flags"] = utils.unpack_flags(
                self.buf.ru24(),
                (
                    (0, "data-offset-present"),
                    (2, "first-sample-flags-present"),
                    (8, "sample-duration-present"),
                    (9, "sample-size-present"),
                    (10, "sample-flags-present"),
                    (11, "sample-composition-time-offsets-present"),
                ),
            )
            atom["data"]["sample-count"] = self.buf.ru32()
        elif typ == "desc":
            atom["data"]["descriptor"] = self.buf.readunit().hex()
        elif typ == "loci":
            self.read_version(atom)
            atom["data"]["language-code"] = self.buf.ru16()
            atom["data"]["reserved"] = self.buf.rh(2)
            atom["data"]["longitude"] = self.buf.rfp32()
            atom["data"]["latitude"] = self.buf.rfp32()
            atom["data"]["altitude"] = self.buf.rfp32()
            atom["data"]["planet"] = self.buf.readunit().split(b"\x00")[0].decode("utf-8")
        elif typ == "hvcC":
            version = self.buf.ru8()
            atom["data"]["version"] = version

            atom["data"]["general-profile-space"] = self.buf.rb(2)
            atom["data"]["general-tier-flag"] = self.buf.rb(1)
            atom["data"]["general-profile-idc"] = self.buf.rb(5)

            atom["data"]["profile-compatibility-flags"] = self.buf.ru32()
            atom["data"]["constraint-indicator-flags"] = self.buf.ru48()
            atom["data"]["level-idc"] = self.buf.ru8()
            atom["data"]["min-spatial-segmentation-idc"] = self.buf.ru16()
            atom["data"]["parallelism-type"] = self.buf.ru8()
            atom["data"]["chroma-format"] = self.buf.ru8()
            atom["data"]["bit-depth-luma-minus8"] = self.buf.ru8()
            atom["data"]["bit-depth-chroma-minus8"] = self.buf.ru8()
            atom["data"]["avg-frame-rate"] = self.buf.rfp16()

            atom["data"]["constant-frame-rate"] = self.buf.rb(2)
            atom["data"]["num-temporal-layers"] = self.buf.rb(3)
            atom["data"]["temporal-id-nested"] = self.buf.rb(1)
            atom["data"]["length-size-minus-one"] = self.buf.rb(2)

            atom["data"]["array-count"] = self.buf.ru8()

            atom["data"]["arrays"] = []
            for i in range(0, atom["data"]["array-count"]):
                array = {}
                array["array-completeness"] = self.buf.rb(1)
                array["reserved"] = self.buf.rb(1)
                array["nal-unit-type"] = utils.unraw(
                    self.buf.rb(6),
                    1,
                    FFMpreg.H265_NAL_UNIT_TYPES,
                    True,
                )
                array["nalu-count"] = self.buf.ru16()
                array["nalus"] = []
                for j in range(0, array["nalu-count"]):
                    entry = {}
                    entry["nalu-length"] = self.buf.ru16()

                    self.buf.pasunit(entry["nalu-length"])

                    entry["nalu"] = FFMpreg.read_h265_nalu(self.buf)

                    self.buf.sapunit()

                    array["nalus"].append(entry)

                atom["data"]["arrays"].append(array)
        elif typ == "keys":
            self.read_version(atom)
            entry_count = self.buf.ru32()
            atom["data"]["entry-count"] = entry_count

            atom["data"]["entries"] = []
            for i in range(0, entry_count):
                length = self.buf.ru32()
                ns = self.buf.rs(4)
                value = self.buf.rs(length - 8)
                atom["data"]["entries"].append({"namespace": ns, "value": value})
        elif typ == "name":
            if self.buf.unit >= 4:
                self.read_version(atom)
            atom["data"]["name"] = self.buf.readunit().decode("utf-8")
        elif typ == "titl":
            self.read_version(atom)
            atom["data"]["reserved1"] = self.buf.rh(2)
            atom["data"]["title"] = self.buf.readunit()[:-1].decode("latin-1")
        elif typ == "cslg":
            atom["data"]["composition-to-dts-shift"] = self.buf.ru32()
            atom["data"]["least-decode-to-display-delta"] = self.buf.ru32()
            atom["data"]["greatest-decode-to-display-delta"] = self.buf.ru32()
            atom["data"]["composition-start-time"] = self.buf.ru32()
            atom["data"]["composition-end-time"] = self.buf.ru32()
        elif typ == "senc":
            atom["data"]["version"] = self.buf.ru8()
            atom["data"]["flags"] = utils.unpack_flags(self.buf.ru24(), ((1, "use-subsample-encryption"),))
            atom["data"]["sample-count"] = self.buf.ru32()
        elif typ == "frma":
            atom["data"]["original-media-type"] = self.buf.rs(4)
        elif typ == "schm":
            atom["data"]["version"] = self.buf.ru8()
            atom["data"]["flags"] = utils.unpack_flags(self.buf.ru24(), ((0, "has-uri"),))
            atom["data"]["type"] = self.buf.rs(4)
            atom["data"]["version"] = f"{self.buf.ru16()}.{self.buf.ru16()}"
            if "has-uri" in atom["data"]["flags"]["names"]:
                atom["data"]["uri"] = self.buf.readunit().decode("utf-8")
        elif typ == "tenc":
            version = self.read_version(atom)

            atom["data"]["reserved"] = self.buf.rh(1 if version != 0 else 2)

            if version >= 1:
                atom["data"]["encrypted-blocks-per-pattern"] = self.buf.ru32()
                atom["data"]["clear-blocks-per-pattern"] = self.buf.ru32()

            atom["data"]["is-encrypted"] = self.buf.ru8()
            atom["data"]["iv-size"] = self.buf.ru8()
            atom["data"]["key-id"] = self.buf.rh(16)

            if atom["data"]["is-encrypted"] == 1 and atom["data"]["iv-size"] == 0:
                constant_iv_size = self.buf.ru8()
                atom["data"]["constant-iv-size"] = constant_iv_size
                atom["data"]["constant-iv"] = self.buf.rh(constant_iv_size)
        elif typ == "mehd":
            version = self.read_version(atom)
            atom["data"]["fragment-duration"] = self.buf.ru32() if version == 0 else self.buf.ru64()
        elif typ == "pssh":
            version = self.read_version(atom)

            system_id = self.buf.ruuid()
            atom["data"]["system-id"] = system_id
            atom["data"]["system-name"] = {
                "29701fe4-3cc7-4a34-8c5b-ae90c7439a47": "Netflix FairPlay",
                "9a04f079-9840-4286-ab92-e65be0885f95": "PlayReady",
                "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed": "Widevine",
                "6dd8b3c3-45f4-4a68-bf3a-64168d01a4a6": "ABV DRM (MoDRM)",
                "f239e769-efa3-4850-9c16-a903c6932efb": "Adobe Primetime DRM version 4",
                "616c7469-6361-7374-2d50-726f74656374": "Alticast",
                "94ce86fb-07ff-4f43-adb8-93d2fa968ca2": "FairPlay",
                "279fe473-512c-48fe-ade8-d176fee6b40f": "Arris Titanium",
                "3d5e6d35-9b9a-41e8-b843-dd3c6e72c42c": "ChinaDRM",
                "3ea8778f-7742-4bf9-b18b-e834b2acbd47": "Clear Key AES-128",
                "be58615b-19c4-4684-88b3-c8c57e99e957": "Clear Key SAMPLE-AES",
                "e2719d58-a985-b3c9-781a-b030af78d30e": "Clear Key DASH-IF",
                "644fe7b5-260f-4fad-949a-0762ffb054b4": "CMLA (OMA DRM)",
                "37c33258-7b99-4c7e-b15d-19af74482154": "Commscope Titanium V3",
                "45d481cb-8fe0-49c0-ada9-ab2d2455b2f2": "CoreCrypt",
                "dcf4e3e3-62f1-5818-7ba6-0a6fe33ff3dd": "DigiCAP SmartXess",
                "35bf197b-530e-42d7-8b65-1b4bf415070f": "DivX DRM Series 5",
                "80a6be7e-1448-4c37-9e70-d5aebe04c8d2": "Irdeto Content Protection",
                "5e629af5-38da-4063-8977-97ffbd9902d4": "Marlin Adaptive Streaming Simple Profile V1.0",
                "6a99532d-869f-5922-9a91-113ab7b1e2f3": "MobiTV DRM",
                "adb41c24-2dbf-4a6d-958b-4457c0d27b95": "Nagra MediaAccess PRM 3.0",
                "1f83e1e8-6ee9-4f0d-ba2f-5ec4e3ed1a66": "SecureMedia",
                "992c46e6-c437-4899-b6a0-50fa91ad0e39": "SecureMedia SteelKnot",
                "a68129d3-575b-4f1a-9cba-3223846cf7c3": "Synamedia/Cisco/NDS VideoGuard DRM",
                "aa11967f-cc01-4a4a-8e99-c5d3dddfea2d": "Unitend DRM (UDRM)",
                "9a27dd82-fde2-4725-8cbc-4234aa06ec09": "Verimatrix VCAS",
                "b4413586-c58c-ffb0-94a5-d4896c1af6c3": "Viaccess-Orca DRM (VODRM)",
                "793b7956-9f94-4946-a942-23e7ef7e44b4": "VisionCrypt",
                "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b": "W3C Common PSSH box",
            }.get(system_id, "Unknown")

            if version == 1:
                key_id_count = self.buf.ru32()
                atom["data"]["key-id-count"] = key_id_count

                atom["data"]["key-ids"] = []
                for i in range(0, key_id_count):
                    atom["data"]["key-ids"].append(self.buf.ruuid())

            blob_length = self.buf.ru32()
            atom["data"]["blob-length"] = blob_length

            self.buf.pushunit()
            self.buf.setunit(blob_length)

            match system_id:
                case "9a04f079-9840-4286-ab92-e65be0885f95":
                    self.buf.skip(4)
                    record_count = self.buf.ru16l()
                    atom["data"]["record-count"] = record_count

                    atom["data"]["records"] = []
                    for i in range(0, record_count):
                        record = {}
                        record_type = self.buf.ru16l()
                        record["type"] = record_type
                        record_length = self.buf.ru16l()
                        record["length"] = record_length

                        content = self.buf.read(record_length)
                        match record_type:
                            case 1:
                                record["data"] = utils.xml_to_dict(content.decode("utf16"))
                            case _:
                                record["data"] = content.hex()

                        atom["data"]["records"].append(record)
                case "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed":
                    atom["data"]["blob"] = {}

                    for i, v in utils.read_protobuf(self.buf, blob_length).items():
                        match i:
                            case 1:
                                atom["data"]["blob"]["algorithm"] = {
                                    "raw": v,
                                    "name": {0: "Unencrypted", 1: "AES-CTR"}.get(v, "Unknown"),
                                }
                            case 2:
                                if "key-ids" not in atom["data"]["blob"]:
                                    atom["data"]["blob"]["key-ids"] = []

                                if isinstance(v, list):
                                    v = [utils.to_uuid(x) for x in v]
                                else:
                                    v = [utils.to_uuid(v)]

                                atom["data"]["blob"]["key-ids"].extend(v)
                            case 3:
                                atom["data"]["blob"]["provider"] = v.decode("utf-8")
                            case 4:
                                atom["data"]["blob"]["content-id"] = utils.to_uuid(v)
                            case 6:
                                atom["data"]["blob"]["policy"] = v.decode("utf-8")
                            case 7:
                                atom["data"]["blob"]["crypto-period-index"] = v
                            case 8:
                                atom["data"]["blob"]["grouped-license"] = v.hex()
                            case 9:
                                atom["data"]["blob"]["protection-scheme"] = {
                                    "raw": v,
                                    "name": {
                                        0: "Unspecified (CENC)",
                                        1667591779: "CENC",
                                        1667392305: "CBC1",
                                        1667591795: "CENS",
                                        1667392371: "CBCS",
                                    }.get(v, "Unknown"),
                                }
                case _:
                    atom["data"]["blob"] = self.buf.rh(blob_length)

            self.buf.skipunit()
            self.buf.popunit()
        elif typ == "pitm":
            version = self.read_version(atom)
            atom["data"]["item-id"] = self.buf.ru32() if version > 0 else self.buf.ru16()
        elif typ == "iloc":
            version = self.read_version(atom)

            temp = self.buf.ru8()
            offset_size = temp >> 4
            atom["data"]["offset-size"] = offset_size
            length_size = temp & 0x0f
            atom["data"]["length-size"] = length_size
            temp = self.buf.ru8()
            base_offset_size = temp >> 4
            atom["data"]["base-offset-size"] = base_offset_size
            index_size = temp & 0x0f
            atom["data"]["index-size"] = index_size

            item_count = self.buf.ru32() if version >= 2 else self.buf.ru16()
            atom["data"]["item-count"] = item_count

            atom["data"]["items"] = []
            for i in range(0, item_count):
                item = {}
                item["id"] = self.buf.ru32() if version >= 2 else self.buf.ru16()

                if version > 0:
                    temp = self.buf.ru16()
                    item["construction-method"] = temp & 0x0f
                    item["reserved"] = temp >> 4

                item["data-reference-index"] = self.buf.ru16()
                base_offset = int.from_bytes(self.buf.read(base_offset_size), "big")
                item["base-offset"] = base_offset

                extent_count = self.buf.ru16()
                item["extent-count"] = extent_count

                item["extents"] = []
                for j in range(0, extent_count):
                    extent = {}

                    if version > 0 and index_size > 0:
                        extent["index"] = int.from_bytes(self.buf.read(index_size), "big")

                    extent["offset"] = int.from_bytes(self.buf.read(offset_size), "big")
                    extent["length"] = int.from_bytes(self.buf.read(length_size), "big")

                    item["extents"].append(extent)

                atom["data"]["items"].append(item)
        elif typ == "iinf":
            version = self.read_version(atom)
            entry_count = self.buf.ru16() if version < 1 else self.buf.ru32()
            atom["data"]["item-count"] = entry_count

            atom["data"]["items"] = []
            for i in range(0, entry_count):
                atom["data"]["items"].append(self.read_atom())

        elif typ == "infe":
            version = self.read_version(atom)
            if version < 2:
                atom["data"]["id"] = self.buf.ru16()
                atom["data"]["protection-index"] = self.buf.ru16()
                atom["data"]["name"] = self.buf.rzs()
                atom["data"]["type"] = self.buf.rzs()
                atom["data"]["encoding"] = self.buf.rzs()

            if version == 1:
                extension_type = self.buf.rs(4)
                atom["data"]["extension-type"] = extension_type
                if extension_type == "fdel":
                    atom["data"]["extension"] = {}
                    atom["data"]["extension"]["content-location"] = self.buf.rzs()
                    atom["data"]["extension"]["content-md5"] = self.buf.rzs()
                    atom["data"]["extension"]["content-length"] = self.buf.ru64()
                    atom["data"]["extension"]["transfer-length"] = self.buf.ru64()
                    count = self.buf.ru8()
                    atom["data"]["extension"]["entry-count"] = count
                    atom["data"]["extension"]["entries"] = [self.buf.ru32() for j in range(0, count)]

            if version >= 2:
                atom["data"]["id"] = self.buf.ru16() if version == 2 else self.buf.ru32()
                atom["data"]["protection-index"] = self.buf.ru16()
                item_type = self.buf.rs(4)
                atom["data"]["type"] = item_type
                atom["data"]["name"] = self.buf.rzs()

                match item_type:
                    case "mime":
                        atom["data"]["content-type"] = self.buf.rzs()
                        atom["data"]["content-encoding"] = self.buf.rzs()
                    case "uri ":
                        atom["data"]["uri-type"] = self.buf.rzs()
        elif typ == "ispe":
            version = self.read_version(atom)
            atom["data"]["width"] = self.buf.ru32()
            atom["data"]["height"] = self.buf.ru32()
        elif typ == "pixi":
            version = self.read_version(atom)
            channel_count = self.buf.ru8()
            atom["data"]["channel-count"] = channel_count
            atom["data"]["channel-bit-depths"] = [self.buf.ru8() for i in range(0, channel_count)]
        elif typ == "av1C":
            temp = self.buf.ru8()
            atom["data"]["version"] = temp & 0x7f
            temp = self.buf.ru8()
            atom["data"]["seq-profile"] = temp >> 5
            atom["data"]["seq-level-idx-0"] = temp & 0x1f
            temp = self.buf.ru8()
            atom["data"]["seq-tier-0"] = bool(temp & 0x80)
            atom["data"]["high-bitdepth"] = bool(temp & 0x40)
            atom["data"]["twelve-bit"] = bool(temp & 0x20)
            atom["data"]["monochrome"] = bool(temp & 0x10)
            atom["data"]["chroma-subsampling-x"] = bool(temp & 0x08)
            atom["data"]["chroma-subsampling-y"] = bool(temp & 0x04)
            atom["data"]["chroma-sample-position"] = temp & 0x03
            temp = self.buf.ru8()
            atom["data"]["reserved"] = temp >> 5
            atom["data"]["initial-presentation-delay-present"] = bool(temp & 0x10)
            atom["data"]["initial-presentation-delay-minus-one"] = temp & 0x0f
            atom["data"]["obus"] = []
            while self.buf.unit > 0:
                atom["data"]["obus"].append(FFMpreg.read_av1_obu(self.buf))
        elif typ == "ipma":
            version = self.read_version(atom)
            item_count = self.buf.ru32() if version > 0 else self.buf.ru16()
            atom["data"]["item-count"] = item_count

            atom["data"]["items"] = []
            for i in range(0, item_count):
                item = {}
                item["id"] = self.buf.ru32() if version > 0 else self.buf.ru16()
                association_count = self.buf.ru8()
                item["association-count"] = association_count

                item["associations"] = []
                for j in range(0, association_count):
                    association = {}
                    if atom["data"]["flags"] & 1:
                        entry = self.buf.ru16()
                        association["essential"] = bool(entry & 0x8000)
                        association["index"] = entry & 0x7fff
                    else:
                        entry = self.buf.ru8()
                        association["essential"] = bool(entry & 0x80)
                        association["index"] = entry & 0x7f

                    item["associations"].append(association)

                atom["data"]["items"].append(item)
        elif typ == "mebx":
            atom_count = self.buf.ru64()
            atom["data"]["atom-count"] = atom_count

            atom["data"]["atoms"] = []
            for i in range(0, atom_count):
                atom["data"]["atoms"].append(self.read_atom())
        elif typ == "ilst":
            atom["entries"] = []
            while self.buf.unit:
                length = self.buf.ru32()
                i = self.buf.rs(4)
                atom["entries"].append({
                    "id": i,
                    "content": self.read_atom(root_context=i),
                })
        elif typ in ("clef", "prof", "enof"):
            self.read_version(atom)
            atom["data"]["width"] = self.buf.rfp32()
            atom["data"]["height"] = self.buf.rfp32()
        elif typ == "alis":
            self.read_version(atom)
            atom["data"]["name"] = self.buf.rzs()
        elif typ == "mpvd":
            with self.buf.subunit():
                atom["data"]["content"] = chew(self.buf)
        elif typ == "meta":
            if self.buf.pu32() == 0:
                self.buf.skip(4)

            self.read_more(atom)
        elif typ == "iref":
            version = self.read_version(atom)

            atom["data"]["from"] = self.buf.ru16() if version == 0 else self.buf.ru32()
            atom["data"]["reference-count"] = self.buf.ru16()
        elif typ == "idat":
            atom["data"]["length"] = self.buf.unit
        elif typ == "irot":
            atom["data"]["value"] = self.buf.ru8()
        elif typ == "smta":
            self.read_version(atom)
            self.read_more(atom)
        elif typ == "mdln":
            atom["data"]["model-name"] = self.buf.rs(self.buf.unit)
        elif typ == "sefd":
            # algorithm is from https://github.com/eilam-ashbell/seft-parser/blob/4083f85aad99e01af014d089bf0b0d42acf27ad4/lib/esm/classes/Seft.js
            with self.buf.sub(self.buf.unit):
                length = self.buf.available()

                self.buf.seek(length - 8)
                headers_block_length = self.buf.ru32l()
                headers_block_start_offset = length - (headers_block_length + 8)
                self.buf.seek(headers_block_start_offset + 4)
                atom["data"]["seft-version"] = self.buf.ru32l()
                record_count = self.buf.ru32l()
                atom["data"]["record-count"] = record_count

                atom["data"]["records"] = []
                for i in range(0, record_count):
                    record = {}
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

                    atom["data"]["records"].append(record)
        elif typ == "clap":
            atom["data"]["clean-aperture-width"] = self.buf.ru32() / self.buf.ru32()
            atom["data"]["clean-aperture-height"] = self.buf.ru32() / self.buf.ru32()
            atom["data"]["horiz-off"] = self.buf.ru32() / self.buf.ru32()
            atom["data"]["vert-off"] = self.buf.ru32() / self.buf.ru32()
        elif typ == "gmin":
            self.read_version(atom)
            atom["data"]["graphicsmode"] = self.buf.ru16()
            atom["data"]["opcolor"] = [self.buf.ru16() for _ in range(0, 3)]
            atom["data"]["balance"] = self.buf.ru16()
            atom["data"]["reserved"] = self.buf.rh(2)
        elif typ == "dac3":
            value = self.buf.ru24()
            atom["data"]["fscod"] = value >> 22
            atom["data"]["bsid"] = (value >> 17) & ((1 << 5) - 1)
            atom["data"]["bsmod"] = (value >> 14) & ((1 << 3) - 1)
            atom["data"]["acmod"] = (value >> 11) & ((1 << 3) - 1)
            atom["data"]["lfeon"] = (value >> 10) & ((1 << 1) - 1)
            atom["data"]["bit-rate-code"] = (value >> 5) & ((1 << 5) - 1)
            atom["data"]["reserved"] = value & ((1 << 5) - 1)
        elif typ == "tx3g":
            atom["data"]["reserved"] = self.buf.rh(6)
            atom["data"]["data-reference-index"] = self.buf.ru16()
            atom["data"]["display-flags"] = self.buf.rh(4)
            atom["data"]["horizontal-justification"] = self.buf.ri8()
            atom["data"]["vertical-justification"] = self.buf.ri8()
            atom["data"]["background-color"] = self.buf.rh(4)
            atom["data"]["font-id"] = self.buf.ru16()
            atom["data"]["font-face"] = self.buf.ru8()
            atom["data"]["font-size"] = self.buf.ru8()
            atom["data"]["font-color"] = self.buf.rh(4)
            atom["data"]["default-text-box-top"] = self.buf.ru16()
            atom["data"]["default-text-box-left"] = self.buf.ru16()
            atom["data"]["default-text-box-bottom"] = self.buf.ru16()
            atom["data"]["default-text-box-right"] = self.buf.ru16()
            atom["data"]["start-char"] = self.buf.ru16()
            atom["data"]["end-char"] = self.buf.ru16()
            self.read_more(atom)
        elif typ == "ftab":
            font_count = self.buf.ru16()
            atom["data"]["font-count"] = font_count

            atom["data"]["fonts"] = []
            for i in range(0, font_count):
                font = {}
                font["id"] = self.buf.ru16()
                font["name"] = self.buf.rs(self.buf.ru8())

                atom["data"]["fonts"].append(font)
        elif typ == "chap":
            atom["data"]["track-id"] = self.buf.ru32()
        elif typ == "text":
            atom["data"]["reserved"] = self.buf.rh(6)
            atom["data"]["data-reference-index"] = self.buf.ru16()
            atom["data"]["display-flags"] = self.buf.rh(4)
            atom["data"]["horizontal-justification"] = self.buf.ri8()
            atom["data"]["vertical-justification"] = self.buf.ri8()
            atom["data"]["background-color"] = self.buf.rh(4)
            atom["data"]["font-id"] = self.buf.ru16()
            atom["data"]["font-face"] = self.buf.ru8()
            atom["data"]["font-size"] = self.buf.ru8()
            atom["data"]["font-color"] = self.buf.rh(4)
            atom["data"]["default-text-box-top"] = self.buf.ru16()
            atom["data"]["default-text-box-left"] = self.buf.ru16()
            atom["data"]["default-text-box-bottom"] = self.buf.ru16()
            atom["data"]["default-text-box-right"] = self.buf.ru16()
            if self.buf.unit > 4:
                atom["data"]["start-char"] = self.buf.ru16()
                atom["data"]["end-char"] = self.buf.ru16()
            self.read_more(atom)
        elif typ == "chpl":
            chapter_count = self.buf.ru8()
            atom["data"]["chapter-count"] = chapter_count

            atom["data"]["chapters"] = []
            for i in range(0, chapter_count):
                chapter = {}
                chapter["timestamp"] = self.buf.ru64()
                chapter["title"] = self.buf.rs(self.buf.ru8())

                atom["data"]["chapters"].append(chapter)
        elif typ == "dfLa":
            self.read_version(atom)
            atom["data"]["content"] = chew(b"fLaC" + self.buf.readunit())
        elif typ == "ID32":
            self.buf.skip(6)
            atom["data"]["content"] = chew(self.buf.readunit())
        elif typ == "nmhd":
            self.read_version(atom)
        elif typ == "jP  ":
            atom["data"]["signature"] = self.buf.rh(4)
        elif typ == "ihdr":
            atom["data"]["height"] = self.buf.ru32()
            atom["data"]["width"] = self.buf.ru32()
            atom["data"]["num-components"] = self.buf.ru16()
            atom["data"]["depth"] = self.buf.ru8()
            atom["data"]["compression"] = self.buf.ru8()
            atom["data"]["colour-unknown"] = self.buf.ru8()
            atom["data"]["ipr"] = self.buf.ru8()
        elif typ == "lbl ":
            atom["data"]["string"] = self.buf.rs(self.buf.unit)
        elif typ == "xml ":
            atom["data"]["xml"] = utils.xml_to_dict(self.buf.rs(self.buf.unit))
        elif typ == "jumd":
            atom["data"]["uuid"] = utils.to_uuid(self.buf.read(16))
            toggles = self.buf.ru8()
            atom["data"]["toggles"] = {
                "raw": toggles,
                "requestable": bool(toggles & (1 << 0)),
                "label": bool(toggles & (1 << 1)),
                "id": bool(toggles & (1 << 2)),
                "signature": bool(toggles & (1 << 3)),
            }

            if atom["data"]["toggles"]["label"]:
                atom["data"]["label"] = self.buf.rzs()

            if atom["data"]["toggles"]["id"]:
                atom["data"]["id"] = self.buf.ru32()

            if atom["data"]["toggles"]["signature"]:
                atom["data"]["signature-hash"] = self.buf.rh(32)
        elif typ == "cbor":
            atom["data"]["blob"] = utils.read_cbor(self.buf)
        elif typ == "bfdb":
            flags = self.buf.ru8()
            atom["data"]["flags"] = {
                "raw": flags,
                "has-filename": bool(flags & (1 << 0)),
            }

            atom["data"]["media-type"] = self.buf.rzs()

            if atom["data"]["flags"]["has-filename"]:
                atom["data"]["filename"] = self.buf.rzs()
        elif typ == "bidb":
            with self.buf.subunit():
                atom["data"]["file"] = chew(self.buf)
        elif typ == "dOps":
            atom["data"]["version"] = self.buf.ru8()
            atom["data"]["output-channel-count"] = self.buf.ru8()
            atom["data"]["pre-skip"] = self.buf.ru16()
            atom["data"]["input-sample-rate"] = self.buf.ru32()
            atom["data"]["output-gain"] = self.buf.ri16()
            atom["data"]["channel-mapping-family"] = self.buf.ru8()

            if atom["data"]["channel-mapping-family"] != 0:
                atom["data"]["stream-count"] = self.buf.ru8()
                atom["data"]["coupled-count"] = self.buf.ru8()
                atom["data"]["channel-mapping"] = [self.buf.ru8() for i in range(0, atom["data"]["output-channel-count"])]
        elif typ == "fiel":
            atom["data"]["field-count"] = self.buf.ru8()
            atom["data"]["field-order"] = self.buf.ru8()
        elif typ == "chnl":
            self.read_version(atom)
            atom["data"]["stream-structure"] = self.buf.ru8()
            atom["data"]["defined-layout"] = self.buf.ru8()
            atom["data"]["omitted-channels-map"] = self.buf.ru16()

            if atom["data"]["defined-layout"] == 0:
                atom["data"]["speaker-count"] = self.buf.ru8()
                for i in range(0, atom["data"]["speaker-count"]):
                    speaker = {}
                    speaker["position"] = self.buf.ru8()
                    speaker["azimuth"] = self.buf.ru8()
                    speaker["elevation"] = self.buf.ru8()

                    atom["data"]["speakers"].append(speaker)
        elif typ == "pcmC":
            # so they only give you a sample of ISO/IEC 23003-5 but it's such
            # a small standard that the sample is the whole thing
            # see https://cdn.standards.iteh.ai/samples/77752/a17f98e0bb664a939b031b6a969995d9/ISO-IEC-23003-5-2020.pdf
            self.read_version(atom)
            atom["data"]["flags"] = utils.unpack_flags(self.buf.ru8(), ((0, "little-endian"),))
            atom["data"]["sample-size"] = self.buf.ru8()
        elif typ == "CNCV":
            atom["data"]["version-string"] = self.buf.rs(self.buf.unit)
        elif typ == "CNDM":
            atom["data"]["values"] = [self.buf.ri16() for i in range(0, self.buf.unit, 2)]
        elif typ == "CNTH":
            self.buf.skip(8)
            with self.buf.subunit():
                atom["data"]["content"] = chew(self.buf)
        elif typ == "d263":
            atom["data"]["encoder"] = self.buf.rs(4)
            atom["data"]["decoder-version"] = self.buf.ru8()
            atom["data"]["level"] = self.buf.ru8()
            atom["data"]["profile"] = self.buf.ru8()
        elif typ == "chan":
            atom["data"]["version"] = self.buf.ru8()
            atom["data"]["flags"] = self.buf.ru24()
            atom["data"]["layout-tag"] = self.buf.ru32()
            atom["data"]["bitmap"] = self.buf.ru32()
            atom["data"]["channel-descriptor-count"] = self.buf.ru32()

            atom["data"]["channel-descriptors"] = []
            for i in range(0, atom["data"]["channel-descriptor-count"]):
                desc = {}
                desc["label"] = self.buf.ru32()
                desc["flags"] = self.buf.ru32()
                desc["coordinates"] = [self.buf.ru32l() for j in range(0, 3)]

                atom["data"]["channel-descriptors"].append(desc)
        elif typ == "saut":
            self.read_version(atom)
            atom["data"]["flag"] = self.buf.ru8()
            atom["data"]["mode"] = utils.unraw(
                self.buf.ru8(),
                1,
                {
                    0x00: "EMPTY",
                    0x01: "VR_NORMAL",
                    0x02: "INTERVIEW",
                    0x03: "MEETING",
                    0x04: "VR_STT",
                    0x05: "ATTACH",
                    0x06: "LIMIT_FOR_MMS",
                    0x07: "VR_AUTO_STT",
                    0x64: "CALL_NORMAL",
                    0x65: "CALL_STT",
                    0x96: "INTERPRETER_NORMAL",
                    0x97: "INTERPRETER_STT",
                    0x9c: "FM_RADIO_NORMAL",
                    0x9d: "FM_RADIO_STT",
                    0xaa: "VOICEMAIL_NORMAL",
                    0xab: "VOICEMAIL_STT",
                    0xc8: "NOTES_NORMAL",
                    0xc9: "NOTES_STT",
                    0xfc: "OTHER_RECORDING_STT",
                    0xff: "OTHER_RECORDING_NORMAL",
                },
                True,
            )
        elif typ in ("vrdt", "metd", "ampl"):
            # silly Samsung
            with self.buf.subunit():
                atom["data"]["value"] = chew(self.buf)
        elif typ == "bkmk":
            atom["data"]["value"] = self.buf.ru32()
            atom["data"]["title"] = self.buf.rs(100, "utf-16be")
            atom["data"]["description"] = self.buf.rs(self.buf.unit, "utf-16be")
        elif typ == "tmcd":
            if self.buf.unit > 8 and self.buf.peek(8)[4:] == b"tcmi":
                self.read_more(atom)
            else:
                atom["data"]["hex"] = self.buf.rh(self.buf.unit)
        elif typ == "tcmi":
            self.read_version(atom)
            atom["data"]["text-font"] = self.buf.ru16()
            atom["data"]["text-face"] = self.buf.ru16()
            atom["data"]["text-size"] = self.buf.ru16()
            atom["data"]["reserved"] = self.buf.ru16()
            atom["data"]["text-color"] = [self.buf.ru16() for i in range(0, 3)]
            atom["data"]["background-color"] = [self.buf.ru16() for i in range(0, 3)]
            atom["data"]["font-name"] = self.buf.rs(self.buf.ru8())
        elif typ == "st3d":
            # https://github.com/google/spatial-media/blob/master/docs/spherical-video-v2-rfc.md#stereoscopic-3d-video-box-st3d
            self.read_version(atom)
            atom["data"]["stereo-mode"] = utils.unraw(
                self.buf.ru8(),
                1,
                {
                    0x00: "Monoscopic",
                    0x01: "Stereoscopic Top-Bottom",
                    0x02: "Stereoscopic Left-Right",
                    0x03: "Stereoscopic Stereo-Custom",
                    0x04: "Stereoscopic Right-Left",
                },
                True,
            )
        elif typ == "svhd":
            self.read_version(atom)
            atom["data"]["metadata-source"] = self.buf.rs(self.buf.unit)
        elif typ == "prhd":
            self.read_version(atom)
            atom["data"]["pose-yaw-degrees"] = self.buf.ru32()
            atom["data"]["pose-pitch-degrees"] = self.buf.ru32()
            atom["data"]["pose-roll-degrees"] = self.buf.ru32()
        elif typ == "equi":
            self.read_version(atom)
            atom["data"]["projection-bounds-top"] = self.buf.ru32()
            atom["data"]["projection-bounds-bottom"] = self.buf.ru32()
            atom["data"]["projection-bounds-left"] = self.buf.ru32()
            atom["data"]["projection-bounds-right"] = self.buf.ru32()
        elif typ == "vvcC":
            self.read_version(atom)
            atom["data"]["reserved1"] = self.buf.rb(5)
            atom["data"]["length-size-minus-one"] = self.buf.rb(2)
            atom["data"]["ptl-present"] = self.buf.rb(1)

            if atom["data"]["ptl-present"]:
                atom["data"]["ols-idx"] = self.buf.rb(9)
                atom["data"]["sublayers-count"] = self.buf.rb(3)
                atom["data"]["constant-frame-rate"] = self.buf.rb(2)
                atom["data"]["chroma-format-idc"] = self.buf.rb(2)
                atom["data"]["bit-depth-minus-eight"] = self.buf.rb(3)
                atom["data"]["reserved2"] = self.buf.rb(5)
                atom["data"]["general-profile-idc"] = self.buf.rb(7)
                atom["data"]["general-tier-flag"] = self.buf.rb(1)
                atom["data"]["general-level-idc"] = self.buf.rb(8)
                atom["data"]["ptl-frame-only-constraint-flag"] = self.buf.rb(1)
                atom["data"]["ptl-multi-layer-enabled-flag"] = self.buf.rb(1)
                atom["data"]["general-constraint-info-bytes"] = self.buf.rb(6)
                atom["data"]["general-constraint-info"] = self.buf.rh(atom["data"]["general-constraint-info-bytes"])

                if atom["data"]["sublayers-count"] > 1:
                    temp = self.buf.rb(atom["data"]["sublayers-count"] - 1)
                    self.buf.align()
                    atom["data"]["ptl-sublayer-level-present-flag"] = temp
                    atom["data"]["sublayer-level-idc"] = self.buf.rh(temp.bit_count())

                atom["data"]["ptl-sub-profile-count"] = self.buf.ru8()
                atom["data"]["ptl-sub-profiles"] = self.buf.rh(atom["data"]["ptl-sub-profile-count"] * 4)

            atom["data"]["max-picture-width"] = self.buf.ru16()
            atom["data"]["max-picture-height"] = self.buf.ru16()
            atom["data"]["avg-frame-rate"] = self.buf.ru16() / 256

            atom["data"]["array-count"] = self.buf.ru8()
            atom["data"]["arrays"] = []
            for i in range(0, atom["data"]["array-count"]):
                array = {}
                array["completeness"] = self.buf.rb(1)
                array["reserved"] = self.buf.rb(2)
                array["type"] = utils.unraw(self.buf.rb(5), 1, FFMpreg.H265_NAL_UNIT_TYPES, True)

                array["nalu-count"] = self.buf.ru16()
                array["nalus"] = []
                for i in range(0, array["nalu-count"]):
                    self.buf.pasunit(self.buf.ru16())

                    array["nalus"].append(FFMpreg.read_h266_nalu(self.buf))

                    self.buf.sapunit()

                atom["data"]["arrays"].append(array)
        elif typ == "ccst":
            self.read_version(atom)
            atom["data"]["all-ref-pics-intra"] = self.buf.rb(1)
            atom["data"]["intra-pred-used"] = self.buf.rb(1)
            atom["data"]["max-ref-per-pic"] = self.buf.rb(4)
            atom["data"]["reserved"] = self.buf.rb(26)
        elif typ == "kind":
            self.read_version(atom)
            atom["data"]["scheme-uri"] = self.buf.rzs()

            if self.buf.unit > 0:
                atom["data"]["value"] = self.buf.rzs()
        elif typ == "dvvC":
            atom["data"]["version"] = f"{self.buf.ru8()}.{self.buf.ru8()}"
            atom["data"]["profile"] = self.buf.rb(7)
            atom["data"]["level"] = self.buf.rb(6)
            atom["data"]["rpu-present-flag"] = self.buf.rb(1)
            atom["data"]["el-present-flag"] = self.buf.rb(1)
            atom["data"]["bl-present-flag"] = self.buf.rb(1)
            atom["data"]["bl-signal-compatability-id"] = utils.unraw(
                self.buf.rb(4), 1, {0x00: "None", 0x01: "HDR10", 0x02: "SDR / Rec.709", 0x03: "HLG"}, True
            )
            atom["data"]["reserved1"] = self.buf.rb(4)
            atom["data"]["reserved2"] = self.buf.rh(self.buf.unit)
        elif typ == "dec3":
            atom["data"]["data-rate"] = self.buf.rb(13)
            atom["data"]["num-ind-sub"] = self.buf.rb(3)

            atom["data"]["ind-subs"] = []
            for i in range(0, atom["data"]["num-ind-sub"] + 1):
                sub = {}
                sub["fscod"] = utils.unraw(self.buf.rb(2), 1, {0x00: "48 kHz", 0x01: "44.1 kHz", 0x02: "32 kHz"}, True)
                sub["bsid"] = self.buf.rb(5)
                sub["asvc"] = self.buf.rb(1)
                sub["bsmod"] = self.buf.rb(3)
                sub["acmod"] = self.buf.rb(3)
                sub["lfeon"] = self.buf.rb(1)
                sub["num-dep-sub"] = self.buf.rb(4)

                if sub["num-dep-sub"] > 0:
                    sub["chan-loc"] = self.buf.rb(9)
                else:
                    sub["reserved"] = self.buf.rb(1)

                atom["data"]["ind-subs"].append(sub)

            if self.buf.unit > 0:
                atom["data"]["reserved"] = self.buf.rb(1)
                atom["data"]["flag-ec3-extension-type-a"] = self.buf.rb(1)

                if atom["data"]["flag-ec3-extension-type-a"]:
                    atom["data"]["complexity-index-type-a"] = self.buf.rb(8)

            self.buf.align()
        elif typ == "mett":
            atom["data"]["content-encoding"] = self.buf.rzs()
            atom["data"]["mime-format"] = self.buf.rzs()
        elif typ[0] == "©" or typ in ("iods", "SDLN", "smrd"):
            if typ[:2] == "©T" and self.buf.pu16() == self.buf.unit - 4:
                length = self.buf.ru16()
                self.buf.skip(2)
                atom["data"]["payload"] = self.buf.rs(length)
            else:
                atom["data"]["payload"] = self.buf.readunit().decode("latin-1")
        elif typ in ("FIRM", "LENS"):
            atom["data"]["string"] = self.buf.rs(self.buf.unit)
        elif typ in ("hint", "cdsc", "font", "hind", "vdep", "vplx", "subt", "cdep"):
            atom["data"]["track-id"] = self.buf.ru32()
        # video sample boxes
        elif typ in ("avc1", "hvc1", "vp09", "encv", "av01", "hev1", "vvc1", "h263", "mp4v"):
            atom["data"]["reserved1"] = self.buf.rh(6)
            atom["data"]["data_reference_index"] = self.buf.ru16()
            atom["data"]["pre-defined1"] = self.buf.rh(2)
            atom["data"]["reserved2"] = self.buf.rh(2)
            atom["data"]["pre-defined2"] = self.buf.rh(12)
            atom["data"]["width"] = self.buf.ru16()
            atom["data"]["height"] = self.buf.ru16()
            atom["data"]["horizresolution"] = self.buf.rfp32()
            atom["data"]["vertresolution"] = self.buf.rfp32()
            atom["data"]["reserved3"] = self.buf.rh(4)
            atom["data"]["frame-count"] = self.buf.ru16()
            name_length = self.buf.ru8()
            name = self.buf.read(31)
            atom["data"]["compressorname"] = name[:name_length].decode("utf-8")
            atom["data"]["depth"] = self.buf.ru16()
            atom["data"]["pre-defined3"] = self.buf.rh(2)

            self.read_more(atom)
        # audio sample boxes
        elif typ in (
            "samr",
            "sawb",
            "mp4a",
            "drms",
            "owma",
            "ac-3",
            "ec-3",
            "mlpa",
            "dtsl",
            "dtsh",
            "dtse",
            "enca",
            "fLaC",
            "Opus",
            "ipcm",
        ):
            if typ == "mp4a" and self.buf.unit == 4:
                atom["data"]["content"] = self.buf.rh(self.buf.unit)
            else:
                # see https://github.com/sannies/mp4parser for reference
                atom["data"]["reserved1"] = self.buf.rh(6)
                atom["data"]["data-reference-index"] = self.buf.ru16()
                atom["data"]["sound-version"] = self.buf.ru16()
                atom["data"]["reserved2"] = self.buf.rh(6)
                atom["data"]["channel-count"] = self.buf.ru16()
                atom["data"]["sample-size"] = self.buf.ru16()
                atom["data"]["compression-id"] = self.buf.ru16()
                atom["data"]["packet-size"] = self.buf.ru16()

                atom["data"]["sample-rate"] = self.buf.ru32()
                if typ != "mlpa":
                    atom["data"]["sample-rate"] >>= 16

                if atom["data"]["sound-version"] >= 1:
                    atom["data"]["samples-per-packet"] = self.buf.ru32()
                    atom["data"]["bytes-per-packet"] = self.buf.ru32()
                    atom["data"]["bytes-per-frame"] = self.buf.ru32()
                    atom["data"]["bytes-per-sample"] = self.buf.ru32()

                if atom["data"]["sound-version"] >= 2:
                    atom["data"]["sound-v2-data"] = self.buf.rh(20)

                if typ != "owma":
                    self.read_more(atom)
        elif typ in ("lpcm", "beam"):
            # TODO
            pass
        elif typ == "mdat":
            with self.buf.subunit():
                atom["data"]["blob"] = chew(self.buf, blob_mode=True)
        elif typ[0] == "\x00" or typ in ("mdat", "wide", "jp2c", "bnum"):
            pass
        else:
            atom["unknown"] = True

        self.buf.skipunit()
        self.buf.popunit()

        return atom

    def get_all(self, atoms, typ):
        if isinstance(typ, str):
            typ = [typ]

        result = []
        for atom in atoms:
            if atom["type"] in typ:
                result.append(atom)

        return result

    def parse_mdat(self, atoms):
        if self.get_all(atoms, "ftyp")[0]["data"]["major-brand"] in ("avif", "heic", "mif1"):
            return self.process_heif_mdat(atoms)

        moov = self.get_all(atoms, "moov")[0]["data"]["atoms"]
        traks = self.get_all(moov, "trak")

        streams = []
        for trak in traks:
            mdia = self.get_all(trak["data"]["atoms"], "mdia")[0]
            minf = self.get_all(mdia["data"]["atoms"], "minf")[0]
            stbl = self.get_all(minf["data"]["atoms"], "stbl")[0]
            stsd = self.get_all(stbl["data"]["atoms"], "stsd")[0]
            stco_co64 = self.get_all(stbl["data"]["atoms"], ("stco", "co64"))[0]
            stsc = self.get_all(stbl["data"]["atoms"], "stsc")[0]
            stsz = self.get_all(stbl["data"]["atoms"], "stsz")[0]

            codec = stsd["data"]["atoms"][0]["type"]

            stream = {}
            stream["type"] = codec

            self.buf.seek(stsz["offset"])
            self.buf.pasunit(stsz["length"])

            self.buf.skip(12)
            sample_size = self.buf.ru32()
            sample_count = self.buf.ru32()

            if sample_size:
                sample_sizes = [sample_size] * sample_count
            else:
                temp = self.buf.read(4 * sample_count)
                sample_sizes = [int.from_bytes(temp[i : i + 4], "big") for i in range(0, 4 * sample_count, 4)]

            self.buf.sapunit()

            self.buf.seek(stco_co64["offset"])
            self.buf.pasunit(stco_co64["length"])

            self.buf.skip(12)
            chunk_count = self.buf.ru32()

            if stco_co64["type"] == "stco":
                temp = self.buf.read(4 * chunk_count)
                chunk_offsets = [int.from_bytes(temp[i : i + 4], "big") for i in range(0, 4 * chunk_count, 4)]
            else:
                temp = self.buf.read(8 * chunk_count)
                chunk_offsets = [int.from_bytes(temp[i : i + 8], "big") for i in range(0, 8 * chunk_count, 8)]

            self.buf.sapunit()

            self.buf.seek(stsc["offset"])
            self.buf.pasunit(stsc["length"])

            self.buf.skip(12)
            entries = [(self.buf.ru32(), self.buf.ru32(), self.buf.ru32()) for i in range(0, self.buf.ru32())]

            entries.append((chunk_count + 1, 1, 1))
            sample_to_offset = []
            for i in range(0, len(entries) - 1):
                start_chunk, sample_count, _ = entries[i]
                end_chunk, _, _ = entries[i + 1]

                for i in range(start_chunk, end_chunk):
                    chunk_offset = chunk_offsets[i - 1]
                    for j in range(0, sample_count):
                        sample_to_offset.append(chunk_offset)
                        chunk_offset += sample_sizes[len(sample_to_offset) - 1]

            self.buf.popunit()

            stream["sample-count"] = len(sample_to_offset)
            stream["data"] = self.process_stream(stsd["data"]["atoms"][0], sample_to_offset, sample_sizes, atoms)

            streams.append(stream)

        return streams

    def process_heif_mdat(self, atoms):
        meta = self.get_all(atoms, "meta")[0]["data"]["atoms"]
        iloc = self.get_all(meta, "iloc")[0]
        iprp = self.get_all(meta, "iprp")[0]["data"]["atoms"]
        ipco = self.get_all(iprp, "ipco")[0]["data"]["atoms"]

        codec = None
        for atom in ipco:
            if atom["type"] in ("av1C", "hvcC", "avcC"):
                codec = atom["type"]
                break

        pictures = []
        for entry in iloc["data"]["items"]:
            picture = {}
            picture["type"] = codec
            picture["id"] = entry["id"]

            data = b""
            for extent in entry["extents"]:
                self.buf.seek(extent["offset"] + entry["base-offset"])
                data += self.buf.read(extent["length"])

            picture["buf"] = Buf(data)

            self.process_heif_picture(codec, picture)
            pictures.append(picture)

        return pictures

    def process_stream(self, codec, sample_to_offset, sample_sizes, atoms):
        data = {}

        match codec["type"]:
            case "avc1":
                avcC = self.get_all(codec["data"]["atoms"], "avcC")[0]
                nal_length_size = (avcC["data"]["length-size-minus-one"] & 0x03) + 1
                data["nal-length-size"] = nal_length_size

                ranges = utils.expand_ranges(secrets.get_parameter("0", data, "ranges"), 0, len(sample_to_offset) - 1)
                data["samples"] = {}

                for index in ranges:
                    self.buf.seek(sample_to_offset[index])
                    self.buf.pasunit(sample_sizes[index])

                    data["samples"][index] = []
                    while self.buf.unit > 0:
                        nalu = {}
                        nalu["length"] = int.from_bytes(self.buf.read(nal_length_size), "big")

                        self.buf.pasunit(nalu["length"])

                        nalu["payload"] = FFMpreg.read_h264_nalu(self.buf, slim=True)

                        self.buf.sapunit()

                        data["samples"][index].append(nalu)

                    self.buf.sapunit()
            case "av01":
                if self.get_all(atoms, "ftyp")[0]["data"]["major-brand"] == "avis":
                    data["pictures"] = []
                    for i in range(0, len(sample_to_offset)):
                        picture = []
                        self.buf.seek(sample_to_offset[i])
                        self.buf.pasunit(sample_sizes[i])

                        while self.buf.unit > 0:
                            picture.append(FFMpreg.read_av1_obu(self.buf))

                        data["pictures"].append(picture)
                        self.buf.sapunit()
                else:
                    ranges = utils.expand_ranges(secrets.get_parameter("0", data, "ranges"), 0, len(sample_to_offset) - 1)
                    data["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_to_offset[index])
                        self.buf.pasunit(sample_sizes[index])

                        obus = []
                        while self.buf.unit > 0:
                            obus.append(FFMpreg.read_av1_obu(self.buf))

                        data["samples"][index] = obus

                        self.buf.sapunit()
            case "tx3g":
                ranges = utils.expand_ranges(secrets.get_parameter("0", data, "ranges"), 0, len(sample_to_offset) - 1)
                data["samples"] = {}

                for index in ranges:
                    self.buf.seek(sample_to_offset[index])
                    with self.buf.sub(sample_sizes[index]):
                        data["samples"][index] = self.buf.rs(self.buf.ru16())
            case "hev1" | "hvc1":
                hvcC = self.get_all(codec["data"]["atoms"], "hvcC")[0]
                nal_length_size = (hvcC["data"]["length-size-minus-one"] & 0x03) + 1
                data["nal-length-size"] = nal_length_size

                ranges = utils.expand_ranges(secrets.get_parameter("0", data, "ranges"), 0, len(sample_to_offset) - 1)
                data["samples"] = {}

                for index in ranges:
                    self.buf.seek(sample_to_offset[index])
                    self.buf.pasunit(sample_sizes[index])

                    data["samples"][index] = []
                    while self.buf.unit > 0:
                        nalu = {}
                        nalu["length"] = int.from_bytes(self.buf.read(nal_length_size), "big")

                        self.buf.pasunit(nalu["length"])

                        nalu["payload"] = FFMpreg.read_h265_nalu(self.buf)

                        self.buf.sapunit()

                        data["samples"][index].append(nalu)

                    self.buf.sapunit()
            case "vvc1":
                vvcC = self.get_all(codec["data"]["atoms"], "vvcC")[0]
                nal_length_size = (vvcC["data"]["length-size-minus-one"] & 0x03) + 1
                data["nal-length-size"] = nal_length_size

                ranges = utils.expand_ranges(secrets.get_parameter("0", data, "ranges"), 0, len(sample_to_offset) - 1)
                data["samples"] = {}

                for index in ranges:
                    self.buf.seek(sample_to_offset[index])
                    self.buf.pasunit(sample_sizes[index])

                    data["samples"][index] = []
                    while self.buf.unit > 0:
                        nalu = {}
                        nalu["length"] = int.from_bytes(self.buf.read(nal_length_size), "big")

                        self.buf.pasunit(nalu["length"])

                        nalu["payload"] = FFMpreg.read_h266_nalu(self.buf)

                        self.buf.sapunit()

                        data["samples"][index].append(nalu)

                    self.buf.sapunit()
            case "mett":
                ranges = utils.expand_ranges(secrets.get_parameter("0", data, "ranges"), 0, len(sample_to_offset) - 1)
                data["samples"] = {}

                for index in ranges:
                    self.buf.seek(sample_to_offset[index])
                    self.buf.pasunit(sample_sizes[index])

                    self.buf.skip(3)
                    data["samples"][index] = utils.read_protobuf(
                        self.buf,
                        self.buf.unit,
                        True,
                        {0: {14: {}}, 10: {}, 13: "float", 14: "float", 15: "float", 16: "float", 18: {}},
                    )

                    self.buf.sapunit()
            case "mp4a" | "mp4v" | "drac":
                ranges = utils.expand_ranges(secrets.get_parameter("0", data, "ranges"), 0, len(sample_to_offset) - 1)
                data["samples"] = {}

                for index in ranges:
                    self.buf.seek(sample_to_offset[index])
                    with self.buf.sub(sample_sizes[index]):
                        data["samples"][index] = chew(self.buf)
            case _:
                ranges = utils.expand_ranges(secrets.get_parameter("0", data, "ranges"), 0, len(sample_to_offset) - 1)
                data["samples"] = {}

                for index in ranges:
                    self.buf.seek(sample_to_offset[index])
                    with self.buf.sub(sample_sizes[index]):
                        data["samples"][index] = chew(self.buf, blob_mode=True)

                data["unknown"] = True

        return data

    def process_heif_picture(self, codec, picture):
        match codec:
            case "av1C":
                picture["obus"] = []
                while picture["buf"].available():
                    picture["obus"].append(FFMpreg.read_av1_obu(picture["buf"]))
            case "hvcC":
                picture["nals"] = []
                while picture["buf"].available():
                    picture["nals"].append(FFMpreg.read_h265_nalu(picture["buf"]))
            case "avcC":
                picture["nals"] = []
                while picture["buf"].available():
                    picture["nals"].append(FFMpreg.read_h264_nalu(picture["buf"]))

        del picture["buf"]

    def read_esds(self):
        # see ISO/IEC 14496-1
        tlv = {}
        tlv["tag"] = utils.unraw(
            self.buf.ru8(),
            1,
            {
                0x03: "ES_Descriptor",
                0x04: "DecoderConfigDescriptor",
                0x05: "DecoderSpecificInfo",
                0x06: "SLConfigDescriptor",
            },
            True,
        )
        tlv["length"] = self.buf.rubeb()
        tlv["value"] = {}

        self.buf.pasunit(tlv["length"])

        match tlv["tag"]:
            case "ES_Descriptor":
                tlv["value"]["es-id"] = self.buf.ru16()
                tlv["value"]["stream-dependence-flag"] = self.buf.rb(1)
                tlv["value"]["url-flag"] = self.buf.rb(1)
                tlv["value"]["ocr-stream-flag"] = self.buf.rb(1)
                tlv["value"]["stream-priority"] = self.buf.rb(5)

                if tlv["value"]["stream-dependence-flag"]:
                    tlv["value"]["depends-on-es-id"] = self.buf.ru16()

                if tlv["value"]["url-flag"]:
                    tlv["value"]["url-length"] = self.buf.ru8()
                    tlv["value"]["url"] = self.buf.rs(tlv["value"]["url-length"])

                if tlv["value"]["ocr-stream-flag"]:
                    tlv["value"]["ocr-es-id"] = self.buf.ru16()

                tlv["value"]["children"] = []
                while self.buf.unit > 0:
                    tlv["value"]["children"].append(self.read_esds())
            case "DecoderConfigDescriptor":
                tlv["value"]["object-type-indictation"] = utils.unraw(
                    self.buf.ru8(),
                    1,
                    {
                        0x01: "Systems ISO/IEC 14496-1 a",
                        0x02: "Systems ISO/IEC 14496-1 b",
                        0x03: "Interaction Stream",
                        0x04: "Systems ISO/IEC 14496-1 Extended BIFS Configuration c",
                        0x05: "Systems ISO/IEC 14496-1 AFX d",
                        0x06: "Font Data Stream",
                        0x07: "Synthesized Texture Stream",
                        0x08: "Streaming Text Stream",
                        0x20: "Visual ISO/IEC 14496-2 e",
                        0x21: "Visual ITU-T Recommendation H.264 | ISO/IEC 14496-10 f",
                        0x22: "Parameter Sets for ITU-T Recommendation H.264 | ISO/IEC 14496-10 f",
                        0x40: "Audio ISO/IEC 14496-3 g",
                        0x60: "Visual ISO/IEC 13818-2 Simple Profile",
                        0x61: "Visual ISO/IEC 13818-2 Main Profile",
                        0x62: "Visual ISO/IEC 13818-2 SNR Profile",
                        0x63: "Visual ISO/IEC 13818-2 Spatial Profile",
                        0x64: "Visual ISO/IEC 13818-2 High Profile",
                        0x65: "Visual ISO/IEC 13818-2 422 Profile",
                        0x66: "Audio ISO/IEC 13818-7 Main Profile",
                        0x67: "Audio ISO/IEC 13818-7 LowComplexity Profile",
                        0x68: "Audio ISO/IEC 13818-7 Scaleable Sampling Rate Profile",
                        0x69: "Audio ISO/IEC 13818-3",
                        0x6a: "Visual ISO/IEC 11172-2",
                        0x6b: "Audio ISO/IEC 11172-3",
                        0x6c: "Visual ISO/IEC 10918-1",
                        0x6e: "Visual ISO/IEC 15444-1",
                    },
                    True,
                )
                tlv["value"]["stream-type"] = utils.unraw(
                    self.buf.rb(6),
                    1,
                    {
                        0x01: "ObjectDescriptorStream",
                        0x02: "ClockReferenceStream",
                        0x03: "SceneDescriptionStream",
                        0x04: "VisualStream",
                        0x05: "AudioStream",
                        0x06: "MPEG7Stream",
                        0x07: "IPMPStream",
                        0x08: "ObjectContentInfoStream",
                        0x09: "MPEGJStream",
                        0x0a: "Interaction Stream",
                        0x0b: "IPMPToolStream",
                    },
                    True,
                )
                tlv["value"]["up-stream"] = self.buf.rb(1)
                tlv["value"]["reserved"] = self.buf.rb(1)
                tlv["value"]["buffer-size-db"] = self.buf.ru24()
                tlv["value"]["max-bitrate"] = self.buf.ru32()
                tlv["value"]["avg-bitrate"] = self.buf.ru32()

                tlv["value"]["children"] = []
                while self.buf.unit > 0:
                    tlv["value"]["children"].append(self.read_esds())
            case "DecoderSpecificInfo":
                tlv["value"]["payload"] = self.buf.rh(self.buf.unit)
            case "SLConfigDescriptor":
                tlv["value"]["predefined"] = self.buf.ru8()

                if tlv["value"]["predefined"] == 0:
                    tlv["value"]["use-access-unit-start-flag"] = self.buf.rb(1)
                    tlv["value"]["use-access-unit-end-flag"] = self.buf.rb(1)
                    tlv["value"]["use-random-access-point-flag"] = self.buf.rb(1)
                    tlv["value"]["has-random-access-units-only-flag"] = self.buf.rb(1)
                    tlv["value"]["use-padding-flag"] = self.buf.rb(1)
                    tlv["value"]["use-timestamps-flag"] = self.buf.rb(1)
                    tlv["value"]["use-idle-flag"] = self.buf.rb(1)
                    tlv["value"]["duration-flag"] = self.buf.rb(1)
                    tlv["value"]["timestamp-resolution"] = self.buf.ru32()
                    tlv["value"]["ocr-resolution"] = self.buf.ru32()
                    tlv["value"]["timestamp-length"] = self.buf.ru8()
                    tlv["value"]["ocr-length"] = self.buf.ru8()
                    tlv["value"]["au-length"] = self.buf.ru8()
                    tlv["value"]["instant-bitrate-length"] = self.buf.ru8()
                    tlv["value"]["degradation-priority-length"] = self.buf.rb(4)
                    tlv["value"]["au-sequence-number"] = self.buf.rb(5)
                    tlv["value"]["packet-sequence-number-length"] = self.buf.rb(5)
                    tlv["value"]["reserved"] = self.buf.rb(2)

                    if tlv["value"]["duration-flag"]:
                        tlv["value"]["time-scale"] = self.buf.ru32()
                        tlv["value"]["access-unit-duration"] = self.buf.ru16()
                        tlv["value"]["composition-unit-duration"] = self.buf.ru16()

                    if not tlv["value"]["use-timestamps-flag"]:
                        tlv["value"]["start-decoding-timestamp"] = self.buf.rb(tlv["value"]["timestamp-length"])
                        tlv["value"]["start-comosition-timestamp"] = self.buf.rb(tlv["value"]["timestamp-length"])
            case _:
                tlv["unknown"] = True
                tlv["value"]["payload"] = self.buf.rh(self.buf.unit)

        self.buf.sapunit()

        return tlv


@module.register
class MatroskaModule(module.RuminantModule):
    desc = "Matroska files like WebM or MKV files."

    FIELDS = {
        0x00000027: ("Position", "uint"),
        0x00000067: ("Timestamp", "uint"),
        0x00000080: ("ChapterDisplay", "libmkv-workaround"),
        0x00000083: ("TrackType", "uint"),
        0x00000085: ("ChapString", "utf8"),
        0x00000086: ("CodecID", "ascii"),
        0x00000088: ("FlagDefault", "uint"),
        0x00000091: ("ChapterTimeStart", "uint"),
        0x00000092: ("ChapterTimeEnd", "uint"),
        0x00000098: ("ChapterFlagHidden", "uint"),
        0x0000009a: ("FlagInterlaced", "uint"),
        0x0000009c: ("FlagLacing", "uint"),
        0x0000009f: ("Channels", "uint"),
        0x000000a0: ("BlockGroup", "master"),
        0x000000a1: ("Block", "binary"),
        0x000000a3: ("SimpleBlock", "binary"),
        0x000000aa: ("CodecDecodeAll", "uint"),
        0x000000ae: ("TrackEntry", "master"),
        0x000000b0: ("PixelWidth", "uint"),
        0x000000b2: ("CueDuration", "uint"),
        0x000000b3: ("CueTime", "uint"),
        0x000000b5: ("SamplingFrequency", "float"),
        0x000000b6: ("ChapterAtom", "master"),
        0x000000b7: ("CueTrackPositions", "master"),
        0x000000b9: ("FlagEnabled", "uint"),
        0x000000ba: ("PixelHeight", "uint"),
        0x000000bb: ("CuePoint", "master"),
        0x000000bf: ("CRC-32", "hex"),
        0x000000d7: ("TrackNumber", "uint"),
        0x000000e0: ("Video", "master"),
        0x000000e1: ("Audio", "master"),
        0x000000e7: ("Timestamp", "uint"),
        0x000000ec: ("Void", "binary"),
        0x000000f0: ("CueRelativePosition", "uint"),
        0x000000f1: ("CueClusterPosition", "uint"),
        0x000000f7: ("CueTrack", "uint"),
        0x00004282: ("DocType", "ascii"),
        0x00004285: ("DocTypeReadVersion", "uint"),
        0x00004286: ("EBMLVersion", "uint"),
        0x00004287: ("DocTypeVersion", "uint"),
        0x000042f2: ("EBMLMaxIDLength", "uint"),
        0x000042f3: ("EBMLMaxSizeLength", "uint"),
        0x000042f7: ("EBMLReadVersion", "uint"),
        0x0000437c: ("ChapLanguage", "ascii"),
        0x0000437d: ("ChapLanguageBCP47", "ascii"),
        0x00004461: ("DateUTC", "date"),
        0x0000447a: ("TagLanguage", "ascii"),
        0x0000447b: ("TagLanguageBCP47", "ascii"),
        0x00004484: ("TadDefault", "uint"),
        0x00004487: ("TagString", "utf8"),
        0x00004489: ("Duration", "float"),
        0x00004598: ("ChapterFlagEnabled", "uint"),
        0x000045a3: ("TagName", "utf8"),
        0x000045b9: ("EditionEntry", "master"),
        0x000045bc: ("EditionUID", "uint"),
        0x000045bd: ("EditionFlagHidden", "uint"),
        0x000045db: ("EditionFlagDefault", "uint"),
        0x000045dd: ("EditionFlagOrdered", "uint"),
        0x0000465c: ("FileData", "blob"),
        0x00004660: ("FileMediaType", "ascii"),
        0x0000466e: ("FileName", "utf8"),
        0x000046ae: ("FileUID", "uint"),
        0x00004d80: ("MuxingApp", "utf8"),
        0x00004dbb: ("Seek", "master"),
        0x0000536e: ("Name", "utf8"),
        0x000053ab: ("SeekID", "hex"),
        0x000053ac: ("SeekPosition", "uint"),
        0x000053b8: ("VideoStereoMode", "uint"),
        0x000054b0: ("DisplayWidth", "uint"),
        0x000054b2: ("DisplayUnit", "uint"),
        0x000054ba: ("DisplayHeight", "uint"),
        0x000055aa: ("FlagForced", "uint"),
        0x000055ab: ("FlagHearingImpaired", "uint"),
        0x000055ac: ("FlagVisualImpaired", "uint"),
        0x000055ae: ("FlagOriginal", "uint"),
        0x000055b0: ("Colour", "master"),
        0x000055b1: ("MatrixCoefficients", "uint"),
        0x000055b7: ("ChromaSitingHorz", "uint"),
        0x000055b8: ("ChromaSitingVert", "uint"),
        0x000055b9: ("Range", "uint"),
        0x000055ba: ("TransferCharacteristics", "uint"),
        0x000055bb: ("Primaries", "uint"),
        0x000055ee: ("MaxBlockAdditionID", "uint"),
        0x000056aa: ("CodecDelay", "uint"),
        0x000056bb: ("SeekPreRoll", "uint"),
        0x00005741: ("WritingApp", "utf8"),
        0x000061a7: ("AttachedFile", "master"),
        0x00006264: ("BitDepth", "uint"),
        0x000063a2: ("CodecPrivate", "binary"),
        0x000063c0: ("Targets", "master"),
        0x000063c5: ("TagTrackUID", "uint"),
        0x000063ca: ("TargetType", "ascii"),
        0x000067c8: ("SimpleTarget", "master"),
        0x000068ca: ("TargetTypeValue", "uint"),
        0x00006de7: ("MinCache", "uint"),
        0x00007373: ("Tag", "master"),
        0x000073a4: ("SegmentUUID", "uuid"),
        0x000073c4: ("ChapterUID", "uint"),
        0x000073c5: ("TrackUID", "uint"),
        0x000075a2: ("DiscardPadding", "sint"),
        0x00007670: ("Projection", "master"),
        0x00007671: ("ProjectionType", "uint"),
        0x00007672: ("ProjectionPrivate", "binary"),
        0x000078b5: ("OutputSamplingFrequency", "float"),
        0x00007ba9: ("Title", "utf8"),
        0x0022b59c: ("Language", "utf8"),
        0x0022b59d: ("LanguageBCP47", "ascii"),
        0x0023314f: ("TrackTimestampScale", "float"),
        0x0023e383: ("DefaultDuration", "uint"),
        0x002ad7b1: ("TimestampScale", "uint"),
        0x1043a770: ("Chapters", "master"),
        0x114d9b74: ("SeekHead", "master"),
        0x1254c367: ("Tags", "master"),
        0x1549a966: ("Info", "master"),
        0x1654ae6b: ("Tracks", "master"),
        0x18538067: ("Segment", "master"),
        0x1941a469: ("Attachments", "master"),
        0x1a45dfa3: ("EMBL", "master"),
        0x1c53bb6b: ("Cues", "skipped-master"),
        0x1f43b675: ("Cluster", "skipped-master"),
    }

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"\x1a\x45\xdf\xa3"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "matroska"

        meta["tags"] = []
        while self.buf.available():
            meta["tags"].append(self.read_tag())

        with self.buf:
            meta["streams"] = []
            for segment in self.get(meta, ["Segment"]):
                meta["streams"].append(self.process_segment(segment))

        return meta

    def read_vint(self, m=True, signed=False):
        val = self.buf.ru8()

        mask = 0x80
        length = 1
        while length <= 8 and not (val & mask):
            mask >>= 1
            length += 1

        if length > 8:
            raise ValueError("VINT too long")

        if m:
            val &= mask - 1
        for _ in range(length - 1):
            val <<= 8
            val |= self.buf.ru8()

        if signed:
            val -= (2 ** (7 * length - 1)) - 1

        return val

    def read_tag(self, internal=False):
        offset = self.buf.tell()
        tag_id = self.read_vint(False)
        tag_length = self.read_vint()

        tag = {}
        tag["name"], tag["type"] = self.FIELDS.get(tag_id, (f"Unknown ({hex(tag_id)})", "unknown"))

        tag["offset"] = offset
        tag["length"] = tag_length

        self.buf.pushunit()
        self.buf.setunit(tag_length)

        match tag["type"]:
            case "sint":
                tag["data"] = int.from_bytes(self.buf.readunit(), "big", signed=True)
            case "uint":
                tag["data"] = int.from_bytes(self.buf.readunit(), "big")
            case "float":
                match tag_length:
                    case 0:
                        tag["data"] = 0.0
                    case 4:
                        tag["data"] = struct.unpack(">f", self.buf.read(4))[0]
                    case 8:
                        tag["data"] = struct.unpack(">d", self.buf.read(8))[0]
                    case _:
                        raise ValueError(f"Invalid float size {tag_length}")
            case "ascii":
                tag["data"] = self.buf.rs(tag_length, "ascii")
            case "utf8":
                tag["data"] = self.buf.rs(tag_length, "utf-8")
            case "date":
                tag["data"] = (
                    datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
                    + datetime.timedelta(microseconds=int.from_bytes(self.buf.readunit(), "big", signed=True) / 1000)
                ).isoformat()
            case "master" | "skipped-master":
                if internal or tag["type"] == "master":
                    if tag_length == 0:
                        self.buf.popunit()
                        self.buf.pushunit()

                    tag["data"] = []
                    while self.buf.unit > 0:
                        tag["data"].append(self.read_tag())
            case "hex":
                tag["data"] = self.buf.rh(tag_length)
            case "uuid":
                tag["data"] = utils.to_uuid(self.buf.read(tag_length))
            case "blob":
                with self.buf.sub(tag_length):
                    tag["data"] = chew(self.buf)

                self.buf.skip(tag_length)
            case "libmkv-workaround":
                # special case for old libmkv used by old HandBrake versions
                # was fixed in f8af3e4 upstream
                with self.buf:
                    is_libmkv = False
                    try:
                        self.read_vint()
                        assert self.read_vint() < tag_length
                    except Exception:
                        is_libmkv = True

                if is_libmkv:
                    tag["name"] = "MuxingApp"
                    tag["type"] = "ascii"
                    tag["data"] = self.buf.rs(tag_length, "ascii")
                else:
                    tag["type"] = "master"

                    if tag_length == 0:
                        self.buf.popunit()
                        self.buf.pushunit()

                    tag["data"] = []
                    while self.buf.unit > 0:
                        tag["data"].append(self.read_tag())
            case "binary":
                tag["data-offset"] = self.buf.tell()

        self.buf.skipunit()
        self.buf.popunit()

        return tag

    @staticmethod
    def get(root: dict, path: list[str]) -> list[dict]:
        if len(path) == 0:
            return [root]

        tags: list[dict] = []
        for tag in root["data" if "data" in root else "tags"]:
            if tag["name"] == path[0]:
                tags += MatroskaModule.get(tag, path[1:])

        return tags

    def process_segment(self, segment: dict) -> list[dict]:
        streams: list[dict] = []
        tracks = self.get(segment, ["Tracks", "TrackEntry"])

        codec_privates = {}
        for track in tracks:
            streams.append({
                "id": self.get(track, ["TrackNumber"])[0]["data"],
                "codec": self.get(track, ["CodecID"])[0]["data"],
            })

            try:
                codec_private = self.get(track, ["CodecPrivate"])[0]
                self.buf.seek(codec_private["data-offset"])
                codec_privates[self.get(track, ["TrackNumber"])[0]["data"]] = codec_private
            except IndexError:
                pass

        blocks = []
        sample_offsets: dict[int, list[int]] = {}
        sample_sizes: dict[int, list[int]] = {}

        for stream in streams:
            sample_offsets[stream["id"]] = []
            sample_sizes[stream["id"]] = []

        for cluster in self.get(segment, ["Cluster"]):
            self.buf.seek(cluster["offset"])

            cluster = self.read_tag(True)
            blocks += self.get(cluster, ["SimpleBlock"]) + self.get(cluster, ["BlockGroup", "SimpleBlock"])

        for block in blocks:
            self.buf.seek(block["data-offset"])
            self.buf.pasunit(block["length"])

            track_id = self.read_vint()
            self.buf.skip(2)
            lacing = (self.buf.ru8() & 0x06) >> 1

            match lacing:
                case 0b00:
                    sample_offsets[track_id].append(self.buf.tell())
                    sample_sizes[track_id].append(self.buf.unit if self.buf.unit is not None else 0)
                case 0b01:
                    count = self.buf.ru8() + 1
                    size = self.buf.unit // count if self.buf.unit is not None else 0

                    for i in range(0, count):
                        sample_offsets[track_id].append(self.buf.tell())
                        sample_sizes[track_id].append(size)
                        self.buf.skip(size)
                case 0b10:
                    count = self.buf.ru8() + 1

                    for i in range(0, count - 1):
                        size = 0
                        while True:
                            c = self.buf.ru8()
                            size += c

                            if c != 0xff:
                                break

                        sample_offsets[track_id].append(self.buf.tell())
                        sample_sizes[track_id].append(size)
                        self.buf.skip(size)

                    sample_offsets[track_id].append(self.buf.tell())
                    sample_sizes[track_id].append(self.buf.unit if self.buf.unit is not None else 0)
                case 0b11:
                    count = self.buf.ru8() + 1

                    last_size = None
                    for i in range(0, count - 1):
                        size = self.buf.read_vint(signed=True)

                        if last_size is not None:
                            size += last_size

                        last_size = size

                        sample_offsets[track_id].append(self.buf.tell())
                        sample_sizes[track_id].append(size)
                        self.buf.skip(size)

                    sample_offsets[track_id].append(self.buf.tell())
                    sample_sizes[track_id].append(self.buf.unit if self.buf.unit is not None else 0)

            self.buf.sapunit()

        for stream in streams:
            ranges: list[int] = utils.expand_ranges(secrets.get_parameter("0", stream, "ranges"), 0, len(sample_offsets) - 1)

            parsed: dict = {}
            nalu: dict = {}
            match stream["codec"]:
                case "V_MPEG4/ISO/AVC":
                    with self.buf:
                        self.buf.seek(codec_privates[stream["id"]]["data-offset"])
                        self.buf.pasunit(codec_privates[stream["id"]]["length"])

                        parsed["configuration-version"] = self.buf.ru8()
                        parsed["avc-profile-indication"] = self.buf.ru8()
                        parsed["profile-compatibility"] = self.buf.ru8()
                        parsed["avc-level-indication"] = self.buf.ru8()
                        parsed["reserved1"] = self.buf.rb(6)
                        parsed["length-size-minus-one"] = self.buf.rb(2)
                        parsed["reserved2"] = self.buf.rb(3)
                        parsed["sequence-parameter-set-count"] = self.buf.rb(5)

                        parsed["sequence-parameter-sets"] = []
                        for i in range(0, parsed["sequence-parameter-set-count"]):
                            self.buf.pasunit(self.buf.ru16())
                            parsed["sequence-parameter-sets"].append(FFMpreg.read_h264_nalu(self.buf))
                            self.buf.sapunit()

                        parsed["picture-parameter-set-count"] = self.buf.ru8()
                        parsed["picture-parameter-sets"] = []
                        for i in range(0, parsed["picture-parameter-set-count"]):
                            self.buf.pasunit(self.buf.ru16())
                            parsed["picture-parameter-sets"].append(FFMpreg.read_h264_nalu(self.buf))
                            self.buf.sapunit()

                        if (
                            parsed["avc-profile-indication"] in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135)
                            and self.buf.hasunit()
                        ):
                            parsed["reserved3"] = self.buf.rb(6)
                            parsed["chroma-format-idc"] = self.buf.rb(2)
                            parsed["reserved4"] = self.buf.rb(5)
                            parsed["bit-depth-luma-minus-eight"] = self.buf.rb(3)
                            parsed["reserved5"] = self.buf.rb(5)
                            parsed["bit-depth-chroma-minus-eight"] = self.buf.rb(3)
                            parsed["sequence-parameter-set-ext-count"] = self.buf.rb(5)

                            parsed["sequence-parameter-ext-sets"] = []
                            for i in range(0, parsed["sequence-parameter-set-ext-count"]):
                                self.buf.pasunit(self.buf.ru16())
                                parsed["sequence-parameter-ext-sets"].append(FFMpreg.read_h264_nalu(self.buf))
                                self.buf.sapunit()

                        codec_privates[stream["id"]]["parsed"] = parsed
                        self.buf.sapunit()

                    nal_length_size = parsed["length-size-minus-one"] + 1
                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        stream["samples"][index] = []
                        while self.buf.hasunit():
                            nalu = {}
                            nalu["length"] = int.from_bytes(self.buf.read(nal_length_size), "big")

                            self.buf.pasunit(nalu["length"])

                            nalu["payload"] = FFMpreg.read_h264_nalu(self.buf, slim=True)

                            self.buf.sapunit()

                            stream["samples"][index].append(nalu)

                        self.buf.sapunit()
                case "V_MPEGH/ISO/HEVC":
                    with self.buf:
                        self.buf.seek(codec_privates[stream["id"]]["data-offset"])
                        self.buf.pasunit(codec_privates[stream["id"]]["length"])

                        parsed["configuration-version"] = self.buf.ru8()

                        parsed["general-profile-space"] = self.buf.rb(2)
                        parsed["general-tier-flag"] = self.buf.rb(1)
                        parsed["general-profile-idc"] = self.buf.rb(5)

                        parsed["profile-compatibility-flags"] = self.buf.ru32()
                        parsed["constraint-indicator-flags"] = self.buf.ru48()
                        parsed["level-idc"] = self.buf.ru8()
                        parsed["min-spatial-segmentation-idc"] = self.buf.ru16()
                        parsed["parallelism-type"] = self.buf.ru8()
                        parsed["chroma-format"] = self.buf.ru8()
                        parsed["reserved1"] = self.buf.rb(5)
                        parsed["bit-depth-luma-minus8"] = self.buf.rb(3)
                        parsed["reserved2"] = self.buf.rb(5)
                        parsed["bit-depth-chroma-minus8"] = self.buf.rb(3)
                        parsed["avg-frame-rate"] = self.buf.rfp16()

                        parsed["constant-frame-rate"] = self.buf.rb(2)
                        parsed["num-temporal-layers"] = self.buf.rb(3)
                        parsed["temporal-id-nested"] = self.buf.rb(1)
                        parsed["length-size-minus-one"] = self.buf.rb(2)

                        parsed["array-count"] = self.buf.ru8()

                        parsed["arrays"] = []
                        for i in range(0, parsed["array-count"]):
                            array = {}
                            array["array-completeness"] = self.buf.rb(1)
                            array["reserved"] = self.buf.rb(1)
                            array["nal-unit-type"] = utils.unraw(
                                self.buf.rb(6),
                                1,
                                FFMpreg.H265_NAL_UNIT_TYPES,
                                True,
                            )
                            array["nalu-count"] = self.buf.ru16()
                            array["nalus"] = []
                            for j in range(0, array["nalu-count"]):
                                entry: dict = {}
                                entry["nalu-length"] = self.buf.ru16()

                                self.buf.pasunit(entry["nalu-length"])

                                entry["nalu"] = FFMpreg.read_h265_nalu(self.buf)

                                self.buf.sapunit()

                                array["nalus"].append(entry)

                            parsed["arrays"].append(array)

                        codec_privates[stream["id"]]["parsed"] = parsed
                        self.buf.sapunit()

                    nal_length_size = parsed["length-size-minus-one"] + 1
                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        stream["samples"][index] = []
                        while self.buf.hasunit():
                            nalu = {}
                            nalu["length"] = int.from_bytes(self.buf.read(nal_length_size), "big")

                            self.buf.pasunit(nalu["length"])

                            nalu["payload"] = FFMpreg.read_h265_nalu(self.buf)

                            self.buf.sapunit()

                            stream["samples"][index].append(nalu)

                        self.buf.sapunit()
                case "A_FLAC":
                    with self.buf:
                        self.buf.seek(codec_privates[stream["id"]]["data-offset"])
                        self.buf.pasunit(codec_privates[stream["id"]]["length"])

                        with self.buf.subunit():
                            codec_privates[stream["id"]]["parsed"] = chew(self.buf)

                        self.buf.sapunit()

                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        stream["samples"][index] = chew(self.buf, blob_mode=True)

                        self.buf.sapunit()
                case "V_AV1":
                    with self.buf:
                        self.buf.seek(codec_privates[stream["id"]]["data-offset"])
                        self.buf.pasunit(codec_privates[stream["id"]]["length"])

                        temp = self.buf.ru8()
                        parsed["version"] = temp & 0x7f
                        temp = self.buf.ru8()
                        parsed["seq-profile"] = temp >> 5
                        parsed["seq-level-idx-0"] = temp & 0x1f
                        temp = self.buf.ru8()
                        parsed["seq-tier-0"] = bool(temp & 0x80)
                        parsed["high-bitdepth"] = bool(temp & 0x40)
                        parsed["twelve-bit"] = bool(temp & 0x20)
                        parsed["monochrome"] = bool(temp & 0x10)
                        parsed["chroma-subsampling-x"] = bool(temp & 0x08)
                        parsed["chroma-subsampling-y"] = bool(temp & 0x04)
                        parsed["chroma-sample-position"] = temp & 0x03
                        temp = self.buf.ru8()
                        parsed["reserved"] = temp >> 5
                        parsed["initial-presentation-delay-present"] = bool(temp & 0x10)
                        parsed["initial-presentation-delay-minus-one"] = temp & 0x0f

                        parsed["obus"] = []
                        while self.buf.hasunit():
                            parsed["obus"].append(FFMpreg.read_av1_obu(self.buf))

                        codec_privates[stream["id"]]["parsed"] = parsed
                        self.buf.sapunit()

                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        stream["samples"][index] = []
                        while self.buf.hasunit():
                            stream["samples"][index].append(FFMpreg.read_av1_obu(self.buf))

                        self.buf.sapunit()
                case "V_DIRAC":
                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        with self.buf.subunit():
                            stream["samples"][index] = chew(self.buf)

                        self.buf.sapunit()
                case "A_OPUS":
                    with self.buf:
                        self.buf.seek(codec_privates[stream["id"]]["data-offset"])
                        self.buf.pasunit(codec_privates[stream["id"]]["length"])

                        self.buf.skip(8)
                        parsed["version"] = self.buf.ru8()
                        channel_count = self.buf.ru8()
                        parsed["channel-count"] = channel_count
                        parsed["pre-skip"] = self.buf.ru16l()
                        parsed["input-sample-rate"] = self.buf.ru32l()
                        parsed["output-gain"] = self.buf.ri16() / 256
                        mapping = self.buf.ru8()
                        parsed["channel-mapping"] = mapping

                        if mapping > 0:
                            parsed["stream-count"] = self.buf.ru8()
                            parsed["coupled-count"] = self.buf.ru8()
                            parsed["channel-mapping-table"] = [self.buf.ru8() for i in range(0, channel_count)]

                        codec_privates[stream["id"]]["parsed"] = parsed
                        self.buf.sapunit()

                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        with self.buf.subunit():
                            stream["samples"][index] = chew(self.buf, blob_mode=True)

                        self.buf.sapunit()
                case "V_PRORES":
                    with self.buf:
                        self.buf.seek(codec_privates[stream["id"]]["data-offset"])
                        self.buf.pasunit(codec_privates[stream["id"]]["length"])

                        parsed["fourcc"] = self.buf.rs(4)

                        codec_privates[stream["id"]]["parsed"] = parsed
                        self.buf.sapunit()

                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        sample = {}
                        sample["header-length"] = self.buf.ru16()
                        sample["version"] = self.buf.ru8()
                        sample["reserved1"] = self.buf.ru8()
                        sample["creator"] = self.buf.rs(4)
                        sample["width"] = self.buf.ru16()
                        sample["height"] = self.buf.ru16()
                        sample["chroma-format"] = utils.unraw(
                            self.buf.ru8(),
                            1,
                            {
                                0x80: "4:2:2 Progressive",
                                0x84: "4:2:2 Interlaced (Top Field First)",
                                0x88: "4:2:2 Interlaced (Bottom Field First)",
                                0xc0: "4:4:4 Progressive",
                                0xc4: "4:4:4 Interlaced (Top Field First)",
                                0xc8: "4:4:4 Interlaced (Bottom Field First)",
                            },
                            True,
                        )
                        sample["aspect-ratio"] = utils.unraw(
                            self.buf.ru8(),
                            1,
                            {
                                0x00: "Unspecified",
                                0x01: "1:1 (Square Pixels)",
                                0x02: "4:3",
                                0x03: "16:9",
                            },
                            True,
                        )
                        sample["color-primaries"] = utils.unraw(
                            self.buf.ru8(),
                            1,
                            {
                                0x00: "Reserved",
                                0x01: "ITU-R BT.709",
                                0x02: "Unspecified",
                                0x04: "ITU-R BT.470 System M",
                                0x05: "ITU-R BT.470 System B, G",
                                0x06: "SMPTE 170M / ITU-R BT.601",
                                0x07: "SMPTE 240M",
                                0x08: "Generic Film (Illuminant C)",
                                0x09: "ITU-R BT.2020 / BT.2100",
                                0x0a: "SMPTE ST 428-1 (CIE 1931 XYZ)",
                                0x0b: "DCI-P3 (SMPTE RP 431-2)",
                                0x0c: "P3-D65 (SMPTE EG 432-1)",
                                0x16: "EBU Tech. 3213-E",
                            },
                            True,
                        )
                        sample["transfer-function"] = utils.unraw(
                            self.buf.ru8(),
                            1,
                            {
                                0x00: "Reserved",
                                0x01: "ITU-R BT.709",
                                0x02: "Unspecified",
                                0x04: "Gamma 2.2 Curve",
                                0x05: "Gamma 2.8 Curve",
                                0x06: "SMPTE 170M / ITU-R BT.601",
                                0x07: "SMPTE 240M",
                                0x08: "Linear",
                                0x09: "Logarithmic (100:1 range)",
                                0x0a: "Logarithmic (316.22777:1 range)",
                                0x0b: "IEC 61966-2-4",
                                0x0c: "ITU-R BT.1361 Extended Gamut",
                                0x0d: "IEC 61966-2-1 (sRGB)",
                                0x0e: "ITU-R BT.2020 (10-bit)",
                                0x0f: "ITU-R BT.2020 (12-bit)",
                                0x10: "SMPTE ST 2084 (PQ / HDR10)",
                                0x11: "SMPTE ST 428-1",
                                0x12: "ARIB STD-B67 (HLG)",
                            },
                            True,
                        )
                        sample["matrix-coefficients"] = utils.unraw(
                            self.buf.ru8(),
                            1,
                            {
                                0x00: "Identity / GBR",
                                0x01: "ITU-R BT.709",
                                0x02: "Unspecified",
                                0x04: "FCC Title 47 CFR 73.682",
                                0x05: "ITU-R BT.470 System B, G / BT.601 PAL",
                                0x06: "SMPTE 170M / ITU-R BT.601 NTSC",
                                0x07: "SMPTE 240M",
                                0x08: "YCgCo",
                                0x09: "ITU-R BT.2020 Non-constant Luminance",
                                0x0a: "ITU-R BT.2020 Constant Luminance",
                                0x0b: "SMPTE ST 2085",
                                0x0c: "Chromaticity-derived Non-constant Luminance",
                                0x0d: "Chromaticity-derived Constant Luminance",
                                0x0e: "ICtCp",
                            },
                            True,
                        )
                        sample["alpha-channel"] = utils.unraw(
                            self.buf.ru8(),
                            1,
                            {
                                0x00: "None",
                                0x01: "8-bit",
                                0x02: "16-bit",
                            },
                            True,
                        )
                        sample["reserved2"] = self.buf.ru8()
                        sample["quantization-flags"] = self.buf.ru8()
                        sample["luma-qmat"] = self.buf.rh(64)
                        sample["chroma-qmat"] = self.buf.rh(64)

                        stream["samples"][index] = sample

                        self.buf.sapunit()
                case "V_MPEGI/ISO/VVC":
                    with self.buf:
                        self.buf.seek(codec_privates[stream["id"]]["data-offset"])
                        self.buf.pasunit(codec_privates[stream["id"]]["length"])

                        parsed["reserved1"] = self.buf.rb(5)
                        parsed["length-size-minus-one"] = self.buf.rb(2)
                        parsed["ptl-present"] = self.buf.rb(1)

                        if parsed["ptl-present"]:
                            parsed["ols-idx"] = self.buf.rb(9)
                            parsed["sublayers-count"] = self.buf.rb(3)
                            parsed["constant-frame-rate"] = self.buf.rb(2)
                            parsed["chroma-format-idc"] = self.buf.rb(2)
                            parsed["bit-depth-minus-eight"] = self.buf.rb(3)
                            parsed["reserved2"] = self.buf.rb(5)
                            parsed["general-profile-idc"] = self.buf.rb(7)
                            parsed["general-tier-flag"] = self.buf.rb(1)
                            parsed["general-level-idc"] = self.buf.rb(8)
                            parsed["ptl-frame-only-constraint-flag"] = self.buf.rb(1)
                            parsed["ptl-multi-layer-enabled-flag"] = self.buf.rb(1)
                            parsed["general-constraint-info-bytes"] = self.buf.rb(6)
                            parsed["general-constraint-info"] = self.buf.rh(parsed["general-constraint-info-bytes"])

                            if parsed["sublayers-count"] > 1:
                                temp = self.buf.rb(parsed["sublayers-count"] - 1)
                                self.buf.align()
                                parsed["ptl-sublayer-level-present-flag"] = temp
                                parsed["sublayer-level-idc"] = self.buf.rh(temp.bit_count())

                            parsed["ptl-sub-profile-count"] = self.buf.ru8()
                            parsed["ptl-sub-profiles"] = self.buf.rh(parsed["ptl-sub-profile-count"] * 4)

                        parsed["max-picture-width"] = self.buf.ru16()
                        parsed["max-picture-height"] = self.buf.ru16()
                        parsed["avg-frame-rate"] = self.buf.ru16() / 256

                        parsed["array-count"] = self.buf.ru8()
                        parsed["arrays"] = []
                        for i in range(0, parsed["array-count"]):
                            array = {}
                            array["completeness"] = self.buf.rb(1)
                            array["reserved"] = self.buf.rb(2)
                            array["type"] = utils.unraw(self.buf.rb(5), 1, FFMpreg.H265_NAL_UNIT_TYPES, True)

                            array["nalu-count"] = self.buf.ru16()
                            array["nalus"] = []
                            for i in range(0, array["nalu-count"]):
                                self.buf.pasunit(self.buf.ru16())

                                array["nalus"].append(FFMpreg.read_h266_nalu(self.buf))

                                self.buf.sapunit()

                            parsed["arrays"].append(array)

                        codec_privates[stream["id"]]["parsed"] = parsed
                        self.buf.sapunit()

                    nal_length_size = parsed["length-size-minus-one"] + 1
                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        stream["samples"][index] = []
                        while self.buf.hasunit():
                            nalu = {}
                            nalu["length"] = int.from_bytes(self.buf.read(nal_length_size), "big")

                            self.buf.pasunit(nalu["length"])

                            nalu["payload"] = FFMpreg.read_h266_nalu(self.buf)

                            self.buf.sapunit()

                            stream["samples"][index].append(nalu)

                        self.buf.sapunit()
                case "A_VORBIS" | "V_THEORA":
                    with self.buf:
                        self.buf.seek(codec_privates[stream["id"]]["data-offset"])
                        self.buf.pasunit(codec_privates[stream["id"]]["length"])

                        parsed["header-count"] = self.buf.ru8() + 1

                        parsed["headers"] = []
                        for i in range(0, parsed["header-count"] - 1):
                            header = {}

                            length = 0
                            while True:
                                c = self.buf.ru8()
                                length += c

                                if c != 0xff:
                                    break

                            header["length"] = length

                            parsed["headers"].append(header)

                        parsed["headers"].append({"length": self.buf.unit - sum([x["length"] for x in parsed["headers"]])})

                        for header in parsed["headers"]:
                            self.buf.pasunit(header["length"])

                            typ = self.buf.ru8()
                            header["type"] = utils.unraw(
                                typ,
                                1,
                                {0x01: "Id", 0x03: "Comment", 0x05: "Setup", 0x80: "Id", 0x81: "Comment", 0x82: "Setup"},
                                True,
                            )
                            self.buf.skip(6)

                            match typ:
                                case 0x01:
                                    header["version"] = self.buf.ru32l()
                                    header["channel-count"] = self.buf.ru8()
                                    header["sample-rate"] = self.buf.ru32l()
                                    header["bitrate-maximum"] = self.buf.ru32l()
                                    header["bitrate-nominal"] = self.buf.ru32l()
                                    header["bitrate-minimum"] = self.buf.ru32l()
                                    temp = self.buf.ru8()
                                    header["blocksize-small"] = 2 ** (temp & 0x03)
                                    header["blocksize-large"] = 2 ** (temp >> 4)
                                    header["framing-flag"] = self.buf.ru8()
                                case 0x03 | 0x81:
                                    header["vendor-string"] = self.buf.rs(self.buf.ru32l())

                                    header["user-strings"] = []
                                    for i in range(0, self.buf.ru32l()):
                                        header["user-strings"].append(self.buf.rs(self.buf.ru32l()))

                                    if self.buf.hasunit():
                                        header["framing-flag"] = self.buf.ru8()
                                case 0x80:
                                    header["version"] = f"{self.buf.ru8()}.{self.buf.ru8()}.{self.buf.ru8()}"
                                    header["frame-width"] = self.buf.ru16()
                                    header["frame-height"] = self.buf.ru16()
                                    header["pic-width"] = self.buf.ru24()
                                    header["pic-height"] = self.buf.ru24()
                                    header["pic-x"] = self.buf.ru8()
                                    header["pic-y"] = self.buf.ru8()
                                    header["framerate"] = self.buf.ru32() / self.buf.ru32()

                                    a = self.buf.ru24l()
                                    b = self.buf.ru24l()
                                    header["aspect"] = {
                                        "a": a,
                                        "b": b,
                                        "rational-approximation": a / b if b != 0 else None,
                                    }

                                    header["colorspace"] = self.buf.ru8()
                                    header["pixel-fmt-flags"] = self.buf.ru8()
                                    header["target-bitrate"] = self.buf.ru24l()
                                    header["quality"] = self.buf.ru8()
                                    if self.buf.hasunit():
                                        header["keyframe-granule-shift"] = self.buf.ru8()
                                        header["pixel-fmt-flags2"] = self.buf.ru8()
                                case 0x05 | 0x82:
                                    pass
                                case _:
                                    header["unknown"] = True

                            self.buf.sapunit()

                        codec_privates[stream["id"]]["parsed"] = parsed
                        self.buf.sapunit()

                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        with self.buf.subunit():
                            stream["samples"][index] = chew(self.buf, blob_mode=True)

                        self.buf.sapunit()
                case _:
                    if stream["id"] in codec_privates:
                        with self.buf:
                            self.buf.seek(codec_privates[stream["id"]]["data-offset"])
                            self.buf.pasunit(codec_privates[stream["id"]]["length"])

                            with self.buf.subunit():
                                stream["codec-private"] = chew(self.buf, blob_mode=True)

                            self.buf.sapunit()

                    stream["samples"] = {}

                    for index in ranges:
                        self.buf.seek(sample_offsets[stream["id"]][index])
                        self.buf.pasunit(sample_sizes[stream["id"]][index])

                        with self.buf.subunit():
                            stream["samples"][index] = chew(self.buf, blob_mode=True)

                        self.buf.sapunit()

                    stream["unknown"] = True

        return streams


@module.register
class OggModule(module.RuminantModule):
    desc = "Ogg files like OGG or OGV files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"OggS"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "ogg"

        meta["packets"] = []

        slacks = {}
        streams = []
        while self.buf.peek(4) == b"OggS":
            self.buf.skip(4)
            assert self.buf.ru8() == 0, "broken Ogg page"

            flags = self.buf.ru8()
            self.buf.skip(8)
            stream_id = self.buf.ru32l()
            self.buf.skip(8)

            if stream_id not in streams:
                streams.append(stream_id)

            if flags & 0x04 and stream_id in streams:
                streams.remove(stream_id)

            segment_count = self.buf.ru8()

            for length in [self.buf.ru8() for i in range(0, segment_count)]:
                if stream_id not in slacks:
                    slacks[stream_id] = b""

                slacks[stream_id] += self.buf.read(length)

                if length != 255:
                    self.process_packet(Buf(slacks[stream_id]), stream_id, meta)
                    slacks[stream_id] = b""

        return meta

    def process_packet(self, buf, stream_id, meta):
        packet = {}
        packet["stream-id"] = stream_id
        packet["codec"] = None
        packet["type"] = None
        packet["data"] = {}

        if buf.peek(7) == b"\x01vorbis":
            buf.skip(7)
            packet["codec"] = "vorbis"
            packet["type"] = "id"

            packet["data"]["version"] = buf.ru32l()
            packet["data"]["channel-count"] = buf.ru8()
            packet["data"]["sample-rate"] = buf.ru32l()
            packet["data"]["bitrate-maximum"] = buf.ru32l()
            packet["data"]["bitrate-nominal"] = buf.ru32l()
            packet["data"]["bitrate-minimum"] = buf.ru32l()
            temp = buf.ru8()
            packet["data"]["blocksize-small"] = 2 ** (temp & 0x03)
            packet["data"]["blocksize-large"] = 2 ** (temp >> 4)
            packet["data"]["framing-flag"] = buf.ru8()
        elif buf.peek(7) == b"\x03vorbis":
            buf.skip(7)
            packet["codec"] = "vorbis"
            packet["type"] = "comment"

            packet["data"]["vendor-string"] = buf.rs(buf.ru32l())

            packet["data"]["user-strings"] = []
            for i in range(0, buf.ru32l()):
                packet["data"]["user-strings"].append(buf.rs(buf.ru32l()))

            packet["data"]["framing-flag"] = buf.ru8()
        elif buf.peek(7) == b"\x05vorbis":
            buf.skip(7)
            packet["codec"] = "vorbis"
            packet["type"] = "setup"
        elif buf.peek(8) == b"OpusHead":
            buf.skip(8)
            packet["codec"] = "opus"
            packet["type"] = "head"

            packet["data"]["version"] = buf.ru8()
            channel_count = buf.ru8()
            packet["data"]["channel-count"] = channel_count
            packet["data"]["pre-skip"] = buf.ru16l()
            packet["data"]["input-sample-rate"] = buf.ru32l()
            packet["data"]["output-gain"] = buf.ri16() / 256
            mapping = buf.ru8()
            packet["data"]["channel-mapping"] = mapping

            if mapping > 0:
                packet["data"]["stream-count"] = buf.ru8()
                packet["data"]["coupled-count"] = buf.ru8()
                packet["data"]["channel-mapping-table"] = [buf.ru8() for i in range(0, channel_count)]
        elif buf.peek(8) == b"OpusTags":
            buf.skip(8)
            packet["codec"] = "opus"
            packet["type"] = "tags"

            packet["data"]["vendor-string"] = buf.rs(buf.ru32l())

            packet["data"]["user-strings"] = []
            for i in range(0, buf.ru32l()):
                packet["data"]["user-strings"].append(buf.rs(buf.ru32l()))
        elif buf.peek(7) == b"\x80theora":
            buf.skip(7)
            packet["codec"] = "theora"
            packet["type"] = "id"

            packet["data"]["version"] = f"{buf.ru8()}.{buf.ru8()}.{buf.ru8()}"
            packet["data"]["frame-width"] = buf.ru16()
            packet["data"]["frame-height"] = buf.ru16()
            packet["data"]["pic-width"] = buf.ru24()
            packet["data"]["pic-height"] = buf.ru24()
            packet["data"]["pic-x"] = buf.ru8()
            packet["data"]["pic-y"] = buf.ru8()
            packet["data"]["framerate"] = buf.ru32() / buf.ru32()

            a = buf.ru24l()
            b = buf.ru24l()
            packet["data"]["aspect"] = {
                "a": a,
                "b": b,
                "rational-approximation": a / b if b != 0 else None,
            }

            packet["data"]["colorspace"] = buf.ru8()
            packet["data"]["pixel-fmt-flags"] = buf.ru8()
            packet["data"]["target-bitrate"] = buf.ru24l()
            packet["data"]["quality"] = buf.ru8()
            if buf.available() > 0:
                packet["data"]["keyframe-granule-shift"] = buf.ru8()
                packet["data"]["pixel-fmt-flags2"] = buf.ru8()
        elif buf.peek(7) == b"\x81theora":
            buf.skip(7)
            packet["codec"] = "theora"
            packet["type"] = "comment"

            packet["data"]["vendor-string"] = buf.rs(buf.ru32l())

            packet["data"]["user-strings"] = []
            for i in range(0, buf.ru32l()):
                packet["data"]["user-strings"].append(buf.rs(buf.ru32l()))
        elif buf.peek(7) == b"\x82theora":
            buf.skip(7)
            packet["codec"] = "theora"
            packet["type"] = "setup"
        else:
            return

        meta["packets"].append(packet)


@module.register
class MpegTsModule(module.RuminantModule):
    desc = "MPEG transport stream files like the ones served on the web by M3U8 playlists."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        if buf.available() < 188:
            return False
        if buf.available() == 188:
            return buf.peek(1) == b"\x47"
        elif buf.available() == 204:
            return buf.peek(1) == b"\x47" and buf.peek(189)[-1] != b"\x47"
        else:
            return buf.peek(1) == b"\x47" and (buf.peek(189)[-1] == 0x47 or buf.peek(205)[-1] == 0x47)

    def read_descriptors(self, buf):
        descs = []

        while buf.unit > 0:
            desc = {}
            desc["tag"] = buf.ru8()
            desc["type"] = "unknown"
            desc["length"] = buf.ru8()
            desc["data"] = {}

            buf.pushunit()
            buf.setunit(desc["length"])

            match desc["tag"]:
                case 0x48:
                    desc["type"] = "Service Descriptor"
                    desc["data"]["service-type"] = utils.unraw(buf.ru8(), 1, {1: "Digital TV", 2: "Radio"})
                    desc["data"]["provider"] = buf.rs(buf.ru8())
                    desc["data"]["service"] = buf.rs(buf.ru8())
                case 0x0a:
                    desc["type"] = "Language"
                    desc["data"]["language"] = buf.rs(3)
                    desc["data"]["audio-type"] = utils.unraw(
                        buf.ru8(),
                        1,
                        {
                            0: "Undefined",
                            1: "Main audio",
                            2: "Commentary",
                            3: "Karaoke",
                        },
                    )
                case 0x25 | 0x26:
                    if buf.peek(2) == b"\xff\xff":
                        desc["type"] = "Twitch ID3"
                    else:
                        desc["payload"] = buf.rh(buf.unit)
                        desc["unknown"] = True
                case _:
                    desc["payload"] = buf.rh(buf.unit)
                    desc["unknown"] = True

            buf.skipunit()
            buf.popunit()

            descs.append(desc)

        return descs

    def process(self, pid, buf):
        chunk = {}
        chunk["pid"] = pid
        chunk["length"] = buf.available()
        chunk["type"] = "unknown"
        chunk["data"] = {}

        if pid in (0x0000, 0x0011) or pid in self.programs:
            chunk["type"] = {0x0011: "sdt", 0x0000: "pat"}.get(pid, "pmt")

            del chunk["data"]
            chunk["psi"] = {}
            chunk["data"] = {}
            chunk["psi"]["table-id"] = buf.ru8()
            temp = buf.ru16()
            chunk["psi"]["fixed"] = temp >> 12

            chunk["psi"]["section-length"] = temp & 0x0fff
            buf.pushunit()
            buf.setunit(chunk["psi"]["section-length"] - 4)

            chunk["psi"]["transport-stream-id"] = buf.ru16()
            temp = buf.ru8()
            chunk["psi"]["reserved1"] = temp >> 6
            chunk["psi"]["version"] = (temp >> 1) & 0x1f
            chunk["psi"]["cni"] = bool(temp & 0x01)
            chunk["psi"]["section-number"] = buf.ru8()
            chunk["psi"]["last-section-number"] = buf.ru8()
            chunk["psi"]["crc-32"] = None

            match pid:
                case 0x0011:
                    chunk["data"]["original-network-id"] = buf.ru16()
                    chunk["data"]["reserved2"] = buf.ru8()

                    chunk["data"]["programs"] = []
                    while buf.unit > 0:
                        program = {}
                        program["service-id"] = buf.ru16()
                        eit = buf.ru8()
                        program["eit"] = {
                            "reserved": eit >> 2,
                            "schedule": bool(eit & 0x02),
                            "present-or-following": bool(eit & 0x01),
                        }
                        temp = buf.ru16()
                        program["running-status"] = utils.unraw(
                            (temp >> 13) & 0x07,
                            1,
                            {0: "Undefined", 1: "Not running", 4: "Running"},
                        )
                        program["scrambled"] = bool(temp & 0x1000)
                        program["descriptor-length"] = temp & 0x0fff

                        buf.pushunit()
                        buf.setunit(temp & 0x0fff)

                        program["descriptors"] = self.read_descriptors(buf)

                        buf.skipunit()
                        buf.popunit()

                        chunk["data"]["programs"].append(program)
                case 0x0000:
                    chunk["data"]["programs"] = []
                    while buf.unit > 0:
                        program = {}
                        program["program-number"] = buf.ru16()
                        program["pid"] = buf.ru16() & 0x1fff

                        self.programs[program["pid"]] = program["program-number"]

                        chunk["data"]["programs"].append(program)
                case _:
                    chunk["data"]["program-id"] = self.programs[pid]
                    temp = buf.ru16()
                    chunk["data"]["reserved"] = temp >> 13
                    chunk["data"]["pcr-id"] = temp & 0x1fff
                    chunk["data"]["program-length"] = buf.ru16() & 0x0fff

                    buf.pushunit()
                    buf.setunit(chunk["data"]["program-length"])

                    chunk["data"]["programs"] = self.read_descriptors(buf)

                    buf.skipunit()
                    buf.popunit()

                    chunk["data"]["elementary-streams"] = []
                    while buf.unit > 0:
                        es = {}
                        es["type"] = utils.unraw(
                            buf.ru8(),
                            1,
                            {
                                2: "MPEG-2 video",
                                3: "MPEG-1 audio",
                                15: "AAC audio",
                                21: "ID3 metadata",
                                27: "H.264 video",
                            },
                        )
                        es["pid"] = buf.ru16() & 0x1fff
                        self.es[es["pid"]] = es["type"]["raw"]
                        es["descriptor-length"] = buf.ru16() & 0x0fff

                        buf.pushunit()
                        buf.setunit(es["descriptor-length"])

                        es["descriptors"] = self.read_descriptors(buf)

                        buf.skipunit()
                        buf.popunit()

                        chunk["data"]["elementary-streams"].append(es)

            buf.skipunit()
            buf.popunit()

            chunk["psi"]["crc-32"] = buf.rh(4)
        else:
            chunk["unknown"] = True

        return chunk

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "mpeg-ts"
        meta["chunks"] = []

        self.programs: dict = {}
        self.es: dict = {}
        slack: dict = {}
        starts: dict = {}

        index = 0
        while self.buf.peek(1) == b"\x47":
            self.buf.skip(1)
            index += 1

            temp = self.buf.ru16()
            pusi = bool(temp & 0x4000)
            pid = temp & 0x1fff

            left = 184
            if self.buf.ru8() & 0x20:
                to_skip = self.buf.ru8()
                self.buf.skip(to_skip)
                left -= to_skip + 1

            if pid not in slack:
                slack[pid] = b""

            if pusi:
                offset = self.buf.ru8() + 1
                self.buf.skip(offset - 1)

                if len(slack[pid]):
                    chunk = self.process(pid, Buf(slack[pid]))
                    chunk["index"] = starts.get(pid, 0)
                    chunk["blob"] = slack[pid]
                    meta["chunks"].append(chunk)

                slack[pid] = self.buf.read(left - offset)
                starts[pid] = index
            else:
                slack[pid] += self.buf.read(left)

            if self.buf.peek(1) != b"\x47" and self.buf.available() > 16 and self.buf.peek(17)[-1] == b"\x47":
                self.buf.skip(16)

        for key, value in slack.items():
            chunk = self.process(key, Buf(value))
            chunk["index"] = starts[key]
            chunk["blob"] = value
            meta["chunks"].append(chunk)

        meta["chunks"].sort(key=lambda x: x["index"])
        for chunk in meta["chunks"]:
            if chunk["pid"] in self.es:
                del chunk["unknown"]

                match self.es[chunk["pid"]]:
                    case 21:
                        chunk["type"] = "id3"

                        blob = chunk["blob"]
                        while blob[:3] != b"ID3":
                            blob = blob[1:]

                        chunk["data"] = chew(blob)
                    case _:
                        chunk["type"] = "es"

            del chunk["index"]
            del chunk["blob"]

        return meta


@module.register
class AsfModule(module.RuminantModule):
    desc = "Advanced Systems Format files like WMA or WMV files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.available() > 16 and buf.pguid() == "75b22630-668e-11cf-a6d9-00aa0062ce6c"

    def read_object(self):
        obj = {}

        obj["uuid"] = self.buf.rguid()
        obj["offset"] = self.buf.tell() - 16
        obj["length"] = self.buf.ru64l()

        self.buf.pushunit()
        self.buf.setunit(obj["length"] - 24)

        obj["name"] = "Unknown"
        obj["data"] = {}
        match obj["uuid"]:
            case "75b22630-668e-11cf-a6d9-00aa0062ce6c":
                obj["name"] = "Header"
                obj["data"]["subobject-count"] = self.buf.ru32l()
                obj["data"]["reserved1"] = self.buf.ru8()
                obj["data"]["reserved2"] = self.buf.ru8()

                obj["data"]["subobjects"] = []
                for i in range(0, obj["data"]["subobject-count"]):
                    obj["data"]["subobjects"].append(self.read_object())
            case "8cabdca1-a947-11cf-8ee4-00c00c205365":
                obj["name"] = "File Properties"
                obj["data"]["file-guid"] = self.buf.rguid()
                obj["data"]["file-size"] = self.buf.ru64l()
                obj["data"]["creation-date"] = utils.filetime_to_date(self.buf.ru64l())
                obj["data"]["data-packets-count"] = self.buf.ru64l()

                temp = self.buf.ru64l()
                obj["data"]["play-duration"] = {"raw": temp, "seconds": temp / 10000000}

                temp = self.buf.ru64l()
                obj["data"]["send-duration"] = {"raw": temp, "seconds": temp / 10000000}

                temp = self.buf.ru64l()
                obj["data"]["preroll"] = {"raw": temp, "seconds": temp / 1000}

                flags = self.buf.ru32l()
                obj["data"]["flags"] = {
                    "raw": flags,
                    "live": bool(flags & (1 << 0)),
                    "huge-data-units": bool(flags & (1 << 1)),
                }

                obj["data"]["min-data-packet-size"] = self.buf.ru32l()
                obj["data"]["max-data-packet-size"] = self.buf.ru32l()
                obj["data"]["max-bitrate"] = self.buf.ru32l()
            case "5fbf03b5-a92e-11cf-8ee3-00c00c205365":
                obj["name"] = "Header Extension"
                obj["data"]["reserved1"] = self.buf.rguid()
                obj["data"]["reserved2"] = self.buf.ru16l()
                obj["data"]["subobject-size"] = self.buf.ru32l()

                self.buf.pushunit()
                self.buf.setunit(obj["data"]["subobject-size"])

                obj["data"]["subobjects"] = []
                while self.buf.unit > 0:
                    obj["data"]["subobjects"].append(self.read_object())

                self.buf.popunit()
            case "7c4346a9-efe0-4bfc-b229-393ede415c85":
                obj["name"] = "Language List"
                obj["data"]["language-count"] = self.buf.ru16l()
                obj["data"]["languages"] = [
                    self.buf.rs(self.buf.ru8(), "utf16") for i in range(0, obj["data"]["language-count"])
                ]
            case "14e6a5cb-c672-4332-8399-a96952065b5a":
                obj["name"] = "Extended Stream Properties Object"
                obj["data"]["start-time-ms"] = self.buf.ru64l()
                obj["data"]["end-time-ms"] = self.buf.ru64l()
                obj["data"]["data-bitrate"] = self.buf.ru32l()
                obj["data"]["buffer-size"] = self.buf.ru32l()
                obj["data"]["initial-buffer-fullness"] = self.buf.ru32l()
                obj["data"]["alternate-data-bitrate"] = self.buf.ru32l()
                obj["data"]["alternate-buffer-size"] = self.buf.ru32l()
                obj["data"]["alternate-initial-buffer-fullness"] = self.buf.ru32l()
                obj["data"]["maximum-object-size"] = self.buf.ru32l()

                flags = self.buf.ru32l()
                obj["data"]["flags"] = {
                    "raw": flags,
                    "reliable": bool(flags & (1 << 0)),
                    "seekable": bool(flags & (1 << 1)),
                    "no-cleanpoints": bool(flags & (1 << 2)),
                    "resend-live-cleanpoints": bool(flags & (1 << 3)),
                }

                obj["data"]["stream-number"] = self.buf.ru16l()
                obj["data"]["stream-language-id-index"] = self.buf.ru16l()
                obj["data"]["avg-time-per-frame"] = self.buf.ru64l()
                obj["data"]["stream-name-count"] = self.buf.ru16l()
                obj["data"]["payload-extension-system-count"] = self.buf.ru16l()

                obj["data"]["stream-names"] = []
                for i in range(0, obj["data"]["stream-name-count"]):
                    name = {}
                    name["language-id-index"] = self.buf.ru16l()
                    name["stream-name"] = self.buf.rs(self.buf.ru16l(), "utf16")

                    obj["data"]["stream-names"].append(name)

                obj["data"]["payload-extension-systems"] = []
                for i in range(0, obj["data"]["payload-extension-system-count"]):
                    extension = {}
                    extension["system-id"] = self.buf.rguid()
                    extension["data-size"] = self.buf.ru16l()
                    extension["system-info"] = self.buf.rh(self.buf.ru32l())

                    obj["data"]["payload-extension-systems"].append(extension)

                obj["data"]["subobjects"] = []
                while self.buf.unit > 0:
                    obj["data"]["subobjects"].append(self.read_object())
            case "d2d0a440-e307-11d2-97f0-00a0c95ea850":
                obj["name"] = "Extended Content Description Object"
                obj["data"]["content-descriptor-count"] = self.buf.ru16l()

                obj["data"]["content-descriptors"] = []
                for i in range(0, obj["data"]["content-descriptor-count"]):
                    desc = {}
                    desc["name"] = self.buf.rs(self.buf.ru16l(), "utf16")

                    typ = self.buf.ru16l()
                    desc["type"] = utils.unraw(
                        typ,
                        2,
                        {
                            0: "Unicode string",
                            1: "BYTE array",
                            2: "BOOL",
                            3: "DWORD",
                            4: "QWORD",
                            5: "WORD",
                        },
                    )

                    self.buf.pushunit()
                    self.buf.setunit(self.buf.ru16l())

                    match desc["type"]["name"]:
                        case "Unicode string":
                            desc["value"] = self.buf.rs(self.buf.unit, "utf16")
                        case "BYTE array":
                            desc["value"] = self.buf.rh(self.buf.unit)
                        case "BOOL":
                            desc["value"] = bool(self.buf.ru32l())
                        case "DWORD":
                            desc["value"] = self.buf.ru32l()
                        case "QWORD":
                            desc["value"] = self.buf.ru64l()
                        case "WORD":
                            desc["value"] = self.buf.ru16l()
                        case _:
                            desc["unknown"] = True

                    self.buf.skipunit()
                    self.buf.popunit()

                    obj["data"]["content-descriptors"].append(desc)
            case "b7dc0791-a9b7-11cf-8ee6-00c00c205365":
                obj["name"] = "Stream Properties Object"

                temp = self.buf.rguid()
                obj["data"]["stream-type"] = {
                    "raw": temp,
                    "name": {
                        "bc19efc0-5b4d-11cf-a8fd-00805f5c442b": "Video Media",
                        "f8699e40-5b4d-11cf-a8fd-00805f5c442b": "Audio Media",
                    }.get(temp, "Unknown"),
                }

                temp = self.buf.rguid()
                obj["data"]["ecc-type"] = {
                    "raw": temp,
                    "name": {
                        "20fb5700-5b55-11cf-a8fd-00805f5c442b": "No Error Correction",
                        "bfc3cd50-618f-11cf-8bb2-00aa00b4e220": "Audio Spread",
                    }.get(temp, "Unknown"),
                }

                obj["data"]["time-offset"] = self.buf.ru64l()
                obj["data"]["type-specific-data-length"] = self.buf.ru32l()
                obj["data"]["ecc-data-length"] = self.buf.ru32l()

                flags = self.buf.ru16l()
                obj["data"]["flags"] = {
                    "raw": flags,
                    "stream-number": flags & 0x7f,
                    "encrypted": bool(flags & (1 << 15)),
                }

                obj["data"]["reserved"] = self.buf.ru32l()

                self.buf.pushunit()
                self.buf.setunit(obj["data"]["type-specific-data-length"])

                match obj["data"]["stream-type"]["name"]:
                    case "Video Media":
                        obj["data"]["type-specific-data"] = {}
                        obj["data"]["type-specific-data"]["image-width"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["image-height"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["reserved"] = self.buf.ru8()
                        obj["data"]["type-specific-data"]["format-data-length"] = self.buf.ru16l()

                        obj["data"]["type-specific-data"]["format-data"] = {}
                        obj["data"]["type-specific-data"]["format-data"]["format-data-length"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["format-data"]["image-width"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["format-data"]["image-height"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["format-data"]["reserved"] = self.buf.ru16l()
                        obj["data"]["type-specific-data"]["format-data"]["bits-per-pixel"] = self.buf.ru16l()
                        obj["data"]["type-specific-data"]["format-data"]["compression-id"] = self.buf.rs(4)
                        obj["data"]["type-specific-data"]["format-data"]["image-size"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["format-data"]["horiz-pixels-per-meter"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["format-data"]["vert-pixels-per-meter"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["format-data"]["colors-used"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["format-data"]["important-colors"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["format-data"]["codec-specific-data"] = self.buf.rh(self.buf.unit)
                    case "Audio Media":
                        obj["data"]["type-specific-data"] = {}
                        obj["data"]["type-specific-data"]["codec-id"] = self.buf.ru16l()
                        obj["data"]["type-specific-data"]["channel-count"] = self.buf.ru16l()
                        obj["data"]["type-specific-data"]["samples-per-second"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["avg-bytes-per-second"] = self.buf.ru32l()
                        obj["data"]["type-specific-data"]["block-alignment"] = self.buf.ru16l()
                        obj["data"]["type-specific-data"]["bits-per-sample"] = self.buf.ru16l()
                        obj["data"]["type-specific-data"]["codec-specific-data"] = self.buf.rh(self.buf.ru16l())
                    case _:
                        obj["data"]["type-specific-data"] = self.buf.rh(self.buf.unit)
                        obj["unknown"] = True

                self.buf.skipunit()
                self.buf.popunit()

                self.buf.pushunit()
                self.buf.setunit(obj["data"]["ecc-data-length"])

                match obj["data"]["ecc-type"]["name"]:
                    case "Audio Spread":
                        obj["data"]["ecc-data"] = {}
                        obj["data"]["ecc-data"]["span"] = self.buf.ru8()
                        obj["data"]["ecc-data"]["virtual-packet-length"] = self.buf.ru16l()
                        obj["data"]["ecc-data"]["virtual-channel-length"] = self.buf.ru16l()
                        obj["data"]["ecc-data"]["silence-data"] = self.buf.rh(self.buf.ru16l())
                    case "No Error Correction":
                        obj["data"]["ecc-data"] = self.buf.rh(self.buf.unit)
                    case _:
                        obj["data"]["ecc-data"] = self.buf.rh(self.buf.unit)
                        obj["unknown"] = True

                self.buf.skipunit()
                self.buf.popunit()
            case "86d15240-311d-11d0-a3a4-00a0c90348f6":
                obj["name"] = "Codec List"
                obj["data"]["reserved"] = self.buf.rguid()
                obj["data"]["codec-entry-count"] = self.buf.ru32l()

                obj["data"]["codec-entries"] = []
                for i in range(0, obj["data"]["codec-entry-count"]):
                    codec = {}
                    codec["type"] = utils.unraw(self.buf.ru16l(), 2, {1: "Audio", 2: "Video"})
                    codec["name"] = self.buf.rs(self.buf.ru16l() << 1, "utf16")
                    codec["description"] = self.buf.rs(self.buf.ru16l() << 1, "utf16")
                    codec["information"] = self.buf.rh(self.buf.ru16l())

                    obj["data"]["codec-entries"].append(codec)
            case "75b22636-668e-11cf-a6d9-00aa0062ce6c":
                obj["name"] = "Data"
                obj["data"]["file-guid"] = self.buf.rguid()
                obj["data"]["total-packet-count"] = self.buf.ru64l()
                obj["data"]["reserved"] = self.buf.ru16l()
            case "33000890-e5b1-11cf-89f4-00a0c90349cb":
                obj["name"] = "Simple Index"
                obj["data"]["file-guid"] = self.buf.rguid()
                obj["data"]["index-entry-time-interval"] = self.buf.ru64l()
                obj["data"]["max-packet-count"] = self.buf.ru32l()
                obj["data"]["index-entries-count"] = self.buf.ru32l()
            case "c5f8cbea-5baf-4877-8467-aa8c44fa4cca":
                obj["name"] = "Metadata Object"
                obj["data"]["description-record-count"] = self.buf.ru16l()

                obj["data"]["description-records"] = []
                for i in range(0, obj["data"]["description-record-count"]):
                    record = {}
                    record["reserved"] = self.buf.ru16l()
                    record["stream-number"] = self.buf.ru16l()
                    record["name-length"] = self.buf.ru16l()
                    record["data-type"] = utils.unraw(
                        self.buf.ru16l(),
                        2,
                        {
                            0x0000: "Unicode string",
                            0x0001: "BYTE array",
                            0x0002: "BOOL",
                            0x0003: "DWORD",
                            0x0004: "QWORD",
                            0x0005: "WORD",
                        },
                        True,
                    )
                    record["data-length"] = self.buf.ru32l()
                    record["name"] = self.buf.rs(record["name-length"], "utf-16")

                    self.buf.pasunit(record["data-length"])

                    match record["data-type"]:
                        case "Unicode string":
                            record["data"] = self.buf.rs(self.buf.unit, "utf-16")
                        case "BYTE array":
                            record["data"] = self.buf.rh(self.buf.unit)
                        case "BOOL":
                            record["data"] = bool(self.buf.ru16l())
                        case "DWORD":
                            record["data"] = self.buf.ru32l()
                        case "QWORD":
                            record["data"] = self.buf.ru64l()
                        case "WORD":
                            record["data"] = self.buf.ru16l()
                        case _:
                            record["data"] = self.buf.rh(self.buf.unit)
                            record["unknown"] = True

                    self.buf.sapunit()

                    obj["data"]["description-records"].append(record)
            case _:
                obj["unknown"] = True

        self.buf.skipunit()
        self.buf.popunit()

        return obj

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "asf"

        meta["objects"] = []
        while self.buf.available() > 0:
            meta["objects"].append(self.read_object())

        return meta


@module.register
class SwfModule(module.RuminantModule):
    dev = True
    desc = "SWF Adobe Flash files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(3) in (b"FWS", b"CWS", b"ZWS")

    def read_rect(
        self,
    ):
        res = {}
        res["nbits"] = self.buf.rb(5)
        res["x-min"] = self.buf.rb(res["nbits"])
        res["x-max"] = self.buf.rb(res["nbits"])
        res["y-min"] = self.buf.rb(res["nbits"])
        res["y-max"] = self.buf.rb(res["nbits"])
        self.buf.align()
        return res

    def read_matrix(self):
        mat = {}

        mat["has-scale"] = self.buf.rb(1)
        if mat["has-scale"]:
            mat["scale-bits"] = self.buf.rb(5)
            mat["scale-x"] = self.buf.rsb(mat["scale-bits"])
            mat["scale-y"] = self.buf.rsb(mat["scale-bits"])

        mat["has-rotate"] = self.buf.rb(1)
        if mat["has-rotate"]:
            mat["rotate-bits"] = self.buf.rb(5)
            mat["rotate-x"] = self.buf.rsb(mat["rotate-bits"])
            mat["rotate-y"] = self.buf.rsb(mat["rotate-bits"])

        mat["transform-bits"] = self.buf.rb(5)
        mat["transform-x"] = self.buf.rsb(mat["transform-bits"])
        mat["transform-y"] = self.buf.rsb(mat["transform-bits"])

        self.buf.align()
        return mat

    def read_color_transform(self, place_object_ver2=False):
        ct = {}

        ct["has-add"] = self.buf.rb(1)
        ct["has-mult"] = self.buf.rb(1)
        ct["bits"] = self.buf.rb(4)

        if ct["has-mult"]:
            ct["red-mult"] = self.buf.rsb(ct["bits"])
            ct["green-mult"] = self.buf.rsb(ct["bits"])
            ct["blue-mult"] = self.buf.rsb(ct["bits"])

            if place_object_ver2:
                ct["alpha-mult"] = self.buf.rsb(ct["bits"])

        if ct["has-add"]:
            ct["red-add"] = self.buf.rsb(ct["bits"])
            ct["green-add"] = self.buf.rsb(ct["bits"])
            ct["blue-add"] = self.buf.rsb(ct["bits"])

            if place_object_ver2:
                ct["alpha-add"] = self.buf.rsb(ct["bits"])

        self.buf.align()
        return ct

    def read_any_filter(self):
        # TODO: https://www.m2osw.com/swf_struct_any_filter

        filt = {}
        typ = self.buf.ru8()

        match typ:
            case _:
                raise ValueError(f"Unknown filter type {typ}")

        self.buf.align()
        return filt

    def read_tags(self):
        tags = []
        should_break = False

        while self.buf.available() >= 4 and not should_break:
            tag = {}
            temp = self.buf.ru16l()
            code = temp >> 6
            tag["length"] = temp & 0x3f

            if tag["length"] == 63:
                tag["length"] = self.buf.ru32l()

            self.buf.pasunit(tag["length"])

            tag["type"] = None
            tag["data"] = {}
            match code:
                case 0:
                    tag["type"] = "End"
                    should_break = True
                case 1:
                    tag["type"] = "ShowFrame"
                case 2:
                    tag["type"] = "DefineShape"
                    tag["data"]["id"] = self.buf.ru16l()
                    tag["data"]["fill-bits"] = self.buf.rb(4)
                    tag["data"]["line-bits"] = self.buf.rb(4)

                    tag["data"]["shapes"] = []
                    while True:
                        shape = {}

                        shape["type"] = self.buf.rb(1)

                        if shape["type"] == 0:
                            shape["reserved"] = self.buf.rb(0)
                            shape["has-line-style"] = self.buf.rb(1)
                            shape["has-fill-style1"] = self.buf.rb(1)
                            shape["has-fill-style0"] = self.buf.rb(1)
                            shape["has-move-to"] = self.buf.rb(1)

                            if not (
                                shape["reserved"]
                                or shape["has-line-style"]
                                or shape["has-fill-style1"]
                                or shape["has-fill-style0"]
                                or shape["has-move-to"]
                            ):
                                break

                            if shape["has-move-to"]:
                                shape["move-bits"] = self.buf.rb(5)
                                shape["move-x"] = self.buf.rsb(shape["move-bits"])
                                shape["move-y"] = self.buf.rsb(shape["move-bits"])

                            if shape["has-fill-style0"]:
                                shape["fill-style0"] = self.buf.rb(tag["data"]["fill-bits"])

                            if shape["has-fill-style1"]:
                                shape["fill-style1"] = self.buf.rb(tag["data"]["fill-bits"])

                            if shape["has-line-style"]:
                                shape["line-style"] = self.buf.rb(tag["data"]["line-bits"])
                        else:
                            shape["edge-type"] = self.buf.rb(1)
                            shape["coord-size"] = self.buf.rb(4) + 2

                            if shape["edge-type"] == 0:
                                shape["control-delta-x"] = self.buf.rsb(shape["coord-size"])
                                shape["control-delta-y"] = self.buf.rsb(shape["coord-size"])
                                shape["anchor-delta-x"] = self.buf.rsb(shape["coord-size"])
                                shape["anchor-delta-y"] = self.buf.rsb(shape["coord-size"])
                            else:
                                shape["has-x-and-y"] = self.buf.rb(1)

                                if shape["has-x-and-y"]:
                                    shape["delta-x"] = self.buf.rsb(shape["coord-size"])
                                    shape["delta-y"] = self.buf.rsb(shape["coord-size"])
                                else:
                                    shape["has-x-or-y"] = self.buf.rb(1)

                                    if shape["has-x-or-y"]:
                                        shape["delta-x"] = self.buf.rsb(shape["coord-size"])
                                    else:
                                        shape["delta-y"] = self.buf.rsb(shape["coord-size"])

                        tag["data"]["shapes"].append(shape)

                    self.buf.align()

                case 9:
                    tag["type"] = "SetBackgroundColor"
                    tag["data"]["red"] = self.buf.ru8()
                    tag["data"]["green"] = self.buf.ru8()
                    tag["data"]["blue"] = self.buf.ru8()
                case 26:
                    tag["type"] = "PlaceObject2"

                    if self.version >= 8 and code == 70:
                        tag["data"]["reserved-ver8"] = self.buf.rb(5)
                        tag["data"]["place-bitmap-caching"] = self.buf.rb(1)
                        tag["data"]["place-blend-mode"] = self.buf.rb(1)
                        tag["data"]["place-filters"] = self.buf.rb(1)

                    if self.version >= 5:
                        tag["data"]["has-actions"] = self.buf.rb(1)
                    else:
                        tag["data"]["reserved-ver5"] = self.buf.rb(1)

                    tag["data"]["has-clipping-depth"] = self.buf.rb(1)
                    tag["data"]["has-name"] = self.buf.rb(1)
                    tag["data"]["has-morph-position"] = self.buf.rb(1)
                    tag["data"]["has-color-transform"] = self.buf.rb(1)
                    tag["data"]["has-matrix"] = self.buf.rb(1)
                    tag["data"]["has-id-ref"] = self.buf.rb(1)
                    tag["data"]["has-move"] = self.buf.rb(1)
                    tag["data"]["depth"] = self.buf.ru16l()

                    if tag["data"]["has-id-ref"]:
                        tag["data"]["object-id-ref"] = self.buf.ru16l()

                    if tag["data"]["has-matrix"]:
                        tag["data"]["matrix"] = self.read_matrix()

                    if tag["data"]["has-color-transform"]:
                        tag["data"]["color-transform"] = self.read_color_transform(code == 26)

                    if tag["data"]["has-morph-position"]:
                        tag["data"]["morph-position"] = self.buf.ru16l()

                    if tag["data"]["has-name"]:
                        tag["data"]["name"] = self.buf.rzs()

                    if tag["data"]["has-clipping-depth"]:
                        tag["data"]["clipping-depth"] = self.buf.ru16l()

                    self.buf.align()
                case 39:
                    tag["type"] = "DefineSprite"
                    tag["data"]["sprite-id"] = self.buf.ru16l()
                    tag["data"]["frame-count"] = self.buf.ru16l()
                    tag["data"]["tags"] = self.read_tags()
                case 69:
                    tag["type"] = "FileAttributes"
                    tag["data"]["reserved1"] = self.buf.rb(1)
                    tag["data"]["use-direct-blit"] = self.buf.rb(1)
                    tag["data"]["use-gpu"] = self.buf.rb(1)
                    tag["data"]["has-metadata"] = self.buf.rb(1)
                    tag["data"]["actionscript-3"] = self.buf.rb(1)
                    tag["data"]["reserved2"] = self.buf.rb(2)
                    tag["data"]["use-network"] = self.buf.rb(1)
                    tag["data"]["reserved3"] = self.buf.rb(24)
                case 86:
                    tag["type"] = "DefineSceneAndFrameLabelData"

                    tag["data"]["scenes"] = []
                    for i in range(0, self.buf.ruleb()):
                        scene = {}
                        scene["frame-offset"] = self.buf.ruleb()
                        scene["name"] = self.buf.rzs()

                        tag["data"]["scenes"].append(scene)

                    tag["data"]["frame-labels"] = []
                    for i in range(0, self.buf.ruleb()):
                        label = {}
                        label["frame-number"] = self.buf.ruleb()
                        label["name"] = self.buf.rzs()

                        tag["data"]["frame-labels"].append(label)
                case _:
                    tag["type"] = f"Unknown ({code})"
                    tag["unknown"] = True

            self.buf.sapunit()
            tags.append(tag)

        return tags

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "swf"

        meta["compression"] = {"FWS": "none", "CWS": "zlib", "ZWS": "lzma"}[self.buf.rs(3)]

        meta["version"] = self.buf.ru8()
        self.version = meta["version"]

        meta["decompressed-length"] = self.buf.ru32l()

        match meta["compression"]:
            case "none":
                pass
            case "zlib":
                fd = utils.tempfd()
                utils.stream_zlib(self.buf, fd, self.buf.available(), revert=True)
                self.buf = Buf(fd)
                self.buf.seek(0)
            case "lzma":
                fd = utils.tempfd()
                utils.stream_xz(self.buf, fd, self.buf.available())
                self.buf = Buf(fd)
                self.buf.seek(0)
            case _:
                raise ValueError("Unknown compression")

        meta["frame-size"] = self.read_rect()
        meta["frame-rate"] = self.buf.rfp16l()
        meta["frame-count"] = self.buf.ru16l()

        meta["tags"] = self.read_tags()

        return meta


@module.register
class DuckIvfModule(module.RuminantModule):
    desc = "Duck IVF video files."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"DKIF"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "duck-ivf"

        self.buf.skip(4)
        meta["version"] = self.buf.ru16l()
        meta["header-length"] = self.buf.ru16l()

        self.buf.pasunit(meta["header-length"] - 8)

        meta["format"] = self.buf.rs(4)
        meta["width"] = self.buf.ru16l()
        meta["height"] = self.buf.ru16l()
        d = self.buf.ru32l()
        n = self.buf.ru32l()
        meta["time-base"] = {"value": n / d, "denominator": d, "numerator": n}
        meta["frame-count"] = self.buf.ru32l()
        meta["unused"] = self.buf.ru32l()

        self.buf.sapunit()

        match meta["format"]:
            case "AV01":
                with self.buf:
                    length = self.buf.ru32l()
                    self.buf.skip(8)

                    self.buf.pasunit(length)

                    meta["first-sample-obus"] = []
                    while self.buf.hasunit():
                        meta["first-sample-obus"].append(FFMpreg.read_av1_obu(self.buf))

                    self.buf.sapunit()

        for i in range(0, meta["frame-count"]):
            self.buf.skip(self.buf.ru32l() + 8)

        return meta


@module.register
class DiracModule(module.RuminantModule):
    desc = "BBC Dirac data units."

    @staticmethod
    def identify(buf: Buf, ctx={}) -> bool:
        return buf.peek(4) == b"BBCD"

    def chew(self) -> ruminant_types.JSON:
        meta: dict = {}
        meta["type"] = "dirac"

        meta["units"] = []
        should_break = False
        while not should_break:
            unit: dict = {}
            self.buf.skip(4)

            typ = self.buf.ru8()

            if typ & 0b00001000:
                unit["type"] = "picture"
                unit["frame-flags"] = {
                    "picture-syntax": ["dirac", "vc-2"][typ >> 7],
                    "arithmetic-coding": bool(typ & 0x40),
                    "reserved": (typ >> 5) & 0x01,
                    "variant-profile-flag": bool(typ & 0x10),
                    "picture-flag": bool(typ & 0x08),
                    "num-refs": typ & 0x07,
                }
            else:
                unit["type"] = utils.unraw(
                    typ,
                    1,
                    {
                        0x00: "sequence-header",
                        0x20: "auxiliary-data",
                        0x10: "end-of-sequence",
                    },
                    True,
                )

            unit["next-offset"] = self.buf.ru32()
            unit["previous-offset"] = self.buf.ru32()

            unit["data"] = {}
            if unit["next-offset"] == 13:
                should_break = True
            else:
                self.buf.pasunit(unit["next-offset"] - 13)

                match unit["type"]:
                    case "picture":
                        unit["data"]["frame-counter"] = self.buf.ru32()
                    case "auxiliary-data":
                        unit["data"]["string"] = self.buf.rs(self.buf.unit)
                    case "sequence-header":
                        unit["data"]["parse-paramets"] = {}
                        unit["data"]["parse-paramets"]["major-version"] = self.buf.riue()
                        unit["data"]["parse-paramets"]["minor-version"] = self.buf.riue()
                        unit["data"]["parse-paramets"]["profile"] = self.buf.riue()
                        unit["data"]["parse-paramets"]["level"] = self.buf.riue()

                        unit["data"]["base-video-format"] = utils.unraw(
                            self.buf.riue(),
                            1,
                            {
                                0x00: "Custom Format",
                                0x01: "QSIF525",
                                0x02: "QCIF",
                                0x03: "SIF525",
                                0x04: "CIF",
                                0x05: "4SIF525",
                                0x06: "4CIF",
                                0x07: "SD 480I-60 (525 Line 59.94 Field/s Standard Definition)",
                                0x08: "SD 576I-50 (625 Line 50 Field/s Standard Definition)",
                                0x09: "HD 720P-60 (720 Line 59.94 Frame/s High Definition)",
                                0x0a: "HD 720P-50 (720 Line 50 Frame/s High Definition)",
                                0x0b: "HD 1080I-60 (1080 Line 60 Field/s High Definition)",
                                0x0c: "HD 1080I-50 (1080 Line 50 Field/s High Definition)",
                                0x0d: "HD 1080P-60 (1080 Line 59.94 Frame/s High Definition)",
                                0x0e: "HD 1080P50 (1080 Line 50 Frame/s High Definition)",
                                0x0f: "DC 2K-24 (2K D-Cinema, 24fps)",
                                0x10: "DC 4K-24 (4K D-Cinema, 24fps)",
                                0x11: "UHDTV 4K-60 (2160-line 59.94 Frame/s UHDTV)",
                                0x12: "UHDTV 4K-50 (2160-line 50 Frame/s UHDTV)",
                                0x13: "UHDTV 8K-60 (4320-line 59.94 Frame/s UHDTV)",
                                0x14: "UHDTV 8K-50 (4320-line 50 Frame/s UHDTV)",
                            },
                            True,
                        )

                        unit["data"]["source-parameters"] = {}
                        unit["data"]["source-parameters"]["custom-dimensions"] = self.buf.rb(1)
                        if unit["data"]["source-parameters"]["custom-dimensions"]:
                            unit["data"]["source-parameters"]["frame-width"] = self.buf.riue()
                            unit["data"]["source-parameters"]["frame-height"] = self.buf.riue()
                        unit["data"]["source-parameters"]["custom-chroma-sampling"] = self.buf.rb(1)
                        if unit["data"]["source-parameters"]["custom-chroma-sampling"]:
                            unit["data"]["source-parameters"]["chroma-format"] = utils.unraw(
                                self.buf.riue(),
                                1,
                                {0x00: "4:4:4", 0x01: "4:2:2", 0x02: "4:2:0"},
                                True,
                            )
                        unit["data"]["source-parameters"]["custom-scan-format"] = self.buf.rb(1)
                        if unit["data"]["source-parameters"]["custom-scan-format"]:
                            unit["data"]["source-parameters"]["scan-format"] = utils.unraw(
                                self.buf.riue(),
                                1,
                                {0x00: "progressive", 0x01: "interlaced"},
                                True,
                            )
                        unit["data"]["source-parameters"]["custom-frame-rate"] = self.buf.rb(1)
                        if unit["data"]["source-parameters"]["custom-frame-rate"]:
                            unit["data"]["source-parameters"]["frame-rate-index"] = self.buf.riue()
                            if unit["data"]["source-parameters"]["frame-rate-index"] == 0:
                                unit["data"]["source-parameters"]["frame-rate-num"] = self.buf.riue()
                                unit["data"]["source-parameters"]["frame-rate-denom"] = self.buf.riue()
                            else:
                                (
                                    unit["data"]["source-parameters"]["frame-rate-num"],
                                    unit["data"]["source-parameters"]["frame-rate-denom"],
                                ) = {
                                    0x01: (24000, 1001),
                                    0x02: (24, 1),
                                    0x03: (25, 1),
                                    0x04: (30000, 1001),
                                    0x05: (30, 1),
                                    0x06: (50, 1),
                                    0x07: (60000, 1001),
                                    0x08: (60, 1),
                                    0x09: (15000, 1001),
                                    0x0a: (25, 2),
                                }.get(
                                    unit["data"]["source-parameters"]["frame-rate-index"],
                                    (0, 1),
                                )
                            unit["data"]["source-parameters"]["frame-rate"] = (
                                unit["data"]["source-parameters"]["frame-rate-num"]
                                / unit["data"]["source-parameters"]["frame-rate-denom"]
                            )

                        unit["data"]["source-parameters"]["custom-pixel-aspect-ratio"] = self.buf.rb(1)
                        if unit["data"]["source-parameters"]["custom-pixel-aspect-ratio"]:
                            unit["data"]["source-parameters"]["pixel-aspect-ratio-index"] = self.buf.riue()
                            if unit["data"]["source-parameters"]["pixel-aspect-ratio-index"] == 0:
                                unit["data"]["source-parameters"]["pixel-aspect-ratio-num"] = self.buf.riue()
                                unit["data"]["source-parameters"]["pixel-aspect-ratio-denom"] = self.buf.riue()
                            else:
                                (
                                    unit["data"]["source-parameters"]["pixel-aspect-ratio-num"],
                                    unit["data"]["source-parameters"]["pixel-aspect-ratio-denom"],
                                ) = {
                                    0x01: (1, 1),
                                    0x02: (10, 11),
                                    0x03: (12, 11),
                                    0x04: (40, 33),
                                    0x05: (16, 11),
                                    0x06: (4, 3),
                                }.get(
                                    unit["data"]["source-parameters"]["pixel-aspect-ratio-index"],
                                    (0, 1),
                                )

                        unit["data"]["source-parameters"]["custom-clean-area"] = self.buf.rb(1)
                        if unit["data"]["source-parameters"]["custom-clean-area"]:
                            unit["data"]["source-parameters"]["clean-area-width"] = self.buf.riue()
                            unit["data"]["source-parameters"]["clean-area-height"] = self.buf.riue()
                            unit["data"]["source-parameters"]["clean-area-left-offset"] = self.buf.riue()
                            unit["data"]["source-parameters"]["clean-area-top-offset"] = self.buf.riue()

                        unit["data"]["source-parameters"]["custom-signal"] = self.buf.rb(1)
                        if unit["data"]["source-parameters"]["custom-signal"]:
                            unit["data"]["source-parameters"]["signal-index"] = self.buf.riue()

                            if unit["data"]["source-parameters"]["signal-index"] == 0:
                                unit["data"]["source-parameters"]["signal-luma-offset"] = self.buf.riue()
                                unit["data"]["source-parameters"]["signal-luma-excursion"] = self.buf.riue()
                                unit["data"]["source-parameters"]["signal-chroma-offset"] = self.buf.riue()
                                unit["data"]["source-parameters"]["signal-chroma-excursion"] = self.buf.riue()
                            else:
                                unit["data"]["source-parameters"]["signal-luma-offset"] = {
                                    0x01: 0,
                                    0x02: 16,
                                    0x03: 64,
                                    0x04: 256,
                                }.get(unit["data"]["source-parameters"]["signal-index"], 0)
                                unit["data"]["source-parameters"]["signal-luma-excursion"] = {
                                    0x01: 255,
                                    0x02: 219,
                                    0x03: 876,
                                    0x04: 3504,
                                }.get(unit["data"]["source-parameters"]["signal-index"], 0)
                                unit["data"]["source-parameters"]["signal-chroma-offset"] = {
                                    0x01: 128,
                                    0x02: 128,
                                    0x03: 512,
                                    0x04: 2048,
                                }.get(unit["data"]["source-parameters"]["signal-index"], 0)
                                unit["data"]["source-parameters"]["signal-chroma-excursion"] = {
                                    0x01: 255,
                                    0x02: 224,
                                    0x03: 896,
                                    0x04: 3584,
                                }.get(unit["data"]["source-parameters"]["signal-index"], 0)

                        # eww br*t*sh
                        unit["data"]["source-parameters"]["custom-colour-spec"] = self.buf.rb(1)
                        if unit["data"]["source-parameters"]["custom-colour-spec"]:
                            unit["data"]["source-parameters"]["colour-spec-index"] = self.buf.riue()
                            unit["data"]["source-parameters"]["colour-spec-primaries"] = utils.unraw(
                                unit["data"]["source-parameters"]["colour-spec-index"],
                                1,
                                {
                                    0x00: "HDTV",
                                    0x01: "SDTV 525",
                                    0x02: "SDTV 625",
                                    0x03: "HDTV",
                                    0x04: "HDTV",
                                },
                                True,
                            )
                            unit["data"]["source-parameters"]["colour-spec-matrix"] = utils.unraw(
                                unit["data"]["source-parameters"]["colour-spec-index"],
                                1,
                                {
                                    0x00: "HDTV",
                                    0x01: "SDTV",
                                    0x02: "SDTV",
                                    0x03: "HDTV",
                                    0x04: "HDTV",
                                },
                                True,
                            )
                            unit["data"]["source-parameters"]["colour-spec-transfer-function"] = utils.unraw(
                                unit["data"]["source-parameters"]["colour-spec-index"],
                                1,
                                {
                                    0x00: "TV gamma",
                                    0x01: "TV gamma",
                                    0x02: "TV gamma",
                                    0x03: "TV gamma",
                                    0x04: "DCinema gamma",
                                },
                                True,
                            )

                            if unit["data"]["source-parameters"]["colour-spec-index"] == 0:
                                unit["data"]["source-parameters"]["custom-colour-spec-primaries"] = self.buf.rb(1)
                                if unit["data"]["source-parameters"]["custom-colour-spec-primaries"]:
                                    unit["data"]["source-parameters"]["colour-spec-primaries-index"] = self.buf.riue()
                                    unit["data"]["source-parameters"]["colour-spec-primaries"] = utils.unraw(
                                        unit["data"]["source-parameters"]["colour-spec-primaries-index"],
                                        1,
                                        {
                                            0x00: "HDTV",
                                            0x01: "SDTV 525",
                                            0x02: "SDTV 625",
                                            0x03: "DCinema",
                                        },
                                        True,
                                    )

                            if unit["data"]["source-parameters"]["colour-spec-index"] == 0:
                                unit["data"]["source-parameters"]["custom-colour-spec-matrix"] = self.buf.rb(1)
                                if unit["data"]["source-parameters"]["custom-colour-spec-matrix"]:
                                    unit["data"]["source-parameters"]["colour-spec-matrix-index"] = self.buf.riue()
                                    unit["data"]["source-parameters"]["colour-spec-matrix"] = utils.unraw(
                                        unit["data"]["source-parameters"]["colour-spec-matrix-index"],
                                        1,
                                        {
                                            0x00: "HDTV",
                                            0x01: "SDTV",
                                            0x02: "Reversible",
                                        },
                                        True,
                                    )

                            if unit["data"]["source-parameters"]["colour-spec-index"] == 0:
                                unit["data"]["source-parameters"]["custom-colour-spec-transfer-function"] = self.buf.rb(1)
                                if unit["data"]["source-parameters"]["custom-colour-spec-transfer-function"]:
                                    unit["data"]["source-parameters"]["colour-spec-transfer-function-index"] = self.buf.riue()
                                    unit["data"]["source-parameters"]["colour-spec-transfer-function"] = utils.unraw(
                                        unit["data"]["source-parameters"]["colour-spec-transfer-function-index"],
                                        1,
                                        {
                                            0x00: "TV gamma",
                                            0x01: "Extended Gamut",
                                            0x02: "Linear",
                                            0x03: "DCI Gamma",
                                        },
                                        True,
                                    )

                        self.buf.align()

                self.buf.sapunit()

            meta["units"].append(unit)

        return meta
