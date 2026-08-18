import math
from . import utils
from .buf import Buf


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
    AV2_OBU_TYPES = {
        0x00: "RESERVED",
        0x01: "SEQUENCE_HEADER",
        0x02: "TEMPORAL_DELIMITER",
        0x03: "MULTI_FRAME_HEADER",
        0x04: "CLOSED_LOOP_KEY",
        0x05: "OPEN_LOOP_KEY",
        0x06: "LEADING_TILE_GROUP",
        0x07: "REGULAR_TILE_GROUP",
        0x08: "METADATA_SHORT",
        0x09: "METADATA_GROUP",
        0x0a: "SWITCH",
        0x0b: "LEADING_SEF",
        0x0c: "REGULAR_SEF",
        0x0d: "LEADING_TIP",
        0x0e: "REGULAR_TIP",
        0x0f: "BUFFER_REMOVAL_TIMING",
        0x10: "LAYER_CONFIGURATION_RECORD",
        0x11: "ATLAS_SEGMENT",
        0x12: "OPERATING_POINT_SET",
        0x13: "BRIDGE_FRAME",
        0x14: "MSDO",
        0x15: "RAS_FRAME",
        0x16: "QUANTIZATION_MATRIX",
        0x17: "FILM_GRAIN",
        0x18: "CONTENT_INTERPRETATION",
        0x19: "PADDING",
        0x1a: "RESERVED",
        0x1b: "RESERVED",
        0x1c: "RESERVED",
        0x1d: "RESERVED",
        0x1e: "RESERVED",
        0x1f: "RESERVED",
    }
    # BOOK New FFMpreg constant

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
        nal["cpb-cnt-minus-one"] = buf.rue()
        nal["bit-rate-scale"] = buf.rb(4)
        nal["cpb-size-scale"] = buf.rb(4)
        nal["list"] = [
            {"bit-rate-value-minus-one": buf.rue(), "cpb-size-value-minus-one": buf.rue(), "cbr-flag": buf.rb(1)}
            for i in range(0, nal["cpb-cnt-minus-one"] + 1)
        ]
        nal["initial-cpb-removal-delay-length-minus-one"] = buf.rb(5)
        nal["cpb-removal-delay-length-minus-one"] = buf.rb(5)
        nal["dpb-output-delay-length-minus-one"] = buf.rb(5)
        nal["time-offset-length"] = buf.rb(5)

        return nal

    @staticmethod
    def read_h264_nalu(buf: Buf, slim=False, state={}) -> dict:
        buf = Buf(buf.read(buf.unit).replace(b"\x00\x00\x03", b"\x00\x00"))

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
                        state["separate-colour-plane-flag"] = nal["separate-colour-plane-flag"]

                    state["chroma-array-type"] = 0 if nal.get("separate-colour-plane-flag", 0) else nal["chroma-format-idc"]

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

                nal["log2-max-frame-num-minus-four"] = buf.rue()
                state["log2-max-frame-num-minus-four"] = nal["log2-max-frame-num-minus-four"]
                nal["pic-order-cnt-type"] = buf.rue()
                state["pic-order-cnt-type"] = nal["pic-order-cnt-type"]

                if nal["pic-order-cnt-type"] == 0:
                    nal["log2-max-pic-order-cnt-lsb-minus-four"] = buf.rue()
                    state["log2-max-pic-order-cnt-lsb-minus-four"] = nal["log2-max-pic-order-cnt-lsb-minus-four"]
                elif nal["pic-order-cnt-type"] == 1:
                    nal["delta-pic-order-always-zero-flag"] = buf.rb(1)
                    state["delta-pic-order-always-zero-flag"] = nal["delta-pic-order-always-zero-flag"]
                    nal["offset-for-non-ref-pic"] = buf.rse()
                    nal["offset-for-top-to-bottom-field"] = buf.rse()
                    nal["num-ref-frames-in-pic-order-cnt-cycle"] = buf.rue()
                    nal["offsets-for-ref-frame"] = [buf.rse() for i in range(0, nal["num-ref-frames-in-pic-order-cnt-cycle"])]

                nal["max-num-ref-frames"] = buf.rue()
                nal["gaps-in-frame-num-value-allowed-flag"] = buf.rb(1)
                nal["pic-width-in-mbs-minus-one"] = buf.rue()
                state["pic-width-in-mbs-minus-one"] = nal["pic-width-in-mbs-minus-one"]
                nal["pic-height-in-map-units-minus-one"] = buf.rue()
                nal["frame-mbs-only-flag"] = buf.rb(1)
                state["frame-mbs-only-flag"] = nal["frame-mbs-only-flag"]

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
                    state["nal-hrd-parameters-present-flag"] = nal["nal-hrd-parameters-present-flag"]

                    if nal["nal-hrd-parameters-present-flag"]:
                        nal["hrd-parameters"] = FFMpreg.read_h264_hrd_parameters(buf)
                        state["hrd-parameters"] = nal["hrd-parameters"]

                    nal["vcl-hrd-parameters-present-flag"] = buf.rb(1)
                    state["vcl-hrd-parameters-present-flag"] = nal["vcl-hrd-parameters-present-flag"]

                    if nal["vcl-hrd-parameters-present-flag"]:
                        nal["vcl-hrd-parameters"] = FFMpreg.read_h264_hrd_parameters(buf)
                        state["vcl-hrd-parameters"] = nal["vcl-hrd-parameters"]

                    if nal["nal-hrd-parameters-present-flag"] or nal["vcl-hrd-parameters-present-flag"]:
                        nal["low-delay-hrd-flag"] = buf.rb(1)

                    nal["pic-struct-present-flag"] = buf.rb(1)
                    state["pic-struct-present-flag"] = nal["pic-struct-present-flag"]
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
                state["entropy-coding-mode-flag"] = nal["entropy-coding-mode-flag"]
                nal["bottom-field-pic-order-in-frame-present-flag"] = buf.rb(1)
                state["bottom-field-pic-order-in-frame-present-flag"] = nal["bottom-field-pic-order-in-frame-present-flag"]
                nal["num-slice-groups-minus-one"] = buf.rue()
                state["num-slice-groups-minus-one"] = nal["num-slice-groups-minus-one"]

                if nal["num-slice-groups-minus-one"] > 0:
                    nal["slice-group-map-type"] = buf.rue()
                    state["slice-group-map-type"] = nal["slice-group-map-type"]

                    match nal["slice-group-map-type"]:
                        case 0:
                            nal["run-length-minus-one"] = [buf.rue() for i in range(nal["num-slice-groups-minus-one"] + 1)]
                        case 1:
                            pass
                        case 2:
                            nal["top-left-and-bottom-right"] = [
                                (buf.rue(), buf.rue()) for i in range(nal["num-slice-groups-minus-one"])
                            ]
                        case 3 | 4 | 5:
                            nal["slice-group-change-direction-flag"] = buf.rb(1)
                            nal["slice-group-change-rate-minus-one"] = buf.rue()
                            state["slice-group-change-rate-minus-one"] = nal["slice-group-change-rate-minus-one"]
                        case 6:
                            nal["pic-size-in-map-units-minus-one"] = buf.rue()
                            v = math.ceil(math.log2(nal["num-slice-groups-minus-one"] + 1))
                            nal["slice-group-id"] = [buf.rb(v) for i in range(nal["pic-size-in-map-units-minus-one"] + 1)]

                nal["num-ref-idx-l0-default-active-minus-one"] = buf.rue()
                state["num-ref-idx-l0-default-active-minus-one"] = nal["num-ref-idx-l0-default-active-minus-one"]
                nal["num-ref-idx-l1-default-active-minus-one"] = buf.rue()
                state["num-ref-idx-l1-default-active-minus-one"] = nal["num-ref-idx-l1-default-active-minus-one"]
                nal["weighted-pred-flag"] = buf.rb(1)
                state["weighted-pred-flag"] = nal["weighted-pred-flag"]
                nal["weighted-bipred-idc"] = buf.rb(2)
                state["weighted-bipred-idc"] = nal["weighted-bipred-idc"]
                nal["pic-init-qp-minus26"] = buf.rse()
                nal["pic-init-qs-minus26"] = buf.rse()
                nal["chroma-qp-index-offset"] = buf.rse()
                nal["deblocking-filter-control-present-flag"] = buf.rb(1)
                state["deblocking-filter-control-present-flag"] = nal["deblocking-filter-control-present-flag"]
                nal["constrained-intra-pred-flag"] = buf.rb(1)
                nal["redundant-pic-cnt-present-flag"] = buf.rb(1)
                state["redundant-pic-cnt-present-flag"] = nal["redundant-pic-cnt-present-flag"]

                if buf.available() > 0 and not (buf._bits == 0 and buf.pu8() == 0x80):
                    nal["transform-8x8-mode-flag"] = buf.rb(1)
                    nal["pic-scaling-matrix-present-flag"] = buf.rb(1)

                    if nal["pic-scaling-matrix-present-flag"]:
                        nal["pic-scaling-matrices"] = []
                        num_matrices = 6 + ((6 if state.get("chroma-format-idc") == 3 else 2) * nal["transform-8x8-mode-flag"])
                        for i in range(num_matrices):
                            matrix = []
                            if buf.rb(1):
                                matrix = FFMpreg.read_h264_scaling_list(buf, 16 if i < 6 else 64)
                            nal["pic-scaling-matrices"].append(matrix)

                    nal["second-chroma-qp-index-offset"] = buf.rse()

                buf.align()
            case (
                "Coded slice of an IDR picture"
                | "Coded slice of a non-IDR picture"
                | "Coded slice of an auxiliary coded picture without partitioning"
            ):
                nal["first-mb-in-slice"] = buf.rue()
                nal["slice-type"] = buf.rue()
                nal["pic-parameter-set-id"] = buf.rue()

                if state.get("separate-colour-plane-flag"):
                    nal["colour-plane-id"] = buf.rb(2)

                nal["frame-num"] = buf.rb(state.get("log2-max-frame-num-minus-four", 0) + 4)

                if not state.get("frame-mbs-only-flag"):
                    nal["field-pic-flag"] = buf.rb(1)

                    if nal["field-pic-flag"]:
                        nal["bottom-field-flag"] = buf.rb(1)

                if nal["unit-type"] == "Coded slice of an IDR picture":
                    nal["idr-pic-id"] = buf.rue()

                temp = state.get("pic-order-cnt-type", 0)
                if temp == 0:
                    nal["pic-order-cnt-lsb"] = buf.rb(state.get("log2-max-pic-order-cnt-lsb-minus-four", 0) + 4)

                    if state.get("bottom-field-pic-order-in-frame-present-flag") and not nal.get("field-pic-flag"):
                        nal["delta-pic-order-cnt-bottom"] = buf.rse()
                if temp == 1 and not state.get("delta-pic-order-always-zero-flag"):
                    nal["delta-pic-order-cnt"] = [buf.rse()]

                    if state.get("bottom-field-pic-order-in-frame-present-flag") and not nal.get("field-pic-flag"):
                        nal["delta-pic-order-cnt"].append(buf.rse())

                if state.get("redundant-pic-cnt-present-flag"):
                    nal["redundant-pic-cnt"] = buf.rue()

                if nal["slice-type"] % 5 == 1:
                    nal["direct-spatial-mv-pred-flag"] = buf.rb(1)

                if nal["slice-type"] % 5 in (0, 1, 3):
                    nal["num-ref-idx-active-override-flag"] = buf.rb(1)

                    if nal["num-ref-idx-active-override-flag"]:
                        nal["num-ref-idx-l0-active-minus-one"] = buf.rue()

                        if nal["slice-type"] % 5 == 1:
                            nal["num-ref-idx-l1-active-minus-one"] = buf.rue()

                if nal["slice-type"] % 5 != 2 and nal["slice-type"] % 5 != 4:
                    nal["ref-pic-list-modification-flag-l0"] = buf.rb(1)
                    if nal["ref-pic-list-modification-flag-l0"]:
                        while True:
                            nal["modification-of-pic-nums-idc"] = buf.rue()
                            if nal["modification-of-pic-nums-idc"] == 0 or nal["modification-of-pic-nums-idc"] == 1:
                                nal["abs-diff-pic-num-minus-one"] = buf.rue()
                            elif nal["modification-of-pic-nums-idc"] == 2:
                                nal["long-term-pic-num"] = buf.rue()
                            elif nal["unit-type"] == "Coded slice extension" and (
                                nal["modification-of-pic-nums-idc"] == 4 or nal["modification-of-pic-nums-idc"] == 5
                            ):
                                nal["abs-diff-view-idx-minus-one"] = buf.rue()
                            if nal["modification-of-pic-nums-idc"] == 3:
                                break
                if nal["slice-type"] % 5 == 1:
                    nal["ref-pic-list-modification-flag-l1"] = buf.rb(1)
                    if nal["ref-pic-list-modification-flag-l1"]:
                        while True:
                            nal["modification-of-pic-nums-idc"] = buf.rue()
                            if nal["modification-of-pic-nums-idc"] == 0 or nal["modification-of-pic-nums-idc"] == 1:
                                nal["abs-diff-pic-num-minus-one"] = buf.rue()
                            elif nal["modification-of-pic-nums-idc"] == 2:
                                nal["long-term-pic-num"] = buf.rue()
                            elif nal["unit-type"] == "Coded slice extension" and (
                                nal["modification-of-pic-nums-idc"] == 4 or nal["modification-of-pic-nums-idc"] == 5
                            ):
                                nal["abs-diff-view-idx-minus-one"] = buf.rue()
                            if nal["modification-of-pic-nums-idc"] == 3:
                                break

                if (state.get("weighted-pred-flag", 0) and nal["slice-type"] % 5 in (0, 3)) or (
                    state.get("weighted-bipred-idc", 0) == 1 and nal["slice-type"] % 5 == 1
                ):
                    nal["luma-log2-weight-denom"] = buf.rue()
                    if state.get("chroma-array-type", 0) != 0:
                        nal["chroma-log2-weight-denom"] = buf.rue()
                    nal["luma-weight-l0-flag"] = {}
                    nal["luma-weight-l0"] = {}
                    nal["luma-offset-l0"] = {}
                    nal["chroma-weight-l0-flag"] = {}
                    nal["chroma-weight-l0"] = {}
                    nal["chroma-offset-l0"] = {}
                    for i in range(
                        0,
                        nal.get("num-ref-idx-l0-active-minus-one", state.get("num-ref-idx-l0-default-active-minus-one", 0)) + 1,
                    ):
                        nal["luma-weight-l0-flag"][i] = buf.rb(1)
                        if nal["luma-weight-l0-flag"][i]:
                            nal["luma-weight-l0"][i] = buf.rse()
                            nal["luma-offset-l0"][i] = buf.rse()
                        if state.get("chroma-array-type", 0) != 0:
                            nal["chroma-weight-l0-flag"][i] = buf.rb(1)
                            if nal["chroma-weight-l0-flag"][i]:
                                nal["chroma-weight-l0"][i] = {}
                                nal["chroma-offset-l0"][i] = {}
                                for j in range(0, 2):
                                    nal["chroma-weight-l0"][i][j] = buf.rse()
                                    nal["chroma-offset-l0"][i][j] = buf.rse()
                    if nal["slice-type"] % 5 == 1:
                        nal["luma-weight-l1-flag"] = {}
                        nal["luma-weight-l1"] = {}
                        nal["luma-offset-l1"] = {}
                        nal["chroma-weight-l1-flag"] = {}
                        nal["chroma-weight-l1"] = {}
                        nal["chroma-offset-l1"] = {}
                        for i in range(
                            0,
                            nal.get("num-ref-idx-l0-active-minus-one", state.get("num-ref-idx-l0-default-active-minus-one", 0))
                            + 1,
                        ):
                            nal["luma-weight-l1-flag"][i] = buf.rb(1)
                            if nal["luma-weight-l1-flag"][i]:
                                nal["luma-weight-l1"][i] = buf.rse()
                                nal["luma-offset-l1"][i] = buf.rse()
                            if state.get("chroma-array-type", 0) != 0:
                                nal["chroma-weight-l1-flag"][i] = buf.rb(1)
                                if nal["chroma-weight-l1-flag"][i]:
                                    nal["chroma-weight-l1"][i] = {}
                                    nal["chroma-offset-l1"][i] = {}
                                    for j in range(0, 2):
                                        nal["chroma-weight-l1"][i][j] = buf.rse()
                                        nal["chroma-offset-l1"][i][j] = buf.rse()

                if nal["ref-idc"] != 0:
                    if nal["unit-type"] == "Coded slice of an IDR picture":
                        nal["no-output-of-prior-pics-flag"] = buf.rb(1)
                        nal["long-term-reference-flag"] = buf.rb(1)
                    else:
                        nal["adaptive-ref-pic-marking-mode-flag"] = buf.rb(1)
                        if nal["adaptive-ref-pic-marking-mode-flag"]:
                            nal["memory-management-control-operation"] = []
                            nal["difference-of-pic-nums-minus-one"] = {}
                            nal["long-term-pic-num"] = {}
                            nal["long-term-frame-idx"] = {}
                            nal["max-long-term-frame-idx-plus-one"] = {}
                            while True:
                                nal["memory-management-control-operation"].append(buf.rue())
                                if nal["memory-management-control-operation"][-1] in (1, 3):
                                    nal["difference-of-pic-nums-minus-one"][
                                        len(nal["memory-management-control-operation"]) - 1
                                    ] = buf.rue()
                                if nal["memory-management-control-operation"][-1] == 2:
                                    nal["long-term-pic-num"][len(nal["memory-management-control-operation"]) - 1] = buf.rue()
                                if nal["memory-management-control-operation"][-1] in (3, 6):
                                    nal["long-term-frame-idx"][len(nal["memory-management-control-operation"]) - 1] = buf.rue()
                                if nal["memory-management-control-operation"][-1] == 4:
                                    nal["max-long-term-frame-idx-plus-one"][
                                        len(nal["memory-management-control-operation"]) - 1
                                    ] = buf.rue()
                                if nal["memory-management-control-operation"][-1] == 0:
                                    break

                if state.get("entropy-coding-mode-flag", 0) and nal["slice-type"] % 5 not in (2, 4):
                    nal["cabac-init-idc"] = buf.rue()

                nal["slice-qp-delta"] = buf.rse()

                if nal["slice-type"] % 5 in (3, 4):
                    if nal["slice-type"] % 5 == 3:
                        nal["sp-for-switch-flag"] = buf.rb(1)
                    nal["slice-qs-delta"] = buf.rse()

                if state.get("deblocking-filter-control-present-flag", 0):
                    nal["disable-deblocking-filter-idc"] = buf.rue()
                    if nal["disable-deblocking-filter-idc"] != 1:
                        nal["slice-alpha-c0-offset-div2"] = buf.rse()
                        nal["slice-beta-offset-div2"] = buf.rse()

                if state.get("num-slice-groups-minus-one", 0) > 0 and 3 <= state.get("slice-group-map-type", 0) <= 5:
                    nal["slice-group-change-cycle"] = buf.rb(
                        math.ceil(
                            math.log2(
                                (
                                    (
                                        (state.get("pic-width-in-mbs-minus-one", 0) + 1)
                                        * (state.get("pic-height-in-map-units-minus-one", 0) + 1)
                                    )
                                    / (state.get("slice-group-change-rate-minus-one", 0) + 1)
                                )
                                + 1
                            )
                        )
                    )

                buf.align()
            case "Supplemental enhancement information":
                # BOOK New FFMpreg H.264 SEI
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

                nal["type"] = utils.unraw(
                    t,
                    1,
                    {
                        0x00: "buffering_period",
                        0x01: "pic_timing",
                        0x05: "user_data_unregistered",
                        0x2d: "frame_packing_arrangement",
                        0x89: "mastering_display_colour_volume",
                        0x90: "content_light_level_info",
                    },
                    True,
                )
                nal["length"] = l

                buf.pasunit(l)

                match nal["type"]:
                    case "user_data_unregistered":
                        nal["uuid"] = buf.ruuid()

                        match nal["uuid"]:
                            case "dc45e9bd-e6d9-48b7-962c-d820d923eeef":
                                nal["libx264-banner"] = buf.rs(buf.unit)
                            case "59948b28-11ec-45af-9675-19d41feaa94d":
                                nal["h264-vaapi-banner"] = buf.rs(buf.unit)
                            case "a4dcf53f-130a-291c-9bd6-1ac002e6bdab":
                                nal["string"] = buf.rs(buf.unit)
                            case _:
                                nal["payload"] = buf.rh(buf.unit)
                                nal["unknown"] = True
                    case "buffering_period":
                        nal["seq-parameter-set-id"] = buf.rue()

                        v = state.get("hrd-parameters", {}).get("initial-cpb-removal-delay-length-minus-one", 0) + 1

                        if state.get("nal-hrd-parameters-present-flag"):
                            nal["nal-initial-cpb-removal-delay-and-offset"] = [
                                (buf.rb(v), buf.rb(v))
                                for i in range(0, state.get("hrd-parameters", {}).get("cpb-cnt-minus-one", 0) + 1)
                            ]

                        if state.get("vcl-hrd-parameters-present-flag"):
                            nal["vcl-initial-cpb-removal-delay-and-offset"] = [
                                (buf.rb(v), buf.rb(v))
                                for i in range(0, state.get("vcl-hrd-parameters", {}).get("cpb-cnt-minus-one", 0) + 1)
                            ]
                    case "pic_timing":
                        params = state.get("hrd-parameters", state.get("vcl-hrd-parameters", {}))

                        if state.get("nal-hrd-parameters-present-flag") or state.get("vcl-hrd-parameters-present-flag"):
                            nal["cpb-removal-delay"] = buf.rb(params.get("cpb-removal-delay-length-minus-one", 0) + 1)
                            nal["dpb-output-delay"] = buf.rb(params.get("dpb-output-delay-length-minus-one", 0) + 1)
                        if state.get("pic-struct-present-flag"):
                            nal["pic-struct"] = buf.rb(4)
                            nal["clock-ts"] = []
                            for i in range({0: 1, 1: 1, 2: 1, 3: 2, 4: 2, 5: 3, 6: 3, 7: 2, 8: 3}[nal["pic-struct"]]):
                                ts = {}
                                ts["clock-timestamp-flag"] = buf.rb(1)
                                if ts["clock-timestamp-flag"]:
                                    ts["ct-type"] = buf.rb(2)
                                    ts["nuit-field-based-flag"] = buf.rb(1)
                                    ts["counting-type"] = buf.rb(5)
                                    ts["full-timestamp-flag"] = buf.rb(1)
                                    ts["discontinuity-flag"] = buf.rb(1)
                                    ts["cnt-dropped-flag"] = buf.rb(1)
                                    ts["n-frames"] = buf.rb(8)
                                    if ts["full-timestamp-flag"]:
                                        ts["seconds-value"] = buf.rb(6)
                                        ts["minutes-value"] = buf.rb(6)
                                        ts["hours-value"] = buf.rb(5)
                                    else:
                                        ts["seconds-flag"] = buf.rb(1)
                                        if ts["seconds-flag"]:
                                            ts["seconds-value"] = buf.rb(6)
                                            ts["minutes-flag"] = buf.rb(1)
                                            if ts["minutes-flag"]:
                                                ts["minutes-value"] = buf.rb(6)
                                                ts["hours-flag"] = buf.rb(1)
                                                if ts["hours-flag"]:
                                                    ts["hours-value"] = buf.rb(5)
                                    if params.get("time-offset-length", 0) > 0:
                                        ts["time-offset"] = buf.rb(params.get("time-offset-length", 0))

                                nal["clock-ts"].append(ts)
                    case "frame_packing_arrangement":
                        nal["frame-packing-arrangement-id"] = buf.rue()
                        nal["frame-packing-arrangement-cancel-flag"] = buf.rb(1)
                        if not nal["frame-packing-arrangement-cancel-flag"]:
                            nal["frame-packing-arrangement-type"] = buf.rb(7)
                            nal["quincunx-sampling-flag"] = buf.rb(1)
                            nal["content-interpretation-type"] = buf.rb(6)
                            nal["spatial-flipping-flag"] = buf.rb(1)
                            nal["frame0-flipped-flag"] = buf.rb(1)
                            nal["field-views-flag"] = buf.rb(1)
                            nal["current-frame-is-frame0-flag"] = buf.rb(1)
                            nal["frame0-self-contained-flag"] = buf.rb(1)
                            nal["frame1-self-contained-flag"] = buf.rb(1)
                            if not nal["quincunx-sampling-flag"] and nal["frame-packing-arrangement-type"] != 5:
                                nal["frame0-grid-position-x"] = buf.rb(4)
                                nal["frame0-grid-position-y"] = buf.rb(4)
                                nal["frame1-grid-position-x"] = buf.rb(4)
                                nal["frame1-grid-position-y"] = buf.rb(4)
                            nal["frame-packing-arrangement-reserved-byte"] = buf.rb(8)
                            nal["frame-packing-arrangement-repetition-period"] = buf.rue()
                        nal["frame-packing-arrangement-extension-flag"] = buf.rb(1)
                    case "mastering_display_colour_volume":
                        nal["mdcv-display-primaries"] = [(buf.ru16(), buf.ru16()) for i in range(0, 3)]
                        nal["mdcv-white-point"] = (buf.ru16(), buf.ru16())
                        nal["mdcv-max-display-mastering-luminance"] = buf.ru32()
                        nal["mdcv-min-display-mastering-luminance"] = buf.ru32()
                    case "content_light_level_info":
                        nal["clli-max-content-light-level"] = buf.ru16()
                        nal["clli-max-pic-average-light-level"] = buf.ru16()
                    case _:
                        nal["payload"] = buf.rh(buf.unit)
                        nal["unknown"] = True

                buf.sapunit()
            case "Access unit delimiter":
                nal["primary-pic-type"] = utils.unraw(
                    buf.rb(3),
                    1,
                    {
                        0x00: "2/7",
                        0x01: "0/2/5/7",
                        0x02: "0/1/2/5/6/7",
                        0x03: "4/9",
                        0x04: "3/4/8/9",
                        0x05: "2/4/7/9",
                        0x06: "0/2/3/4/5/7/8/9",
                        0x07: "0/1/2/3/4/5/6/7/8/9",
                    },
                    True,
                )
                buf.align()
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

        # BOOK New FFMpreg AV1 OBU
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
                    nal["du-cpb-removal-delay-increment-length-minus-one"] = buf.rb(5)
                    nal["sub-pic-cpb-params-in-pic-timing-sei-flag"] = buf.rb(1)
                    nal["dpb-output-delay-du-length-minus-one"] = buf.rb(5)

                nal["bit-rate-scale"] = buf.rb(4)
                nal["cpb-size-scale"] = buf.rb(4)

                if nal.get("sub-pic-hrd-params-present-flag"):
                    nal["cpb-size-du-scale"] = buf.rb(4)

                nal["initial-cpb-removal-delay-length-minus-one"] = buf.rb(5)
                nal["au-cpb-removal-delay-length-minus-one"] = buf.rb(5)
                nal["dpb-output-delay-length-minus-one"] = buf.rb(5)

        for i in range(max_sub_layers_minus_one + 1):
            if "fixed-pic-rate-general-flag" not in nal:
                nal["fixed-pic-rate-general-flag"] = {}
            nal["fixed-pic-rate-general-flag"][i] = buf.rb(1)

            if not nal["fixed-pic-rate-general-flag"][i]:
                if "fixed-pic-rate-within-cvs-flag" not in nal:
                    nal["fixed-pic-rate-within-cvs-flag"] = {}
                nal["fixed-pic-rate-within-cvs-flag"][i] = buf.rb(1)

            if nal.get("fixed-pic-rate-within-cvs-flag", {}).get(i, nal["fixed-pic-rate-general-flag"][i]):
                if "elemental-duration-in-tc-minus-one" not in nal:
                    nal["elemental-duration-in-tc-minus-one"] = {}
                nal["elemental-duration-in-tc-minus-one"][i] = buf.rue()
            else:
                if "low-delay-hrd-flag" not in nal:
                    nal["low-delay-hrd-flag"] = {}
                nal["low-delay-hrd-flag"][i] = buf.rb(1)

            if not nal.get("low-delay-hrd-flag", {}).get(i, 0):
                if "cpb-cnt-minus-one" not in nal:
                    nal["cpb-cnt-minus-one"] = {}
                nal["cpb-cnt-minus-one"][i] = buf.rue()

            if nal.get("nal-hrd-parameters-present-flag"):
                for j in range(nal.get("cpb-cnt-minus-one", {}).get(i, 0) + 1):
                    if "bit-rate-value-minus-one" not in nal:
                        nal["bit-rate-value-minus-one"] = {}
                    nal["bit-rate-value-minus-one"][j] = buf.rue()

                    if "cpb-size-value-minus-one" not in nal:
                        nal["cpb-size-value-minus-one"] = {}
                    nal["cpb-size-value-minus-one"][j] = buf.rue()

                    if nal.get("sub-pic-hrd-params-present-flag"):
                        if "cpb-size-du-value-minus-one" not in nal:
                            nal["cpb-size-du-value-minus-one"] = {}
                        nal["cpb-size-du-value-minus-one"][j] = buf.rue()

                        if "bit-rate-du-value-minus-one" not in nal:
                            nal["bit-rate-du-value-minus-one"] = {}
                        nal["bit-rate-du-value-minus-one"][j] = buf.rue()

                    if "cbr-flag" not in nal:
                        nal["cbr-flag"] = {}
                    nal["cbr-flag"][j] = buf.rb(1)

            if nal.get("vcl-hrd-parameters-present-flag"):
                for j in range(nal.get("cpb-cnt-minus-one", {}).get(i, 0) + 1):
                    if "bit-rate-value-minus-one" not in nal:
                        nal["bit-rate-value-minus-one"] = {}
                    nal["bit-rate-value-minus-one"][j] = buf.rue()

                    if "cpb-size-value-minus-one" not in nal:
                        nal["cpb-size-value-minus-one"] = {}
                    nal["cpb-size-value-minus-one"][j] = buf.rue()

                    if nal.get("sub-pic-hrd-params-present-flag"):
                        if "cpb-size-du-value-minus-one" not in nal:
                            nal["cpb-size-du-value-minus-one"] = {}
                        nal["cpb-size-du-value-minus-one"][j] = buf.rue()

                        if "bit-rate-du-value-minus-one" not in nal:
                            nal["bit-rate-du-value-minus-one"] = {}
                        nal["bit-rate-du-value-minus-one"][j] = buf.rue()

                    if "cbr-flag" not in nal:
                        nal["cbr-flag"] = {}
                    nal["cbr-flag"][j] = buf.rb(1)

        return nal

    @staticmethod
    def read_h265_scaling_list(buf: Buf) -> dict:
        nal: dict = {}
        nal["scaling-list-pred-mode-flag"] = [[0] * 6 for _ in range(4)]
        nal["scaling-list-pred-matrix-id-delta"] = [[0] * 6 for _ in range(4)]
        nal["scaling-list-dc-coef-minus-eight"] = [[0] * 6 for _ in range(2)]
        nal["scaling-list-delta-coef"] = []
        nal["scaling-list"] = [[[0] * 64 for _ in range(6)] for _ in range(4)]

        for size_id in range(0, 4):
            matrix_id = 0
            while matrix_id < 6:
                nal["scaling-list-pred-mode-flag"][size_id][matrix_id] = buf.rb(1)
                if not nal["scaling-list-pred-mode-flag"][size_id][matrix_id]:
                    nal["scaling-list-pred-matrix-id-delta"][size_id][matrix_id] = buf.rue()
                else:
                    next_coef = 8
                    coef_num = min(64, 1 << (4 + (size_id << 1)))
                    if size_id > 1:
                        nal["scaling-list-dc-coef-minus-eight"][size_id - 2][matrix_id] = buf.rse()
                        next_coef = nal["scaling-list-dc-coef-minus-eight"][size_id - 2][matrix_id] + 8
                    for i in range(coef_num):
                        delta = buf.rse()
                        nal["scaling-list-delta-coef"].append(delta)
                        next_coef = (next_coef + delta + 256) % 256
                        nal["scaling-list"][size_id][matrix_id][i] = next_coef
                matrix_id += 3 if size_id == 3 else 1

        return nal

    @staticmethod
    def read_h265_nalu(buf: Buf, state={}) -> dict:
        buf = Buf(buf.read(buf.unit).replace(b"\x00\x00\x03", b"\x00\x00"))

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

        # BOOK New FFMpreg H.265 NAL
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
                nal["max-layers-minus-one"] = buf.rb(6)
                nal["max-sub-layers-minus-one"] = buf.rb(3)
                nal["temporal-id-nesting-flag"] = buf.rb(1)
                nal["reserved"] = buf.ru16()
                nal["profile-tier-level"] = FFMpreg.read_h265_profile_tier_level(buf, 1, nal["max-sub-layers-minus-one"])
                nal["sub-layer-ordering-info-present-flag"] = buf.rb(1)
                nal["sub-layer-ordering-infos"] = [
                    {
                        "max-dec-pic-buffering-minus-one": buf.rue(),
                        "max-num-reorder-pics": buf.rue(),
                        "max-latency-increase-plus1": buf.rue(),
                    }
                    for i in range(0, nal["max-sub-layers-minus-one"] + 1 if nal["sub-layer-ordering-info-present-flag"] else 1)
                ]
                nal["max-layer-id"] = buf.rb(6)
                nal["num-layer-sets-minus-one"] = buf.rue()
                nal["layer-id-included-flags"] = [
                    buf.rb(nal["max-layer-id"] + 1) for i in range(0, nal["num-layer-sets-minus-one"])
                ]
                nal["timing-info-present-flag"] = buf.rb(1)

                if nal["timing-info-present-flag"]:
                    nal["num-units-in-tick"] = buf.rb(32)
                    nal["time-scale"] = buf.rb(32)
                    nal["poc-proportional-to-timing-flag"] = buf.rb(1)

                    if nal["poc-proportional-to-timing-flag"]:
                        nal["num-ticks-poc-diff-one-minus-one"] = buf.rue()

                    nal["num-hrd-parameters"] = buf.rue()

                    nal["hrd-parameters"] = []
                    for i in range(0, nal["num-hrd-parameters"]):
                        hrd = {}
                        hrd["hrd-layer-set-idx"] = buf.rue()

                        if i > 0:
                            hrd["cprms-present-flag"] = buf.rb(1)

                        hrd |= FFMpreg.read_h265_hrd_parameters(
                            buf, hrd.get("cprms-present-flag", 1), nal["max-sub-layers-minus-one"]
                        )

                nal["extension-flag"] = buf.rb(1)
                if nal["extension-flag"]:
                    i = buf.rb(buf.available() * 8 - buf._bits)

                    while i and not i & 1:
                        i >>= 1

                    nal["extension-data-flag"] = i >> 1

                buf.align()
            case "SPS_NUT":
                nal["sps-video-parameter-set-id"] = buf.rb(4)
                nal["sps-max-sub-layers-minus-one"] = buf.rb(3)
                nal["sps-temporal-id-nesting-flag"] = buf.rb(1)
                nal["profile-tier-level"] = FFMpreg.read_h265_profile_tier_level(buf, 1, nal["sps-max-sub-layers-minus-one"])
                nal["sps-seq-parameter-set-id"] = buf.rue()
                nal["chroma-format-idc"] = buf.rue()
                if nal["chroma-format-idc"] == 3:
                    nal["separate-colour-plane-flag"] = buf.rb(1)
                nal["pic-width-in-luma-samples"] = buf.rue()
                nal["pic-height-in-luma-samples"] = buf.rue()
                nal["conformance-window-flag"] = buf.rb(1)
                if nal["conformance-window-flag"]:
                    nal["conf-win-left-offset"] = buf.rue()
                    nal["conf-win-right-offset"] = buf.rue()
                    nal["conf-win-top-offset"] = buf.rue()
                    nal["conf-win-bottom-offset"] = buf.rue()
                nal["bit-depth-luma-minus-eight"] = buf.rue()
                nal["bit-depth-chroma-minus-eight"] = buf.rue()
                nal["log2-max-pic-order-cnt-lsb-minus-four"] = buf.rue()
                nal["sps-sub-layer-ordering-info-present-flag"] = buf.rb(1)
                nal["sps-max-dec-pic-buffering-minus-one"] = [0] * (nal["sps-max-sub-layers-minus-one"] + 1)
                nal["sps-max-num-reorder-pics"] = [0] * (nal["sps-max-sub-layers-minus-one"] + 1)
                nal["sps-max-latency-increase-plus1"] = [0] * (nal["sps-max-sub-layers-minus-one"] + 1)
                for i in range(
                    0 if nal["sps-sub-layer-ordering-info-present-flag"] else nal["sps-max-sub-layers-minus-one"],
                    nal["sps-max-sub-layers-minus-one"] + 1,
                ):
                    nal["sps-max-dec-pic-buffering-minus-one"][i] = buf.rue()
                    nal["sps-max-num-reorder-pics"][i] = buf.rue()
                    nal["sps-max-latency-increase-plus1"][i] = buf.rue()
                nal["log2-min-luma-coding-block-size-minus3"] = buf.rue()
                nal["log2-diff-max-min-luma-coding-block-size"] = buf.rue()
                nal["log2-min-luma-transform-block-size-minus2"] = buf.rue()
                nal["log2-diff-max-min-luma-transform-block-size"] = buf.rue()
                nal["max-transform-hierarchy-depth-inter"] = buf.rue()
                nal["max-transform-hierarchy-depth-intra"] = buf.rue()
                nal["scaling-list-enabled-flag"] = buf.rb(1)
                if nal["scaling-list-enabled-flag"]:
                    nal["sps-scaling-list-data-present-flag"] = buf.rb(1)
                    if nal["sps-scaling-list-data-present-flag"]:
                        nal["scaling-list"] = FFMpreg.read_h265_scaling_list(buf)
                nal["amp-enabled-flag"] = buf.rb(1)
                nal["sample-adaptive-offset-enabled-flag"] = buf.rb(1)
                nal["pcm-enabled-flag"] = buf.rb(1)
                if nal["pcm-enabled-flag"]:
                    nal["pcm-sample-bit-depth-luma-minus-one"] = buf.rb(4)
                    nal["pcm-sample-bit-depth-chroma-minus-one"] = buf.rb(4)
                    nal["log2-min-pcm-luma-coding-block-size-minus3"] = buf.rue()
                    nal["log2-diff-max-min-pcm-luma-coding-block-size"] = buf.rue()
                    nal["pcm-loop-filter-disabled-flag"] = buf.rb(1)
                nal["num-short-term-ref-pic-sets"] = buf.rue()
                nal["inter-ref-pic-set-prediction-flag"] = [0] * nal["num-short-term-ref-pic-sets"]
                nal["delta-idx-minus-one"] = [0] * (nal["num-short-term-ref-pic-sets"] + 1)
                nal["delta-rps-sign"] = [0] * nal["num-short-term-ref-pic-sets"]
                nal["abs-delta-rps-minus-one"] = [0] * nal["num-short-term-ref-pic-sets"]
                nal["used-by-curr-pic-flag"] = []
                nal["use-delta-flag"] = []
                nal["num-negative-pics"] = [0] * nal["num-short-term-ref-pic-sets"]
                nal["num-positive-pics"] = [0] * nal["num-short-term-ref-pic-sets"]
                nal["delta-poc-s0-minus-one"] = []
                nal["used-by-curr-pic-s0-flag"] = []
                nal["delta-poc-s1-minus-one"] = []
                nal["used-by-curr-pic-s1-flag"] = []
                num_delta_pocs = [0] * nal["num-short-term-ref-pic-sets"]
                for st_rps_idx in range(0, nal["num-short-term-ref-pic-sets"]):
                    if st_rps_idx != 0:
                        nal["inter-ref-pic-set-prediction-flag"][st_rps_idx] = buf.rb(1)
                    if nal["inter-ref-pic-set-prediction-flag"][st_rps_idx]:
                        if st_rps_idx == nal["num-short-term-ref-pic-sets"]:
                            nal["delta-idx-minus-one"][st_rps_idx] = buf.rue()
                        ref_rps_idx = st_rps_idx - (nal["delta-idx-minus-one"][st_rps_idx] + 1)
                        nal["delta-rps-sign"][st_rps_idx] = buf.rb(1)
                        nal["abs-delta-rps-minus-one"][st_rps_idx] = buf.rue()
                        used_by_curr = []
                        use_delta = []
                        for j in range(0, num_delta_pocs[ref_rps_idx] + 1):
                            u_curr = buf.rb(1)
                            used_by_curr.append(u_curr)
                            u_delta = 0
                            if not u_curr:
                                u_delta = buf.rb(1)
                            use_delta.append(u_delta)
                        nal["used-by-curr-pic-flag"].append(used_by_curr)
                        nal["use-delta-flag"].append(use_delta)
                        num_delta_pocs[st_rps_idx] = sum(
                            1 for k in range(0, num_delta_pocs[ref_rps_idx] + 1) if used_by_curr[k] or use_delta[k]
                        )
                    else:
                        nal["num-negative-pics"][st_rps_idx] = buf.rue()
                        nal["num-positive-pics"][st_rps_idx] = buf.rue()
                        num_delta_pocs[st_rps_idx] = nal["num-negative-pics"][st_rps_idx] + nal["num-positive-pics"][st_rps_idx]
                        d_poc_s0 = []
                        u_s0 = []
                        for i in range(0, nal["num-negative-pics"][st_rps_idx]):
                            d_poc_s0.append(buf.rue())
                            u_s0.append(buf.rb(1))
                        nal["delta-poc-s0-minus-one"].append(d_poc_s0)
                        nal["used-by-curr-pic-s0-flag"].append(u_s0)
                        d_poc_s1 = []
                        u_s1 = []
                        for i in range(0, nal["num-positive-pics"][st_rps_idx]):
                            d_poc_s1.append(buf.rue())
                            u_s1.append(buf.rb(1))
                        nal["delta-poc-s1-minus-one"].append(d_poc_s1)
                        nal["used-by-curr-pic-s1-flag"].append(u_s1)
                nal["long-term-ref-pics-present-flag"] = buf.rb(1)
                if nal["long-term-ref-pics-present-flag"]:
                    nal["num-long-term-ref-pics-sps"] = buf.rue()
                    nal["lt-ref-pic-poc-lsb-sps"] = [0] * nal["num-long-term-ref-pics-sps"]
                    nal["used-by-curr-pic-lt-sps-flag"] = [0] * nal["num-long-term-ref-pics-sps"]
                    for i in range(0, nal["num-long-term-ref-pics-sps"]):
                        nal["lt-ref-pic-poc-lsb-sps"][i] = buf.rb(nal["log2-max-pic-order-cnt-lsb-minus-four"] + 4)
                        nal["used-by-curr-pic-lt-sps-flag"][i] = buf.rb(1)
                nal["sps-temporal-mvp-enabled-flag"] = buf.rb(1)
                nal["strong-intra-smoothing-enabled-flag"] = buf.rb(1)
                nal["vui-parameters-present-flag"] = buf.rb(1)
                if nal["vui-parameters-present-flag"]:
                    nal["aspect-ratio-info-present-flag"] = buf.rb(1)
                    if nal["aspect-ratio-info-present-flag"]:
                        nal["aspect-ratio-idc"] = buf.rb(8)
                        if nal["aspect-ratio-idc"] == 255:
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
                            nal["matrix-coeffs"] = buf.rb(8)
                    nal["chroma-loc-info-present-flag"] = buf.rb(1)
                    if nal["chroma-loc-info-present-flag"]:
                        nal["chroma-sample-loc-type-top-field"] = buf.rue()
                        nal["chroma-sample-loc-type-bottom-field"] = buf.rue()
                    nal["neutral-chroma-indication-flag"] = buf.rb(1)
                    nal["field-seq-flag"] = buf.rb(1)
                    nal["frame-field-info-present-flag"] = buf.rb(1)
                    nal["default-display-window-flag"] = buf.rb(1)
                    if nal["default-display-window-flag"]:
                        nal["def-disp-win-left-offset"] = buf.rue()
                        nal["def-disp-win-right-offset"] = buf.rue()
                        nal["def-disp-win-top-offset"] = buf.rue()
                        nal["def-disp-win-bottom-offset"] = buf.rue()
                    nal["vui-timing-info-present-flag"] = buf.rb(1)
                    if nal["vui-timing-info-present-flag"]:
                        nal["vui-num-units-in-tick"] = buf.rb(32)
                        nal["vui-time-scale"] = buf.rb(32)
                        nal["vui-poc-proportional-to-timing-flag"] = buf.rb(1)
                        if nal["vui-poc-proportional-to-timing-flag"]:
                            nal["vui-num-ticks-poc-diff-one-minus-one"] = buf.rue()
                        nal["vui-hrd-parameters-present-flag"] = buf.rb(1)
                        if nal["vui-hrd-parameters-present-flag"]:
                            nal["vui-hrd-parameters"] = FFMpreg.read_h265_hrd_parameters(
                                buf, 1, nal["sps-max-sub-layers-minus-one"]
                            )
                    nal["bitstream-restriction-flag"] = buf.rb(1)
                    if nal["bitstream-restriction-flag"]:
                        nal["tiles-fixed-structure-flag"] = buf.rb(1)
                        nal["motion-vectors-over-pic-boundaries-flag"] = buf.rb(1)
                        nal["restricted-ref-pic-lists-flag"] = buf.rb(1)
                        nal["min-spatial-segmentation-idc"] = buf.rue()
                        nal["max-bytes-per-pic-denom"] = buf.rue()
                        nal["max-bits-per-min-cu-denom"] = buf.rue()
                        nal["log2-max-mv-length-horizontal"] = buf.rue()
                        nal["log2-max-mv-length-vertical"] = buf.rue()
                nal["sps-extension-present-flag"] = buf.rb(1)
                if nal["sps-extension-present-flag"]:
                    nal["sps-range-extension-flag"] = buf.rb(1)
                    nal["sps-multilayer-extension-flag"] = buf.rb(1)
                    nal["sps-extension-6bits"] = buf.rb(6)
                if nal.get("sps-range-extension-flag"):
                    nal["transform-skip-rotation-enabled-flag"] = buf.rb(1)
                    nal["transform-skip-context-enabled-flag"] = buf.rb(1)
                    nal["implicit-rdpcm-enabled-flag"] = buf.rb(1)
                    nal["explicit-rdpcm-enabled-flag"] = buf.rb(1)
                    nal["extended-precision-processing-flag"] = buf.rb(1)
                    nal["intra-smoothing-disabled-flag"] = buf.rb(1)
                    nal["high-precision-offsets-enabled-flag"] = buf.rb(1)
                    nal["persistent-rice-adaptation-enabled-flag"] = buf.rb(1)
                    nal["cabac-bypass-alignment-enabled-flag"] = buf.rb(1)
                if nal.get("sps-multilayer-extension-flag"):
                    nal["inter-view-mv-vert-constraint-flag"] = buf.rb(1)
            case "PPS_NUT":
                nal["pps-pic-parameter-set-id"] = buf.rue()
                nal["pps-seq-parameter-set-id"] = buf.rue()
                nal["dependent-slice-segments-enabled-flag"] = buf.rb(1)
                nal["output-flag-present-flag"] = buf.rb(1)
                nal["num-extra-slice-header-bits"] = buf.rb(3)
                nal["sign-data-hiding-enabled-flag"] = buf.rb(1)
                nal["cabac-init-present-flag"] = buf.rb(1)
                nal["num-ref-idx-l0-default-active-minus-one"] = buf.rue()
                nal["num-ref-idx-l1-default-active-minus-one"] = buf.rue()
                nal["init-qp-minus26"] = buf.rse()
                nal["constrained-intra-pred-flag"] = buf.rb(1)
                nal["transform-skip-enabled-flag"] = buf.rb(1)
                nal["cu-qp-delta-enabled-flag"] = buf.rb(1)
                if nal["cu-qp-delta-enabled-flag"]:
                    nal["diff-cu-qp-delta-depth"] = buf.rue()
                nal["pps-cb-qp-offset"] = buf.rse()
                nal["pps-cr-qp-offset"] = buf.rse()
                nal["pps-slice-chroma-qp-offsets-present-flag"] = buf.rb(1)
                nal["weighted-pred-flag"] = buf.rb(1)
                nal["weighted-bipred-flag"] = buf.rb(1)
                nal["transquant-bypass-enabled-flag"] = buf.rb(1)
                nal["tiles-enabled-flag"] = buf.rb(1)
                nal["entropy-coding-sync-enabled-flag"] = buf.rb(1)
                if nal["tiles-enabled-flag"]:
                    nal["num-tile-columns-minus-one"] = buf.rue()
                    nal["num-tile-rows-minus-one"] = buf.rue()
                    nal["uniform-spacing-flag"] = buf.rb(1)
                    if not nal["uniform-spacing-flag"]:
                        nal["column-width-minus-one"] = [buf.rue() for i in range(0, nal["num-tile-columns-minus-one"])]
                        nal["row-height-minus-one"] = [buf.rue() for i in range(0, nal["num-tile-rows-minus-one"])]
                    nal["loop-filter-across-tiles-enabled-flag"] = buf.rb(1)
                nal["pps-loop-filter-across-slices-enabled-flag"] = buf.rb(1)
                nal["deblocking-filter-control-present-flag"] = buf.rb(1)
                if nal["deblocking-filter-control-present-flag"]:
                    nal["deblocking-filter-override-enabled-flag"] = buf.rb(1)
                    nal["pps-deblocking-filter-disabled-flag"] = buf.rb(1)
                    if not nal["pps-deblocking-filter-disabled-flag"]:
                        nal["pps-beta-offset-div2"] = buf.rse()
                        nal["pps-tc-offset-div2"] = buf.rse()
                nal["pps-scaling-list-data-present-flag"] = buf.rb(1)
                if nal["pps-scaling-list-data-present-flag"]:
                    nal["scaling-list-data"] = FFMpreg.read_h265_scaling_list(buf)
                nal["lists-modification-present-flag"] = buf.rb(1)
                nal["log2-parallel-merge-level-minus2"] = buf.rue()
                nal["slice-segment-header-extension-present-flag"] = buf.rb(1)
                nal["pps-extension-present-flag"] = buf.rb(1)
                if nal["pps-extension-present-flag"]:
                    nal["pps-range-extension-flag"] = buf.rb(1)
                    nal["pps-multilayer-extension-flag"] = buf.rb(1)
                    nal["pps-extension-6bits"] = buf.rb(6)
                if nal.get("pps-range-extension-flag"):
                    if nal["transform-skip-enabled-flag"]:
                        nal["log2-max-transform-skip-block-size-minus2"] = buf.rue()
                    nal["cross-component-prediction-enabled-flag"] = buf.rb(1)
                    nal["chroma-qp-offset-list-enabled-flag"] = buf.rb(1)
                    if nal["chroma-qp-offset-list-enabled-flag"]:
                        nal["diff-cu-chroma-qp-offset-depth"] = buf.rue()
                        nal["chroma-qp-offset-list-len-minus-one"] = buf.rue()
                        nal["cb-qp-offset-list"] = []
                        nal["cr-qp-offset-list"] = []
                        for i in range(0, nal["chroma-qp-offset-list-len-minus-one"] + 1):
                            nal["cb-qp-offset-list"].append(buf.rse())
                            nal["cr-qp-offset-list"].append(buf.rse())
                    nal["log2-sao-offset-scale-luma"] = buf.rue()
                    nal["log2-sao-offset-scale-chroma"] = buf.rue()
                if nal.get("pps-multilayer-extension-flag"):
                    nal["poc-reset-info-present-flag"] = buf.rb(1)
                    nal["pps-infer-scaling-list-flag"] = buf.rb(1)
                    if nal["pps-infer-scaling-list-flag"]:
                        nal["pps-scaling-list-ref-layer-id"] = buf.rb(6)
                    nal["num-ref-loc-offsets"] = buf.rue()
                    nal["ref-loc-offset-layer-id"] = []
                    nal["scaled-ref-layer-offset-present-flag"] = []
                    nal["scaled-ref-layer-left-offset"] = {}
                    nal["scaled-ref-layer-top-offset"] = {}
                    nal["scaled-ref-layer-right-offset"] = {}
                    nal["scaled-ref-layer-bottom-offset"] = {}
                    nal["ref-region-offset-present-flag"] = []
                    nal["ref-region-left-offset"] = {}
                    nal["ref-region-top-offset"] = {}
                    nal["ref-region-right-offset"] = {}
                    nal["ref-region-bottom-offset"] = {}
                    nal["resample-phase-set-present-flag"] = []
                    nal["phase-hor-luma"] = {}
                    nal["phase-ver-luma"] = {}
                    nal["phase-hor-chroma-plus8"] = {}
                    nal["phase-ver-chroma-plus8"] = {}
                    for i in range(0, nal["num-ref-loc-offsets"]):
                        nal["ref-loc-offset-layer-id"].append(buf.rb(6))
                        nal["scaled-ref-layer-offset-present-flag"].append(buf.rb(1))
                        if nal["scaled-ref-layer-offset-present-flag"][i]:
                            nal["scaled-ref-layer-left-offset"][nal["ref-loc-offset-layer-id"][i]] = buf.rse()
                            nal["scaled-ref-layer-top-offset"][nal["ref-loc-offset-layer-id"][i]] = buf.rse()
                            nal["scaled-ref-layer-right-offset"][nal["ref-loc-offset-layer-id"][i]] = buf.rse()
                            nal["scaled-ref-layer-bottom-offset"][nal["ref-loc-offset-layer-id"][i]] = buf.rse()
                        nal["ref-region-offset-present-flag"].append(buf.rb(1))
                        if nal["ref-region-offset-present-flag"][i]:
                            nal["ref-region-left-offset"][nal["ref-loc-offset-layer-id"][i]] = buf.rse()
                            nal["ref-region-top-offset"][nal["ref-loc-offset-layer-id"][i]] = buf.rse()
                            nal["ref-region-right-offset"][nal["ref-loc-offset-layer-id"][i]] = buf.rse()
                            nal["ref-region-bottom-offset"][nal["ref-loc-offset-layer-id"][i]] = buf.rse()
                        nal["resample-phase-set-present-flag"].append(buf.rb(1))
                        if nal["resample-phase-set-present-flag"][i]:
                            nal["phase-hor-luma"][nal["ref-loc-offset-layer-id"][i]] = buf.rue()
                            nal["phase-ver-luma"][nal["ref-loc-offset-layer-id"][i]] = buf.rue()
                            nal["phase-hor-chroma-plus8"][nal["ref-loc-offset-layer-id"][i]] = buf.rue()
                            nal["phase-ver-chroma-plus8"][nal["ref-loc-offset-layer-id"][i]] = buf.rue()
                    nal["colour-mapping-enabled-flag"] = buf.rb(1)
                    if nal["colour-mapping-enabled-flag"]:
                        nal["num-cm-ref-layers-minus-one"] = buf.rue()
                        nal["cm-ref-layer-id"] = [buf.rb(6) for i in range(0, nal["num-cm-ref-layers-minus-one"] + 1)]
                        nal["cm-octant-depth"] = buf.rb(2)
                        nal["cm-y-part-num-log2"] = buf.rb(2)
                        nal["luma-bit-depth-cm-input-minus-eight"] = buf.rue()
                        nal["chroma-bit-depth-cm-input-minus-eight"] = buf.rue()
                        nal["luma-bit-depth-cm-output-minus-eight"] = buf.rue()
                        nal["chroma-bit-depth-cm-output-minus-eight"] = buf.rue()
                        nal["cm-res-quant-bits"] = buf.rb(2)
                        nal["cm-delta-flc-bits-minus-one"] = buf.rb(2)
                        if nal["cm-octant-depth"] == 1:
                            nal["cm-adapt-threshold-u-delta"] = buf.rse()
                            nal["cm-adapt-threshold-v-delta"] = buf.rse()
                        stack = [(0, 0, 0, 0, 1 << nal["cm-octant-depth"])]
                        nal["split-octant-flag"] = []
                        nal["coded-res-flag"] = {}
                        nal["res-coeff-q"] = {}
                        nal["res-coeff-r"] = {}
                        nal["res-coeff-s"] = {}
                        while stack:
                            inp_depth, idx_y, idx_cb, idx_cr, inp_length = stack.pop()
                            split_flag = 0
                            if inp_depth < nal["cm-octant-depth"]:
                                split_flag = buf.rb(1)
                                nal["split-octant-flag"].append(split_flag)
                            if split_flag:
                                for k in range(1, -1, -1):
                                    for m in range(1, -1, -1):
                                        for n in range(1, -1, -1):
                                            stack.append((
                                                inp_depth + 1,
                                                idx_y + (1 << nal["cm-y-part-num-log2"]) * k * (inp_length // 2),
                                                idx_cb + m * (inp_length // 2),
                                                idx_cr + n * (inp_length // 2),
                                                inp_length // 2,
                                            ))
                            else:
                                for i in range(0, 1 << nal["cm-y-part-num-log2"]):
                                    idx_shift_y = idx_y + (i << (nal["cm-octant-depth"] - inp_depth))
                                    for j in range(0, 4):
                                        coded_res = buf.rb(1)
                                        nal["coded-res-flag"].setdefault(idx_shift_y, {}).setdefault(idx_cb, {}).setdefault(
                                            idx_cr, {}
                                        )[j] = coded_res
                                        if coded_res:
                                            for c in range(0, 3):
                                                q_val = buf.rue()
                                                r_val = buf.rb(nal["cm-res-quant-bits"])
                                                nal["res-coeff-q"].setdefault(idx_shift_y, {}).setdefault(
                                                    idx_cb, {}
                                                ).setdefault(idx_cr, {}).setdefault(j, {})[c] = q_val
                                                nal["res-coeff-r"].setdefault(idx_shift_y, {}).setdefault(
                                                    idx_cb, {}
                                                ).setdefault(idx_cr, {}).setdefault(j, {})[c] = r_val
                                                if q_val or r_val:
                                                    nal["res-coeff-s"].setdefault(idx_shift_y, {}).setdefault(
                                                        idx_cb, {}
                                                    ).setdefault(idx_cr, {}).setdefault(j, {})[c] = buf.rb(1)

            case _:
                nal["unknown"] = True

        return nal

    @staticmethod
    def read_h266_nalu(buf: Buf, state={}) -> dict:
        buf = Buf(buf.read(buf.unit).replace(b"\x00\x00\x03", b"\x00\x00"))

        nal = {}
        nal["length"] = buf.available()
        nal["forbidden-zero-bit"] = buf.rb(1)
        nal["nuh-reserved-zero-bit"] = buf.rb(1)
        nal["nuh-layer-id"] = buf.rb(6)
        nal["unit-type"] = utils.unraw(buf.rb(5), 1, FFMpreg.H266_NAL_UNIT_TYPES, True)
        nal["nuh-temporal-id-plus-one"] = buf.rb(3)

        # BOOK New FFMpreg H.266 NAL
        match nal["unit-type"]:
            case "AUD_NUT":
                nal["irap-or-gdr-flag"] = buf.rb(1)
                nal["pic-type"] = utils.unraw(buf.rb(3), 1, {0x00: "I", 0x01: "P/I", 0x02: "B/P/I"}, True)

        return nal

    @staticmethod
    def read_av2_obu(buf: Buf, state={}) -> dict:
        obu = {}
        obu["length"] = buf.ruleb()
        buf.pasunit(obu["length"])

        obu["extension-flag"] = buf.rb(1)
        obu["type"] = utils.unraw(
            buf.rb(5),
            1,
            FFMpreg.AV2_OBU_TYPES,
            True,
        )
        obu["tlayer-id"] = buf.rb(2)

        if obu["extension-flag"]:
            obu["mlayer-id"] = buf.rb(3)
            obu["xlayer-id"] = buf.rb(5)

        # BOOK New FFMpreg AV2 OBU
        match obu["type"]:
            case "TEMPORAL_DELIMITER":
                pass
            case _:
                obu["unknown"] = True

        buf.sapunit()
        return obu

    @staticmethod
    def read_dvbsub(buf: Buf) -> dict:
        # BOOK New FFMpreg DVBSUB type
        op = {}

        buf.skip(1)
        op["type"] = utils.unraw(
            buf.ru8(),
            1,
            {
                0x10: "Page Composition Segment",
                0x11: "Region Composition Segments",
                0x12: "CLUT Definition Segment",
                0x13: "Object Data Segment",
                0x14: "Display Definition Segment",
                0x80: "End of Display Set",
            },
            True,
        )
        op["page-id"] = buf.ru16()
        op["length"] = buf.ru16()

        buf.pasunit(op["length"])

        op["data"] = {}
        match op["type"]:
            case "Display Definition Segment":
                op["data"]["dds-version"] = buf.rb(4)
                op["data"]["display-window-flag"] = buf.rb(4)
                op["data"]["width"] = buf.ru16() + 1
                op["data"]["height"] = buf.ru16() + 1
            case "Page Composition Segment":
                op["data"]["page-timeout"] = buf.ru8()
                op["data"]["page-version-number"] = buf.rb(4)
                op["data"]["page-state"] = buf.rb(2)
                op["data"]["reserved"] = buf.rb(2)
            case "Region Composition Segments":
                op["data"]["region-id"] = buf.ru8()
                op["data"]["region_version_number"] = buf.rb(4)
                op["data"]["region_fill_flag"] = buf.rb(3)
                op["data"]["reserved0"] = buf.rb(1)
                op["data"]["region-width"] = buf.ru16()
                op["data"]["region-height"] = buf.ru16()
                op["data"]["region-level-of-compatibility"] = buf.rb(3)
                op["data"]["region-depth"] = buf.rb(3)
                op["data"]["reserved1"] = buf.rb(2)
                op["data"]["clut-id"] = buf.ru8()
                op["data"]["region-8-bit-pixel-code"] = buf.ru8()
                op["data"]["region-4-bit-pixel-code"] = buf.rb(4)
                op["data"]["region-2-bit-pixel-code"] = buf.rb(2)
                op["data"]["reserved2"] = buf.rb(2)
            case "CLUT Definition Segment":
                op["data"]["clut-id"] = buf.ru8()
                op["data"]["clut-version-number"] = buf.ru8() >> 4

                op["data"]["entries"] = []
                while buf.hasunit():
                    entry = {}
                    entry["id"] = buf.ru8()
                    entry["2-bit-clut-entry-flag"] = buf.rb(1)
                    entry["4-bit-clut-entry-flag"] = buf.rb(1)
                    entry["8-bit-clut-entry-flag"] = buf.rb(1)
                    entry["reserved"] = buf.rb(4)
                    entry["full-range-flag"] = buf.rb(1)

                    if entry["full-range-flag"]:
                        entry["y"] = buf.ru8()
                        entry["cr"] = buf.ru8()
                        entry["cb"] = buf.ru8()
                        entry["t"] = buf.ru8()
                    else:
                        entry["y"] = buf.rb(4)
                        entry["cr"] = buf.rb(4)
                        entry["cb"] = buf.rb(4)
                        entry["t"] = buf.rb(4)

                    op["data"]["entries"].append(entry)
            case "Object Data Segment":
                op["data"]["object-id"] = buf.ru16()
                op["data"]["version-number"] = buf.rb(4)
                op["data"]["coding-method"] = buf.rb(2)
                op["data"]["non-modifying-colour-flag"] = buf.rb(1)
                op["data"]["reserved"] = buf.rb(1)

                if op["data"]["coding-method"] == 0b00:
                    op["data"]["topfield-pixel-code-length"] = buf.ru16()
                    op["data"]["bottomfield-pixel-code-length"] = buf.ru16()
            case "End of Display Set":
                pass
            case _:
                op["unknown"] = True

        buf.sapunit()

        return op

    @staticmethod
    def read_ac3_frame(buf: Buf) -> dict:
        AC3_FRAME_SIZES = [
            [
                64,
                64,
                80,
                80,
                96,
                96,
                112,
                112,
                128,
                128,
                160,
                160,
                192,
                192,
                224,
                224,
                256,
                256,
                320,
                320,
                384,
                384,
                448,
                448,
                512,
                512,
                640,
                640,
                768,
                768,
                896,
                896,
                1024,
                1024,
                1152,
                1152,
                1280,
                1280,
            ],
            [
                69,
                70,
                87,
                88,
                104,
                105,
                121,
                122,
                139,
                140,
                174,
                175,
                208,
                209,
                243,
                244,
                278,
                279,
                348,
                349,
                417,
                418,
                487,
                488,
                557,
                558,
                696,
                697,
                835,
                836,
                975,
                976,
                1114,
                1115,
                1253,
                1254,
                1393,
                1394,
            ],
            [
                96,
                96,
                120,
                120,
                144,
                144,
                168,
                168,
                192,
                192,
                240,
                240,
                288,
                288,
                336,
                336,
                384,
                384,
                480,
                480,
                576,
                576,
                672,
                672,
                768,
                768,
                960,
                960,
                1152,
                1152,
                1344,
                1344,
                1536,
                1536,
                1728,
                1728,
                1920,
                1920,
            ],
        ]

        frame: dict = {}

        buf.skip(2)
        frame["crc1"] = buf.ru16()
        fscod = buf.rb(2)
        frame["fscod"] = utils.unraw(fscod, 1, {0b00: "48 kHz", 0b01: "44.1 kHz", 0b10: "32 kHz"}, True)
        frame["frmsizecod"] = buf.rb(6)
        frame["bsid"] = buf.rb(5)
        frame["bsmod"] = buf.rb(3)

        frame["length"] = AC3_FRAME_SIZES[fscod][frame["frmsizecod"]] * 2
        buf.pasunit(frame["length"] - 6)

        frame["acmod"] = buf.rb(3)

        if (frame["acmod"] & 0x1) and (frame["acmod"] != 0x1):
            frame["cmixlev"] = buf.rb(2)

        if frame["acmod"] & 0x4:
            frame["surmixlev"] = buf.rb(2)

        if frame["acmod"] == 0x2:
            frame["dsurmod"] = buf.rb(2)

        frame["lfeon"] = buf.rb(1)
        frame["dialnorm"] = buf.rb(5)

        frame["compre"] = buf.rb(1)
        if frame["compre"]:
            frame["compr"] = buf.rb(8)

        frame["langcode"] = buf.rb(1)
        if frame["langcode"]:
            frame["langcod"] = buf.rb(8)

        if frame["acmod"] == 0:
            frame["dialnorm2"] = buf.rb(5)

            frame["compr2e"] = buf.rb(1)
            if frame["compr2e"]:
                frame["compr2"] = buf.rb(8)

            frame["langcod2e"] = buf.rb(1)
            if frame["langcod2e"]:
                frame["langcod2"] = buf.rb(8)

        frame["audprodie"] = buf.rb(1)
        if frame["audprodie"]:
            frame["mixlevel"] = buf.rb(5)
            frame["roomtyp"] = buf.rb(2)

        if frame["acmod"] == 0:
            frame["audprodi2e"] = buf.rb(1)
            if frame["audprodi2e"]:
                frame["mixlevel2"] = buf.rb(5)
                frame["roomtyp2"] = buf.rb(2)

        frame["copyrightb"] = buf.rb(1)
        frame["origbs"] = buf.rb(1)

        frame["timecod1e"] = buf.rb(1)
        if frame["timecod1e"]:
            frame["timecod1"] = buf.rb(14)

        frame["timecod2e"] = buf.rb(1)
        if frame["timecod2e"]:
            frame["timecod2"] = buf.rb(14)

        frame["addbsie"] = buf.rb(1)
        if frame["addbsie"]:
            frame["addbsil"] = buf.rb(6)
            frame["addbsi"] = [buf.rb(8) for _ in range(frame["addbsil"] + 1)]

        buf.align()

        buf.sapunit()

        return frame

    @staticmethod
    def read_mp2_frame(buf: Buf) -> dict:
        frame = {}

        buf.rb(12)
        frame["version-id"] = buf.rb(1)
        frame["layer"] = buf.rb(2)
        frame["protection-bit"] = buf.rb(1)
        frame["bitrate"] = [
            [
                None,
                8,
                16,
                24,
                32,
                40,
                48,
                56,
                64,
                80,
                96,
                112,
                128,
                144,
                160,
                None,
            ],
            [
                None,
                32,
                48,
                56,
                64,
                80,
                96,
                112,
                128,
                160,
                192,
                224,
                256,
                320,
                384,
                None,
            ],
        ][frame["version-id"]][buf.rb(4)] * 1000
        frame["sampling-rate"] = [[22050, 24000, 16000, None], [44100, 48000, 32000, None]][frame["version-id"]][buf.rb(2)]
        frame["padding-bit"] = buf.rb(1)
        frame["private-bit"] = buf.rb(1)
        frame["channel-mode"] = buf.rb(2)
        frame["mode-extension"] = buf.rb(2)
        frame["copyright"] = buf.rb(1)
        frame["original-copy"] = buf.rb(1)
        frame["emphasis"] = buf.rb(2)

        if frame["protection-bit"] == 0:
            frame["crc"] = buf.rb(16)

        frame["length"] = (144 * frame["bitrate"] // frame["sampling-rate"]) + frame["padding-bit"]

        buf.skip(frame["length"] - 4)

        return frame

    @staticmethod
    def read_mp3_frame(buf: Buf) -> dict:
        frame = {}

        buf.rb(11)
        frame["version"] = utils.unraw(
            buf.rb(2),
            1,
            {0b00: "MPEG-2.5", 0b10: "MPEG-2", 0b11: "MPEG-1"},
            True,
        )
        frame["layer"] = utils.unraw(buf.rb(2), 1, {0b01: "Layer III"}, True)
        frame["error-protection"] = buf.rb(1) == 0
        frame["bitrate"] = {
            "MPEG-1": [
                None,
                32,
                40,
                48,
                56,
                64,
                80,
                96,
                112,
                128,
                160,
                192,
                224,
                256,
                320,
                -1,
            ],
            "MPEG-2": [
                None,
                8,
                16,
                24,
                32,
                40,
                48,
                56,
                64,
                80,
                96,
                112,
                128,
                144,
                160,
                -1,
            ],
            "MPEG-2.5": [
                None,
                8,
                16,
                24,
                32,
                40,
                48,
                56,
                64,
                80,
                96,
                112,
                128,
                144,
                160,
                -1,
            ],
        }[frame["version"]][buf.rb(4)]
        frame["frequency"] = {
            "MPEG-1": [44100, 48000, 32000, -1],
            "MPEG-2": [22050, 24000, 16000, -1],
            "MPEG-2.5": [11025, 12000, 8000, -1],
        }[frame["version"]][buf.rb(2)]
        frame["padding"] = buf.rb(1)
        frame["private"] = buf.rb(1)
        frame["mode"] = utils.unraw(
            buf.rb(2),
            1,
            {
                0b00: "Stereo",
                0b01: "Joint Stereo",
                0b10: "Dual Channel",
                0b11: "Single Channel",
            },
            True,
        )
        frame["mode-extension"] = buf.rb(2)
        frame["copyrighted"] = bool(buf.rb(1))
        frame["original"] = bool(buf.rb(1))
        frame["emphasis"] = buf.rb(2)

        buf.skip(
            ((144 if frame["version"] == "MPEG-1" else 72) * frame["bitrate"] * 1000) // frame["frequency"]
            + frame["padding"]
            - 4
        )

        return frame

    # BOOK New FFMpreg method
