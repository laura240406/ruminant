# mypy: disable-error-code="no-redef"
from . import utils, crypto
from .buf import Buf
from typing import Callable, Any

tests: dict[str, dict[str, Callable]] = {}


# annotation to register a function as a test
def test(group, name):
    def inner(func):
        if group not in tests:
            tests[group] = {}

        tests[group][name] = func
        return func

    return inner


# invert a function failure to allow "should fail" tests
def inv(func):
    def f():
        try:
            func()
        except Exception:
            return

        raise Exception("Test ran successfully when it shouldn't")

    return f


# is a == b?
def assert_eq(a, b):
    if isinstance(a, int) and isinstance(b, int):
        # special case to print hex
        assert a == b, f"Expected {b}, got {a} (i.e. {hex(a)})"
    else:
        assert a == b, f"Expected {b}, got {a}"


@test("Sanity", "simple-pass")
def f():
    pass


@test("Sanity", "inverted")
@inv
def f():
    # this should crash
    assert False


@test("Buffer", "from-bytes")
def f():
    Buf(b"deadbeef")


@test("Buffer", "from-file")
def f():
    Buf(open(__file__, "rb"))


@test("Buffer", "fail-from-string")
@inv
def f():
    Buf("deadbeef")


buffer_read_cases = [
    (Buf.ru8, Buf.pu8, 0x81, 1),
    (Buf.ru16, Buf.pu16, 0x8182, 2),
    (Buf.ru24, Buf.pu24, 0x818283, 3),
    (Buf.ru32, Buf.pu32, 0x81828384, 4),
    (Buf.rf32, Buf.pf32, -4.794317366894298e-38, 4),
    (Buf.ru64, Buf.pu64, 0x8182838485868788, 8),
    (Buf.rf64, Buf.pf64, -2.1597750994171683e-301, 8),
    (Buf.ri8, Buf.pi8, -0x7f, 1),
    (Buf.ri16, Buf.pi16, -0x7e7e, 2),
    (Buf.ri24, Buf.pi24, -0x7e7d7d, 3),
    (Buf.ri32, Buf.pi32, -0x7e7d7c7c, 4),
    (Buf.ri64, Buf.pi64, -0x7e7d7c7b7a797878, 8),
    (Buf.ru8l, Buf.pu8l, 0x81, 1),
    (Buf.ru16l, Buf.pu16l, 0x8281, 2),
    (Buf.ru24l, Buf.pu24l, 0x838281, 3),
    (Buf.ru32l, Buf.pu32l, 0x84838281, 4),
    (Buf.rf32l, Buf.pf32l, -3.091780090135418e-36, 4),
    (Buf.ru64l, Buf.pu64l, 0x8887868584838281, 8),
    (Buf.rf64l, Buf.pf64l, -1.4249914579614907e-267, 8),
    (Buf.ri8l, Buf.pi8l, -0x7f, 1),
    (Buf.ri16l, Buf.pi16l, -0x7d7f, 2),
    (Buf.ri24l, Buf.pi24l, -0x7c7d7f, 3),
    (Buf.ri32l, Buf.pi32l, -0x7b7c7d7f, 4),
    (Buf.ri64l, Buf.pi64l, -0x7778797a7b7c7d7f, 8),
    (lambda buf: buf.rs(4), lambda buf: buf.ps(4), "abcd", 4, b"abcdefgh", "rs", "ps"),
    (lambda buf: buf.rh(4), lambda buf: buf.ph(4), "81828384", 4, None, "rh", "ph"),
    (Buf.rzs, Buf.pzs, "abcd", 5, b"abcd\x00efgh"),
    (Buf.rzs, Buf.pzs, "abcd", 5, b"abcd", "rzs-end-as-zero", "pzs-end-as-zero"),
    (Buf.rl, Buf.pl, b"abcd", 5, b"abcd\nefgh", "rl-lf", "pl-lf"),
    (Buf.rl, Buf.pl, b"abcd", 6, b"abcd\r\nefgh", "rl-crlf", "pl-crlf"),
    (Buf.rl, Buf.pl, b"abcd", 5, b"abcd\refgh", "rl-cr", "pl-cr"),
    (Buf.rl, Buf.pl, b"abcd", 6, b"abcd\n\refgh", "rl-lfcr", "pl-lfcr"),
    (Buf.rl, Buf.pl, b"abcd", 4, b"abcd", "rl-end", "pl-end"),
    (Buf.rl, Buf.pl, b"abcd", 5, b"abcd\n", "rl-lfend", "pl-lfend"),
    (Buf.rl, Buf.pl, b"abcd", 5, b"abcd\r", "rl-crend", "pl-crend"),
    (
        Buf.rguid,
        Buf.pguid,
        "64636261-6665-6867-696a-6b6c6d6e6f70",
        16,
        b"abcdefghijklmnop",
    ),
]


def buf_instance(rf, pf, val, pos, buf_bytes=None, rname=None, pname=None):
    if buf_bytes is None:
        buf_bytes = bytes.fromhex("8182838485868788")
    if rname is None:
        rname = rf.__name__
    if pname is None:
        pname = pf.__name__

    @test("Buffer", rname)
    def f():
        buf = Buf(buf_bytes)
        assert_eq(rf(buf), val)
        assert_eq(buf.tell(), pos)

    @test("Buffer", pname)
    def f():
        buf = Buf(buf_bytes)
        assert_eq(pf(buf), val)
        assert_eq(buf.tell(), 0)


for instance in buffer_read_cases:
    buf_instance(*instance)


@test("Buffer", "overread")
@inv
def f():
    buf = Buf(bytes(7))
    buf.ru64()


@test("Buffer", "unit")
def f():
    buf = Buf(bytes(8))

    buf.pasunit(5)
    buf.ru32()
    assert_eq(buf.tell(), 4)
    assert_eq(buf.unit, 1)
    buf.sapunit()
    assert_eq(buf.tell(), 5)
    assert_eq(buf.unit, None)


@test("Buffer", "unit-overread")
@inv
def f():
    buf = Buf(bytes(8))

    buf.pasunit(5)
    buf.ru64()


@test("Buffer", "unit-stack")
def f():
    buf = Buf(bytes(8))

    buf.pasunit(7)
    buf.pasunit(5)
    assert_eq(buf.unit, 5)
    buf.sapunit()
    assert_eq(buf.unit, 2)


der_test_cases: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("null", "0500", {"type": "NULL", "length": 0, "value": None}),
    ("small-integer", "0203010001", {"type": "INTEGER", "length": 3, "value": 65537}),
    (
        "lets-encrypt-point-example",
        "3006 8001 0981 0109",
        {
            "type": "SEQUENCE",
            "length": 6,
            "value": [
                {"type": "X509 [0]", "length": 1, "value": "09"},
                {"type": "X509 [1]", "length": 1, "value": "09"},
            ],
        },
    ),
    (
        "lets-encrypt-root-certificate",
        "3082056b30820353a0030201020211008210cfb0d240e3594463e0bb63828b00300d06092a864886"
        "f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65"
        "742053656375726974792052657365617263682047726f7570311530130603550403130c49535247"
        "20526f6f74205831301e170d3135303630343131303433385a170d3335303630343131303433385a"
        "304f310b300906035504061302555331293027060355040a1320496e7465726e6574205365637572"
        "6974792052657365617263682047726f7570311530130603550403130c4953524720526f6f742058"
        "3130820222300d06092a864886f70d01010105000382020f003082020a0282020100ade82473f414"
        "37f39b9e2b57281c87bedcb7df38908c6e3ce657a078f775c2a2fef56a6ef6004f28dbde68866c44"
        "93b6b163fd14126bbf1fd2ea319b217ed1333cba48f5dd79dfb3b8ff12f1219a4bc18a8671694a66"
        "666c8f7e3c70bfad292206f3e4c0e680aee24b8fb7997e94039fd347977c99482353e838ae4f0a6f"
        "832ed149578c8074b6da2fd0388d7b0370211b75f2303cfa8faeddda63abeb164fc28e114b7ecf0b"
        "e8ffb5772ef4b27b4ae04c12250c708d0329a0e15324ec13d9ee19bf10b34a8c3f89a36151deac87"
        "0794f46371ec2ee26f5b9881e1895c34796c76ef3b906279e6dba49a2f26c5d010e10eded9108e16"
        "fbb7f7a8f7c7e50207988f360895e7e237960d36759efb0e72b11d9bbc03f94905d881dd05b42ad6"
        "41e9ac0176950a0fd8dfd5bd121f352f28176cd298c1a80964776e4737baceac595e689d7f72d689"
        "c50641293e593edd26f524c911a75aa34c401f46a199b5a73a516e863b9e7d72a712057859ed3e51"
        "78150b038f8dd02f05b23e7b4a1c4b730512fcc6eae050137c439374b3ca74e78e1f0108d030d45b"
        "7136b407bac130305c48b7823b98a67d608aa2a32982ccbabd83041ba2830341a1d605f11bc2b6f0"
        "a87c863b46a8482a88dc769a76bf1f6aa53d198feb38f364dec82b0d0a28fff7dbe21542d422d027"
        "5de179fe18e77088ad4ee6d98b3ac6dd27516effbc64f533434f0203010001a3423040300e060355"
        "1d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e0416041479"
        "b459e67bb6e5e40173800888c81a58f6e99b6e300d06092a864886f70d01010b0500038202010055"
        "1f58a9bcb2a850d00cb1d81a6920272908ac61755c8a6ef882e5692fd5f6564bb9b8731059d32197"
        "7ee74c71fbb2d260ad39a80bea17215685f1500e59ebcee059e9bac915ef869d8f8480f6e4e99190"
        "dc179b621b45f06695d27c6fc2ea3bef1fcfcbd6ae27f1a9b0c8aefd7d7e9afa2204ebffd97fea91"
        "2b22b1170e8ff28a345b58d8fc01c954b9b826cc8a8833894c2d843c82dfee965705ba2cbbf7c4b7"
        "c74e3b82be31c822737392d1c280a43939103323824c3c9f86b255981dbe29868c229b9ee26b3b57"
        "3a82704ddc09c789cb0a074d6ce85d8ec9efceabc7bbb52b4e45d64ad026cce572ca086aa595e315"
        "a1f7a4edc92c5fa5fbffac28022ebed77bbbe3717b9016d3075e46537c3707428cd3c4969cd599b5"
        "2ae0951a8048ae4c3907cecc47a452952bbab8fbadd233537de51d4d6dd5a1b1c7426fe64027355c"
        "a328b7078de78d3390e7239ffb509c796c46d5b415b3966e7e9b0c963ab8522d3fd65be1fb08c284"
        "fe24a8a389daac6ae1182ab1a843615bd31fdc3b8d76f22de88d75df17336c3d53fb7bcb415fffdc"
        "a2d06138e196b8ac5d8b37d775d533c09911ae9d41c1727584be0241425f67244894d19b27be073f"
        "b9b84f817451e17ab7ed9d23e2bee0d52804133c31039edd7a6c8fc60718c67fde478e3f289e0406"
        "cfa5543477bdec899be91743df5bdb5ffe8e1e57a2cd409d7e6222dade1827",
        {
            "type": "SEQUENCE",
            "length": 1387,
            "value": [
                {
                    "type": "SEQUENCE",
                    "length": 851,
                    "value": [
                        {
                            "type": "X509 [0]",
                            "length": 3,
                            "value": [{"type": "INTEGER", "length": 1, "value": 2}],
                        },
                        {
                            "type": "INTEGER",
                            "length": 17,
                            "value": 172886928669790476064670243504169061120,
                        },
                        {
                            "type": "SEQUENCE",
                            "length": 13,
                            "value": [
                                {
                                    "type": "OBJECT IDENTIFIER",
                                    "length": 9,
                                    "value": {
                                        "raw": "1.2.840.113549.1.1.11",
                                        "tree": [
                                            "iso",
                                            "member-body",
                                            "us",
                                            "rsadsi",
                                            "pkcs",
                                            "pkcs-1",
                                            "sha256WithRSAEncryption",
                                        ],
                                        "name": "sha256WithRSAEncryption",
                                    },
                                },
                                {"type": "NULL", "length": 0, "value": None},
                            ],
                        },
                        {
                            "type": "SEQUENCE",
                            "length": 79,
                            "value": [
                                {
                                    "type": "SET",
                                    "length": 11,
                                    "value": [
                                        {
                                            "type": "SEQUENCE",
                                            "length": 9,
                                            "value": [
                                                {
                                                    "type": "OBJECT IDENTIFIER",
                                                    "length": 3,
                                                    "value": {
                                                        "raw": "2.5.4.6",
                                                        "tree": [
                                                            "joint-iso-itu-t",
                                                            "ds",
                                                            "attributeType",
                                                            "countryName",
                                                        ],
                                                        "name": "countryName",
                                                    },
                                                },
                                                {
                                                    "type": "PrintableString",
                                                    "length": 2,
                                                    "value": "US",
                                                },
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "SET",
                                    "length": 41,
                                    "value": [
                                        {
                                            "type": "SEQUENCE",
                                            "length": 39,
                                            "value": [
                                                {
                                                    "type": "OBJECT IDENTIFIER",
                                                    "length": 3,
                                                    "value": {
                                                        "raw": "2.5.4.10",
                                                        "tree": [
                                                            "joint-iso-itu-t",
                                                            "ds",
                                                            "attributeType",
                                                            "organizationName",
                                                        ],
                                                        "name": "organizationName",
                                                    },
                                                },
                                                {
                                                    "type": "PrintableString",
                                                    "length": 32,
                                                    "value": "Internet Security Research Group",
                                                },
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "SET",
                                    "length": 21,
                                    "value": [
                                        {
                                            "type": "SEQUENCE",
                                            "length": 19,
                                            "value": [
                                                {
                                                    "type": "OBJECT IDENTIFIER",
                                                    "length": 3,
                                                    "value": {
                                                        "raw": "2.5.4.3",
                                                        "tree": [
                                                            "joint-iso-itu-t",
                                                            "ds",
                                                            "attributeType",
                                                            "commonName",
                                                        ],
                                                        "name": "commonName",
                                                    },
                                                },
                                                {
                                                    "type": "PrintableString",
                                                    "length": 12,
                                                    "value": "ISRG Root X1",
                                                },
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "SEQUENCE",
                            "length": 30,
                            "value": [
                                {
                                    "type": "UTCTime",
                                    "length": 13,
                                    "value": "2015-06-04T11:04:38",
                                },
                                {
                                    "type": "UTCTime",
                                    "length": 13,
                                    "value": "2035-06-04T11:04:38",
                                },
                            ],
                        },
                        {
                            "type": "SEQUENCE",
                            "length": 79,
                            "value": [
                                {
                                    "type": "SET",
                                    "length": 11,
                                    "value": [
                                        {
                                            "type": "SEQUENCE",
                                            "length": 9,
                                            "value": [
                                                {
                                                    "type": "OBJECT IDENTIFIER",
                                                    "length": 3,
                                                    "value": {
                                                        "raw": "2.5.4.6",
                                                        "tree": [
                                                            "joint-iso-itu-t",
                                                            "ds",
                                                            "attributeType",
                                                            "countryName",
                                                        ],
                                                        "name": "countryName",
                                                    },
                                                },
                                                {
                                                    "type": "PrintableString",
                                                    "length": 2,
                                                    "value": "US",
                                                },
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "SET",
                                    "length": 41,
                                    "value": [
                                        {
                                            "type": "SEQUENCE",
                                            "length": 39,
                                            "value": [
                                                {
                                                    "type": "OBJECT IDENTIFIER",
                                                    "length": 3,
                                                    "value": {
                                                        "raw": "2.5.4.10",
                                                        "tree": [
                                                            "joint-iso-itu-t",
                                                            "ds",
                                                            "attributeType",
                                                            "organizationName",
                                                        ],
                                                        "name": "organizationName",
                                                    },
                                                },
                                                {
                                                    "type": "PrintableString",
                                                    "length": 32,
                                                    "value": "Internet Security Research Group",
                                                },
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "SET",
                                    "length": 21,
                                    "value": [
                                        {
                                            "type": "SEQUENCE",
                                            "length": 19,
                                            "value": [
                                                {
                                                    "type": "OBJECT IDENTIFIER",
                                                    "length": 3,
                                                    "value": {
                                                        "raw": "2.5.4.3",
                                                        "tree": [
                                                            "joint-iso-itu-t",
                                                            "ds",
                                                            "attributeType",
                                                            "commonName",
                                                        ],
                                                        "name": "commonName",
                                                    },
                                                },
                                                {
                                                    "type": "PrintableString",
                                                    "length": 12,
                                                    "value": "ISRG Root X1",
                                                },
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "SEQUENCE",
                            "length": 546,
                            "value": [
                                {
                                    "type": "SEQUENCE",
                                    "length": 13,
                                    "value": [
                                        {
                                            "type": "OBJECT IDENTIFIER",
                                            "length": 9,
                                            "value": {
                                                "raw": "1.2.840.113549.1.1.1",
                                                "tree": [
                                                    "iso",
                                                    "member-body",
                                                    "us",
                                                    "rsadsi",
                                                    "pkcs",
                                                    "pkcs-1",
                                                    "rsaEncryption",
                                                ],
                                                "name": "rsaEncryption",
                                            },
                                        },
                                        {"type": "NULL", "length": 0, "value": None},
                                    ],
                                },
                                {
                                    "type": "BIT STRING",
                                    "length": 527,
                                    "value": {
                                        "type": "SEQUENCE",
                                        "length": 522,
                                        "value": [
                                            {
                                                "type": "INTEGER",
                                                "length": 513,
                                                "value": 709477870415445373015359016562426660610553770685944520893298396600226760899977879191004898543350831842119174188613678136510262472550532722234131754439181090009824131001234702144200501816519311599904090606194984753842587622398776018408050245574116028550608708896478977104703101364577377554823893350339376892984086676842821506637376561471221178677513035811884589888230947855482554780924844280661412982827405878164907670403886160896655313460186264922042760067692235383478494519985672059698752915965998412445946254227413232257276525240006651483130792248112417425846451951438781260632137645358927568158361961710185115502577127010922344394993078948994750404287047493247048147066090211292167313905862438457453781042040498702821432013765502024105065778257759178356925494156447570322373310256999609083201778278588599854706241788119448943034477370959349516873162063461521707809689839710972753590949570167489887658749686740890549110678989462474318310617765270337415238713770800711236563610171101328052424145478220993016515262478543813796899677215192789612682845145008993144513547444131126029557147570005369943143213525671105288817016183804256755470528641042403865830064493168693765438364296560479053823886598989258655438933191724193029337334607,
                                            },
                                            {
                                                "type": "INTEGER",
                                                "length": 3,
                                                "value": 65537,
                                            },
                                        ],
                                    },
                                },
                            ],
                        },
                        {
                            "type": "X509 [3]",
                            "length": 66,
                            "value": [
                                {
                                    "type": "SEQUENCE",
                                    "length": 64,
                                    "value": [
                                        {
                                            "type": "SEQUENCE",
                                            "length": 14,
                                            "value": [
                                                {
                                                    "type": "OBJECT IDENTIFIER",
                                                    "length": 3,
                                                    "value": {
                                                        "raw": "2.5.29.15",
                                                        "tree": [
                                                            "joint-iso-itu-t",
                                                            "ds",
                                                            "certificateExtension",
                                                            "keyUsage",
                                                        ],
                                                        "name": "keyUsage",
                                                    },
                                                },
                                                {
                                                    "type": "BOOLEAN",
                                                    "length": 1,
                                                    "value": True,
                                                },
                                                {
                                                    "type": "OCTET STRING",
                                                    "length": 4,
                                                    "value": {
                                                        "type": "BIT STRING",
                                                        "length": 2,
                                                        "value": "03",
                                                    },
                                                },
                                            ],
                                        },
                                        {
                                            "type": "SEQUENCE",
                                            "length": 15,
                                            "value": [
                                                {
                                                    "type": "OBJECT IDENTIFIER",
                                                    "length": 3,
                                                    "value": {
                                                        "raw": "2.5.29.19",
                                                        "tree": [
                                                            "joint-iso-itu-t",
                                                            "ds",
                                                            "certificateExtension",
                                                            "basicConstraints",
                                                        ],
                                                        "name": "basicConstraints",
                                                    },
                                                },
                                                {
                                                    "type": "BOOLEAN",
                                                    "length": 1,
                                                    "value": True,
                                                },
                                                {
                                                    "type": "OCTET STRING",
                                                    "length": 5,
                                                    "value": {
                                                        "type": "SEQUENCE",
                                                        "length": 3,
                                                        "value": [
                                                            {
                                                                "type": "BOOLEAN",
                                                                "length": 1,
                                                                "value": True,
                                                            }
                                                        ],
                                                    },
                                                },
                                            ],
                                        },
                                        {
                                            "type": "SEQUENCE",
                                            "length": 29,
                                            "value": [
                                                {
                                                    "type": "OBJECT IDENTIFIER",
                                                    "length": 3,
                                                    "value": {
                                                        "raw": "2.5.29.14",
                                                        "tree": [
                                                            "joint-iso-itu-t",
                                                            "ds",
                                                            "certificateExtension",
                                                            "subjectKeyIdentifier",
                                                        ],
                                                        "name": "subjectKeyIdentifier",
                                                    },
                                                },
                                                {
                                                    "type": "OCTET STRING",
                                                    "length": 22,
                                                    "value": {
                                                        "type": "OCTET STRING",
                                                        "length": 20,
                                                        "value": "79b459e67bb6e5e40173800888c81a58f6e99b6e",
                                                    },
                                                },
                                            ],
                                        },
                                    ],
                                }
                            ],
                        },
                    ],
                },
                {
                    "type": "SEQUENCE",
                    "length": 13,
                    "value": [
                        {
                            "type": "OBJECT IDENTIFIER",
                            "length": 9,
                            "value": {
                                "raw": "1.2.840.113549.1.1.11",
                                "tree": [
                                    "iso",
                                    "member-body",
                                    "us",
                                    "rsadsi",
                                    "pkcs",
                                    "pkcs-1",
                                    "sha256WithRSAEncryption",
                                ],
                                "name": "sha256WithRSAEncryption",
                            },
                        },
                        {"type": "NULL", "length": 0, "value": None},
                    ],
                },
                {
                    "type": "BIT STRING",
                    "length": 513,
                    "value": "551f58a9bcb2a850d00cb1d81a6920272908ac61755c8a6ef882e5692fd5f6564bb9b8731059d321977ee74c71fbb2d260ad39a80bea17215685f1500e59ebcee059e9bac915ef869d8f8480f6e4e99190dc179b621b45f06695d27c6fc2ea3bef1fcfcbd6ae27f1a9b0c8aefd7d7e9afa2204ebffd97fea912b22b1170e8ff28a345b58d8fc01c954b9b826cc8a8833894c2d843c82dfee965705ba2cbbf7c4b7c74e3b82be31c822737392d1c280a43939103323824c3c9f86b255981dbe29868c229b9ee26b3b573a82704ddc09c789cb0a074d6ce85d8ec9efceabc7bbb52b4e45d64ad026cce572ca086aa595e315a1f7a4edc92c5fa5fbffac28022ebed77bbbe3717b9016d3075e46537c3707428cd3c4969cd599b52ae0951a8048ae4c3907cecc47a452952bbab8fbadd233537de51d4d6dd5a1b1c7426fe64027355ca328b7078de78d3390e7239ffb509c796c46d5b415b3966e7e9b0c963ab8522d3fd65be1fb08c284fe24a8a389daac6ae1182ab1a843615bd31fdc3b8d76f22de88d75df17336c3d53fb7bcb415fffdca2d06138e196b8ac5d8b37d775d533c09911ae9d41c1727584be0241425f67244894d19b27be073fb9b84f817451e17ab7ed9d23e2bee0d52804133c31039edd7a6c8fc60718c67fde478e3f289e0406cfa5543477bdec899be91743df5bdb5ffe8e1e57a2cd409d7e6222dade1827",
                },
            ],
        },
    ),
)


def der_instance(name: str, data: str, dest: dict[str, Any]) -> None:
    @test("utils.read_der", name)
    def f():
        buf = Buf(bytes.fromhex(data))
        assert_eq(utils.read_der(buf), dest)


for test_case in der_test_cases:
    der_instance(*test_case)


@test("Cryptography", "AES 128-bit encrypt")
def aes_128_encrypt():
    cipher = crypto.AES(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    assert_eq(
        cipher.encrypt(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")).hex(),
        "3ad77bb40d7a3660a89ecaf32466ef97",
    )
    assert_eq(
        cipher.encrypt(bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")).hex(),
        "f5d3d58503b9699de785895a96fdbaaf",
    )
    assert_eq(
        cipher.encrypt(bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef")).hex(),
        "43b1cd7f598ece23881b00e3ed030688",
    )
    assert_eq(
        cipher.encrypt(bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710")).hex(),
        "7b0c785e27e8ad3f8223207104725dd4",
    )


@test("Cryptography", "AES 128-bit decrypt")
def aes_128_decrypt():
    cipher = crypto.AES(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    assert_eq(
        cipher.decrypt(bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")).hex(),
        "6bc1bee22e409f96e93d7e117393172a",
    )
    assert_eq(
        cipher.decrypt(bytes.fromhex("f5d3d58503b9699de785895a96fdbaaf")).hex(),
        "ae2d8a571e03ac9c9eb76fac45af8e51",
    )
    assert_eq(
        cipher.decrypt(bytes.fromhex("43b1cd7f598ece23881b00e3ed030688")).hex(),
        "30c81c46a35ce411e5fbc1191a0a52ef",
    )
    assert_eq(
        cipher.decrypt(bytes.fromhex("7b0c785e27e8ad3f8223207104725dd4")).hex(),
        "f69f2445df4f9b17ad2b417be66c3710",
    )


@test("Cryptography", "AES 192-bit encrypt")
def aes_192_encrypt():
    cipher = crypto.AES(bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"))
    assert_eq(
        cipher.encrypt(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")).hex(),
        "bd334f1d6e45f25ff712a214571fa5cc",
    )
    assert_eq(
        cipher.encrypt(bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")).hex(),
        "974104846d0ad3ad7734ecb3ecee4eef",
    )
    assert_eq(
        cipher.encrypt(bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef")).hex(),
        "ef7afd2270e2e60adce0ba2face6444e",
    )
    assert_eq(
        cipher.encrypt(bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710")).hex(),
        "9a4b41ba738d6c72fb16691603c18e0e",
    )


@test("Cryptography", "AES 192-bit decrypt")
def aes_192_decrypt():
    cipher = crypto.AES(bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"))
    assert_eq(
        cipher.decrypt(bytes.fromhex("bd334f1d6e45f25ff712a214571fa5cc")).hex(),
        "6bc1bee22e409f96e93d7e117393172a",
    )
    assert_eq(
        cipher.decrypt(bytes.fromhex("974104846d0ad3ad7734ecb3ecee4eef")).hex(),
        "ae2d8a571e03ac9c9eb76fac45af8e51",
    )
    assert_eq(
        cipher.decrypt(bytes.fromhex("ef7afd2270e2e60adce0ba2face6444e")).hex(),
        "30c81c46a35ce411e5fbc1191a0a52ef",
    )
    assert_eq(
        cipher.decrypt(bytes.fromhex("9a4b41ba738d6c72fb16691603c18e0e")).hex(),
        "f69f2445df4f9b17ad2b417be66c3710",
    )


@test("Cryptography", "AES 256-bit encrypt")
def aes_256_encrypt():
    cipher = crypto.AES(bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))
    assert_eq(
        cipher.encrypt(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")).hex(),
        "f3eed1bdb5d2a03c064b5a7e3db181f8",
    )
    assert_eq(
        cipher.encrypt(bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")).hex(),
        "591ccb10d410ed26dc5ba74a31362870",
    )
    assert_eq(
        cipher.encrypt(bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef")).hex(),
        "b6ed21b99ca6f4f9f153e7b1beafed1d",
    )
    assert_eq(
        cipher.encrypt(bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710")).hex(),
        "23304b7a39f9f3ff067d8d8f9e24ecc7",
    )


@test("Cryptography", "AES 256-bit decrypt")
def aes_256_decrypt():
    cipher = crypto.AES(bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))
    assert_eq(
        cipher.decrypt(bytes.fromhex("f3eed1bdb5d2a03c064b5a7e3db181f8")).hex(),
        "6bc1bee22e409f96e93d7e117393172a",
    )
    assert_eq(
        cipher.decrypt(bytes.fromhex("591ccb10d410ed26dc5ba74a31362870")).hex(),
        "ae2d8a571e03ac9c9eb76fac45af8e51",
    )
    assert_eq(
        cipher.decrypt(bytes.fromhex("b6ed21b99ca6f4f9f153e7b1beafed1d")).hex(),
        "30c81c46a35ce411e5fbc1191a0a52ef",
    )
    assert_eq(
        cipher.decrypt(bytes.fromhex("23304b7a39f9f3ff067d8d8f9e24ecc7")).hex(),
        "f69f2445df4f9b17ad2b417be66c3710",
    )


@test("Cryptography", "Poly1305")
def poly1305():
    for key, msg, tag in (
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
        ),
        (
            "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
            "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
            "36e5f6b5c5e06070f0efca96227a863e",
        ),
        (
            "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
            "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
            "f3477e7cd95417af89a6b8794c310cf0",
        ),
        (
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
            "4541669a7eaaee61e708dc7cbcc5eb62",
        ),
        (
            "0200000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
            "03000000000000000000000000000000",
        ),
        (
            "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
            "02000000000000000000000000000000",
            "03000000000000000000000000000000",
        ),
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000",
            "05000000000000000000000000000000",
        ),
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101",
            "00000000000000000000000000000000",
        ),
        (
            "0200000000000000000000000000000000000000000000000000000000000000",
            "fdffffffffffffffffffffffffffffff",
            "faffffffffffffffffffffffffffffff",
        ),
        (
            "0100000000000000040000000000000000000000000000000000000000000000",
            "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000",
            "14000000000000005500000000000000",
        ),
        (
            "0100000000000000040000000000000000000000000000000000000000000000",
            "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000",
            "13000000000000000000000000000000",
        ),
    ):
        assert_eq(crypto.poly1305(bytes.fromhex(msg), bytes.fromhex(key)).hex(), tag)


@test("Cryptography", "ChaCha20-Poly1305")
def chacha20_poly1305():
    assert_eq(
        crypto.chacha20_poly1305(
            bytes.fromhex(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
            ),
            bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            bytes.fromhex("070000004041424344454647"),
            bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691"),
            aad=bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
        ).hex(),
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    )


@test("Cryptography", "Argon2i")
def argon2i():
    assert_eq(
        crypto.argon2(b"\x01" * 32, b"\x02" * 32, 4, 32, 4, 32, "i").hex(),
        "3987246ad001e4d85bf24829332821ee38aec95434e9d13df3fd7fb783fdd45d",
    )


@test("Cryptography", "Argon2d")
def argon2d():
    assert_eq(
        crypto.argon2(b"\x01" * 32, b"\x02" * 32, 4, 32, 4, 32, "d").hex(),
        "e45d62c8c56b1756428d10d8d0fa34bb7588b1f3f5065530d72ac3dedd6e864d",
    )


@test("Cryptography", "Argon2id")
def argon2id():
    assert_eq(
        crypto.argon2(b"\x01" * 32, b"\x02" * 32, 4, 32, 4, 32, "id").hex(),
        "e93820f3bea5f680d17351abc63a2b06a76152bc7643b4dec49fbf1eb5eec562",
    )


@test("Cryptography", "Curve25519")
def curve25519():
    # Alice public
    assert_eq(
        crypto.curve25519(
            b"\x09" + bytes(31), bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        ).hex(),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    )

    # Bob public
    assert_eq(
        crypto.curve25519(
            b"\x09" + bytes(31), bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        ).hex(),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    )

    # Alice shared
    assert_eq(
        crypto.curve25519(
            bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
            bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
        ).hex(),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    )

    # Bob shared
    assert_eq(
        crypto.curve25519(
            bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
        ).hex(),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    )
