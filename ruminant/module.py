import os
from . import buf, ruminant_types


class RuminantModule(object):
    priority = 0
    dev = False
    desc = ""

    def __init__(self, buf: buf.Buf):
        self.buf = buf
        self.extra_ctx: dict = {}

    @staticmethod
    def identify(buf: buf.Buf, ctx={}) -> bool:
        return False

    def chew(self) -> ruminant_types.JSON:
        self.buf.skip(self.buf.available())
        return {}


modules: list[RuminantModule] = []
debug = os.environ.get("RUMINANT_DEBUG_MODE", "0") != "0"


def register(cls):
    if cls.dev and os.environ.get("RUMINANT_DEV_MODE", "0") == "0":
        return cls

    if cls.__name__ in [x.__name__ for x in modules]:
        old_cls = None
        for x in modules:
            if x.__name__ == cls.__name__:
                old_cls = x
                break

        raise ValueError(f"Module {cls} already registered from {old_cls}!")

    modules.append(cls)
    modules.sort(key=lambda x: x.priority)

    return cls
