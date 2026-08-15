from .. import module
from ..buf import Buf

import traceback
from contextvars import ContextVar

state_stack: ContextVar[dict | None] = ContextVar("state_stack", default=None)
to_extract: list[int] = []
extract_all = False


class EntryModule(module.RuminantModule):
    def __init__(self, walk_mode, blob_mode, flat, extra_ctx, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.walk_mode = walk_mode
        self.blob_mode = blob_mode
        self.flat = flat
        self.extra_ctx = extra_ctx

    def chew(self):
        state = state_stack.get()

        meta = {}
        meta["blob-id"] = state["blob-id"]
        my_blob_id = state["blob-id"]
        state["blob-id"] += 1

        offset = self.buf.tell()

        matched = False

        if self.blob_mode:
            matched = True
            meta["type"] = "blob"
            meta["length"] = self.buf.size()
            self.buf.skip(self.buf.size())
        else:
            for m in module.modules:
                if m.identify(self.buf, {"walk": self.walk_mode} | self.extra_ctx):
                    old_offset = self.buf.tell()

                    try:
                        rest = m(self.buf)
                        rest.extra_ctx = self.extra_ctx
                        rest = rest.chew()
                    except Exception as e:
                        if self.walk_mode:
                            raise e

                        self.buf.skip(self.buf.available())

                        stack_list = []
                        for frame in traceback.extract_tb(e.__traceback__):
                            stack_list.append({
                                "filename": frame.filename,
                                "lineno": frame.lineno,
                                "name": frame.name,
                                "line": frame.line,
                            })

                        rest = {
                            "type": "error",
                            "module": m.__name__,
                            "error-type": type(e).__name__,
                            "error-message": str(e),
                            "stack": stack_list,
                        }

                    meta["length"] = self.buf.tell()
                    meta |= rest

                    matched = True

                    new_offset = self.buf.tell()
                    if self.buf.available() > 0 and not self.walk_mode and not self.flat:
                        with self.buf.cut():
                            meta = {"type": "nested", "segments": [meta]}

                            if new_offset == old_offset:
                                self.blob_mode = True
                                meta["segments"].append(self.chew())
                            else:
                                trailer = self.chew()
                                if trailer["type"] == "nested":
                                    meta["segments"] += trailer["segments"]
                                else:
                                    meta["segments"].append(trailer)

                        self.buf.skip(self.buf.available())
                    break

        if not matched:
            meta |= {"type": "unknown", "length": self.buf.size()}

        state["blob-callback"](my_blob_id, self.buf, offset, meta)

        return meta


def chew(
    blob,
    walk_mode=False,
    blob_mode=False,
    flat=False,
    extra_ctx={},
    shallow=False,
    blob_callback=lambda *x: None,
    parameters={},
):
    first = state_stack.get() is None

    if first:
        token = state_stack.set({"blob-id": 0, "blob-callback": blob_callback, "parameters": parameters, "parameter-index": 0})

    try:
        return EntryModule(
            walk_mode, blob_mode or (shallow and state_stack.get()["blob-id"]), flat, extra_ctx, Buf.of(blob)
        ).chew()
    finally:
        if first:
            state_stack.reset(token)


from . import (  # noqa: F401,E402
    containers,
    images,
    videos,
    documents,
    fonts,
    audio,
    crypto,
    compression,
    text,
    misc,
    android,
    executables,
    filesystems,
)
