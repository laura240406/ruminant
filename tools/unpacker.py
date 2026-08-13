import tempfile
import base64
import os
import lzma
import sys

directory = tempfile.TemporaryDirectory()


def unpack(content):
    content = lzma.decompress(base64.b85decode(content))

    while len(content):
        name = content[1 : content[0] + 1].decode("utf-8")
        content = content[content[0] + 1 :]
        section = content[3 : int.from_bytes(content[:3], "little") + 3]
        content = content[int.from_bytes(content[:3], "little") + 3 :]

        path = os.path.join(directory.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, "wb") as f:
            f.write(section)

    sys.path.insert(0, directory.name)
    from ruminant.main import main

    sys.exit(main(True))
