import base64
import os
import lzma
import hashlib

base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ruminant")

files = []
for r, _, f in os.walk(base):
    for f2 in f:
        if f2.split(".")[-1] in ("py", "txt"):
            files.append(os.path.join(r, f2))

content = b""
for file in files:
    name = os.path.join(b"ruminant", file[len(base) + 1 :].encode())
    content += len(name).to_bytes(1, "little") + name

    with open(file, "rb") as f:
        section = f.read()
        content += len(section).to_bytes(3, "little") + section

content = lzma.compress(content, preset=9 | lzma.PRESET_EXTREME)
content_hash = hashlib.sha256(content).hexdigest()

with open(os.path.join(os.path.dirname(__file__), "unpacker.py"), "r") as f:
    print(f.read() + '\nunpack("' + content_hash + '","' + base64.b85encode(content).decode("utf-8") + '")')
