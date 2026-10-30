import os
import gzip
import subprocess
import math
from PIL import Image

instructions_bitmap = gzip.decompress(
    bytes.fromhex(
        """
1f8b0800000000000203ed9adb96c5200843fbff3fdd596b9e667aa109c4
7a69f6b34701217ab0fb6e8c31c618638c31c618638ce9ccf60b380c19f9
a9b8d50372982131edf69f31dd54e5e1e0f3e34b247679bde4efbed7d634
79402e67a894463b59b3a66997682a80efb8b9802058d3ac69edb2e26b05
b280a6a96e8f7f6f7d97f97c761ff909f25fe6e0cba33b97f31c2cb9b31f
9cfc3c0f327f3d4982f880f66c2772e720ab6989f8c49bf2bea65ddab95d
11e4791007553e687b3e71bec9fd2ad67e3a7a7766df1980dc0a105f8ab5
16e424b5e3889b41916aefde600e206eb2dacbf6d31ee35fd1d8d69a466d
7a3cbf2a2572f1110e6e7476270eb8fa42c1722a4dab1c46c8c95e097e53
4dbb3b3be285d82da08e24d57f4f363e097b12cf16454da3b24ee8575a18
eb8325ffa7d8fb6dce72f00e069eb31d358d8ac9689a5659142fc3ee9ac6
1ad9eeaa26d1347017847ef5d23436a9ea9dae76cdbdee9ab6a79ea1a942
b6a64da4692ff7d3d2b56c4db3a6a54b3877d63fee0bbead23681a3bac45
9c3fa569c2fc1959d3d85e814a6a9abeadb3bdf7b887ccbedfa9de3da9fe
409c93783f41f56d2a1b67c42f799c91c1547fa6f5679689774fb09f49e5
b9301f849ab6c3efd4aa9d7a7c4e1de4db92c53e30939cad0efbbc06abde
afcdbc85ff654deb188729c23e4b9eb4f826c74c5afb4b0a5afa59d9c19f
d754ed1f46cb9a31c618638c31c618b3303fadf000f290600000
"""
    )
)
instructions_row_length = len(instructions_bitmap) // 20

instructions_rows = []
for i in range(0, len(instructions_bitmap), instructions_row_length):
    instructions_rows.append(instructions_bitmap[i : i + instructions_row_length])

instructions_row_length += 48

os.chdir(os.path.dirname(__file__))


def run(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, check=True)
    return result.stdout


source_code = run("git archive --format tar HEAD | gzip -9")
print(f"Source code is {len(source_code)} bytes")

side = max(
    math.ceil(math.sqrt(len(source_code) / 3)),
    instructions_row_length // 3,
)

instructions_bitmap = bytearray()
for i in instructions_rows:
    i = b"\xff\xff\xff\xff\xff\xff\xff\xff" + i
    while len(i) < (side - 11) * 3:
        i += b"\xff"

    i += b"\xff\xff\xff\xff\xff\xff\xff"

    instructions_bitmap += b"\x1f\x8b\x08\x04\x8f\x0b\x9e\x3b\x00\x03"
    instructions_bitmap += (len(i) + 4).to_bytes(2, "little")
    instructions_bitmap += bytes(2)
    instructions_bitmap += (len(i)).to_bytes(2, "little")
    instructions_bitmap += i
    instructions_bitmap += b"\x03\x00"
    instructions_bitmap += bytes(8)

output = instructions_bitmap + source_code
cutout = math.ceil(len(output) / side / 3)
if len(output) < side * cutout * 3:
    output += bytes((side * cutout * 3 - len(output)))

print(f"Image will be {side}x{cutout} pixels")

img = Image.frombytes("RGB", (side, cutout), output)
img.save("src.png")
