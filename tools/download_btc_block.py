import sys
import requests

for h in sys.argv[1:]:
    block = bytes.fromhex(requests.get(f"https://blockchain.info/rawblock/{h}?format=hex").text)
    with open("/dev/stdout", "wb") as f:
        f.write(b"\xf9\xbe\xb4\xd9")
        f.write(len(block).to_bytes(4, "little"))
        f.write(block)
