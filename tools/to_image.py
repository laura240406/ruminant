import os
import gzip
import subprocess
import math
import base64
from PIL import Image

instructions_bitmap = gzip.decompress(
    base64.b85decode(
        "ABzY8000000t4-u+m^*32t)h-Kiyeto@RQX3B-D7_OnL;A$qX;Zj3R;7-Nhv#u#Ia>CE;EI1Cy2skqexa+o18?e?EB-Bjh_;Pc~4"
        + "BzAed<nO-M)--uQE@!BeMmt%vrfHXGDuC~}xqu*8)2wOjvf^t6vVf+kZjXO&eV6%sb|3i(@?YlQ%cDD&^BgR>vmc!NJP$H|JxPN2"
        + "fc9)Ba_1ncX^Hs6oASP<UD~-_5#)Ig2UR|3dp>c#$^9zUemZ)0X5Sfr+zJq1inSKxB(>v+n?aFk@7`bzAa1hS%l6YA<6qI()|y6b"
        + "dOW`>C35i*4sLXICl0v!Lcww>O{*M6$jM#_ep5}mJ3Hcq*e#%rB-MXUHa-b^63-SzO{20-=vP`8>w_i#r`Y>#&T{Y$2A;DWHI0hN"
        + "Xqr}86feW>n#LO0?y4ryG;kM$e)ZBcHmT~Ju6E76?wYozo}sBiwx&&_X)pKF(zR?&v!<m>ICs`R?hC%HBWM~stVNtZrD?+a8ClcV"
        + "UV%z#n!c^Gz4y3>%)Z~L-aV=QK%A3!KSA|vDjR3SFL|7i!Bl^y^=FoecTcdNN#(gPAB38=!|&9poqBvu9pu}R#Xc~ToUIP~yaub@"
        + "ug$!L|7A_<7>6msK1-go_$J3pTKh{1TKZYp!JpSu?H@+VnlZ*0V~jDz7_%@xt?&TykYE4+"
    )
)
instructions_row_length = len(instructions_bitmap) // 20

instructions_rows = []
for i in range(0, len(instructions_bitmap), instructions_row_length):
    instructions_rows.append(instructions_bitmap[i : i + instructions_row_length])

instructions_row_length += 48


def run(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, check=True)
    return result.stdout


os.chdir(run("git rev-parse --show-toplevel").decode("utf-8").strip())
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
