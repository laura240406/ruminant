import os
import tqdm

content = ""
bar = tqdm.tqdm()

for root, _, files in os.walk(os.path.join(os.path.dirname(os.path.dirname(__file__)), "ruminant")):
    for file in files:
        file = os.path.join(root, file)

        with open(file, "r") as f:
            lines = f.read().split("\n")

            for line in lines:
                line = line.strip()

                if line:
                    content += line + " "
                bar.update(1)

bar.close()

print(f"{len(content)} character(s).")

with open("/tmp/ruminant.txt", "w") as f:
    f.write(content)
