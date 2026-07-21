import os

try:
    from . import ruminant_types

    OIDS: ruminant_types.OidRegistry = {}
except ImportError:
    OIDS = {}

# read ruminant/oids.txt
with open(os.path.join(os.path.dirname(__file__), "oids.txt"), "r") as file:
    rows = []
    for line in file.readlines():
        # we ignore comments, they're nuked by oids-tool.py
        if line.startswith("#"):
            continue

        # remove tailing newline and split OID and name
        line_split = line[:-1].split(": ")
        # add it to the rows
        rows.append((line_split[0], ": ".join(line_split[1:])))

    # build the hierachy
    for row in rows:
        key = [int(x) for x in row[0].split(".")]

        root = OIDS
        for i in key[:-1]:
            if i not in root:
                root[i] = {"name": "?", "children": {}}

            root = root[i]["children"]

        if key[-1] not in root:
            root[key[-1]] = {"name": "?", "children": {}}

        root[key[-1]]["name"] = row[1]
