from typing import TypeAlias, TypedDict

JSON: TypeAlias = dict[str, "JSON"] | list["JSON"] | str | int | float | bool | None


class OidNode(TypedDict):
    name: str
    children: dict[int, "OidNode"]


OidRegistry: TypeAlias = dict[int, OidNode]

BufStack: TypeAlias = list[tuple[int | None, int]]
BufBackup: TypeAlias = tuple[int | None, int, BufStack, int, int, int, int]
