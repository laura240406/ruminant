from . import ruminant_types

secrets: dict[str, ruminant_types.JSON] = {}


def get(name: str) -> ruminant_types.JSON:
    return secrets.get(name)


def set(name: str, value: ruminant_types.JSON) -> None:
    secrets[name] = value
