from . import ruminant_types

parameters: dict[str, ruminant_types.JSON] = {}

parameter_index: int = 0


def get(name: str) -> ruminant_types.JSON:
    return parameters.get(name)


def set(name: str, value: ruminant_types.JSON) -> None:
    parameters[name] = value


def get_parameter(default=None, register_dict=None, register_name=None) -> ruminant_types.JSON:
    global parameter_index

    if register_dict is not None:
        register_dict[register_name] = {"parameter-index": parameter_index, "found": str(parameter_index) in parameters}

    parameter_index += 1
    return parameters.get(str(parameter_index - 1), default)
