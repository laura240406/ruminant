from . import ruminant_types
from .modules import state_stack
from typing import cast


def get(name: str) -> ruminant_types.JSON:
    state: dict = cast(dict, state_stack.get())
    parameters = state["parameters"]
    return parameters.get(name)


def set(name: str, value: ruminant_types.JSON) -> None:
    state: dict = cast(dict, state_stack.get())
    parameters = state["parameters"]
    parameters[name] = value


def get_parameter(default=None, register_dict=None, register_name=None, parameter_index=None) -> ruminant_types.JSON:
    state: dict = cast(dict, state_stack.get())
    parameters = state["parameters"]

    has_custom_index = parameter_index is None
    if has_custom_index:
        parameter_index = state["parameter-index"]

    if register_dict is not None:
        register_dict[register_name] = {"parameter-index": parameter_index, "found": str(parameter_index) in parameters}

    if not has_custom_index:
        state["parameter-index"] += 1

    return parameters.get(str(parameter_index), default)
