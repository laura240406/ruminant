import os
import inspect
import atexit

has_profile = True
try:
    from line_profiler import LineProfiler
except ImportError:
    has_profile = False

profile = has_profile and os.environ.get("RUMINANT_PROFILE", "0") != "0"

if profile:
    lp = LineProfiler()

    def save():
        with open("ruminant_profile.txt", "w") as f:
            lp.print_stats(stream=f)

    atexit.register(save)


def add_class(cls):
    if not profile:
        return

    for _, method in inspect.getmembers(cls, predicate=inspect.isroutine):
        lp.add_function(method)


def wrap_main(func):
    if not profile:
        return func

    return lp(func)
