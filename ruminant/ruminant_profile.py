import os
import inspect
import atexit

has_profile = True
try:
    from line_profiler import LineProfiler, show_text
except ImportError:
    has_profile = False

profile = has_profile and os.environ.get("RUMINANT_PROFILE", "0") != "0"

if profile:
    lp = LineProfiler()

    def save():
        stats = lp.get_stats()
        filtered_timings = {key: hits for key, hits in stats.timings.items() if hits and any(nhits > 0 for _, nhits, _ in hits)}

        with open("ruminant_profile.txt", "w") as f:
            show_text(filtered_timings, stats.unit, stream=f)

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
