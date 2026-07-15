from .command import CommandBackend
from .precomputed import PrecomputedBackend
from .python_plugin import PythonPluginBackend

BUILTIN_BACKENDS = {
    "command": CommandBackend,
    "precomputed": PrecomputedBackend,
    "python": PythonPluginBackend,
}

