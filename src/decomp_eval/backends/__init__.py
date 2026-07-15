from .command import CommandBackend
from .ghidra import GhidraHeadlessBackend
from .precomputed import PrecomputedBackend
from .python_plugin import PythonPluginBackend

BUILTIN_BACKENDS = {
    "command": CommandBackend,
    "ghidra": GhidraHeadlessBackend,
    "precomputed": PrecomputedBackend,
    "python": PythonPluginBackend,
}
