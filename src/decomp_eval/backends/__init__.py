from .command import CommandBackend
from .ghidra import GhidraHeadlessBackend
from .precomputed import PrecomputedBackend
from .pseudocode import DatasetPseudocodeBackend
from .python_plugin import PythonPluginBackend

BUILTIN_BACKENDS = {
    "command": CommandBackend,
    "ghidra": GhidraHeadlessBackend,
    "precomputed": PrecomputedBackend,
    "pseudocode": DatasetPseudocodeBackend,
    "python": PythonPluginBackend,
}
