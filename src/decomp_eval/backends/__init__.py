from .command import CommandBackend
from .ghidra import GhidraHeadlessBackend
from .openai_compatible import OpenAICompatibleBackend
from .precomputed import PrecomputedBackend
from .pseudocode import DatasetPseudocodeBackend
from .python_plugin import PythonPluginBackend

BUILTIN_BACKENDS = {
    "command": CommandBackend,
    "ghidra": GhidraHeadlessBackend,
    "openai": OpenAICompatibleBackend,
    "precomputed": PrecomputedBackend,
    "pseudocode": DatasetPseudocodeBackend,
    "python": PythonPluginBackend,
}
