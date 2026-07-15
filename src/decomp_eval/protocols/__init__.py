from .decompile_eval import DecompileEvalExitCodeProtocol
from .exebench import ExeBenchJsonIOProtocol

BUILTIN_PROTOCOLS = {
    "exebench_json_io": ExeBenchJsonIOProtocol,
    "decompile_eval_exitcode": DecompileEvalExitCodeProtocol,
}

__all__ = ["BUILTIN_PROTOCOLS", "ExeBenchJsonIOProtocol", "DecompileEvalExitCodeProtocol"]
