from .decompile_eval import DecompileEvalExitCodeProtocol
from .exebench import ExeBenchJsonIOProtocol
from .ossfuzz_rsr import OSSFuzzRSRProtocol

BUILTIN_PROTOCOLS = {
    "exebench_json_io": ExeBenchJsonIOProtocol,
    "decompile_eval_exitcode": DecompileEvalExitCodeProtocol,
    "ossfuzz_rsr": OSSFuzzRSRProtocol,
}

__all__ = [
    "BUILTIN_PROTOCOLS",
    "DecompileEvalExitCodeProtocol",
    "ExeBenchJsonIOProtocol",
    "OSSFuzzRSRProtocol",
]
