from .decompile_eval import DecompileEvalAdapter
from .exebench import ExeBenchFlatAdapter

BUILTIN_DATASETS = {
    "exebench_flat": ExeBenchFlatAdapter,
    "decompile_eval": DecompileEvalAdapter,
}
