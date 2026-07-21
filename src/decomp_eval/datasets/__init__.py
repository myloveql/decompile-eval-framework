from .decompile_eval import DecompileEvalAdapter
from .exebench import ExeBenchFlatAdapter
from .refdec import ReFDecAdapter
from .ossfuzz import OSSFuzzAdapter

BUILTIN_DATASETS = {
    "exebench_flat": ExeBenchFlatAdapter,
    "decompile_eval": DecompileEvalAdapter,
    "refdec": ReFDecAdapter,
    "ossfuzz": OSSFuzzAdapter,
}
