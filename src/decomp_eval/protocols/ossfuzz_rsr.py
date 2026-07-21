from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .base import BaseEvaluationProtocol
from ..datasets.common import command_log
from ..models import ProtocolDescriptor, ValidationResult


class OSSFuzzRSRProtocol(BaseEvaluationProtocol):
    """Compile-only Re-compilable Success Rate protocol from DecompileBench."""

    descriptor = ProtocolDescriptor(
        protocol_id="ossfuzz_rsr",
        version="1",
        description="Compile a candidate OSS-Fuzz function into a shared object with clang.",
        capabilities=("candidate_compile", "shared_object_compile"),
        compile_unit="candidate_with_public_prelude",
        test_granularity="compile_only",
        comparator="clang_shared_object_compile_success",
    )

    def __init__(self, config: dict[str, Any], *, adapter: Any, base_dir: Path):
        super().__init__(config, adapter=adapter, base_dir=base_dir)
        self.clang = str(config.get("clang", "clang"))
        self.extra_flags = list(config.get("extra_flags", ["-shared", "-fPIC"]))
        self.timeout = int(config.get("timeout", getattr(adapter, "timeout", 30)))

    def validate_reference(self, sample, executor, workdir: Path) -> ValidationResult:
        code = str(sample.private_payload["row"].get("func", ""))
        evidence = self.evaluate_candidate(sample, code, executor, workdir)
        return ValidationResult(sample.sample_id, evidence.recompilable, evidence)

    def evaluate_candidate(self, sample, code: str, executor, workdir: Path):
        started = time.perf_counter()
        workdir.mkdir(parents=True, exist_ok=True)
        cpp = sample.language in {"cpp", "c++", "cxx"}
        compiler = "clang++" if cpp and self.clang == "clang" else self.clang
        suffix = ".cpp" if cpp else ".c"
        source_path = workdir / f"candidate{suffix}"
        library_path = workdir / "libfunction.so"
        prelude = sample.compile_context.prelude if sample.compile_context else ""
        source_path.write_text(f"{prelude}\n{code}\n", encoding="utf-8")
        result = executor.run(
            [compiler, *self.extra_flags, str(source_path), "-o", str(library_path)],
            cwd=workdir,
            timeout=self.timeout,
        )
        passed = not result.timed_out and result.returncode == 0
        return self.evidence(
            compile_pass=passed,
            link_pass=passed,
            reason=None if passed else ("compile_timeout" if result.timed_out else "compile_error"),
            elapsed_seconds=time.perf_counter() - started,
            logs={"compile": command_log(result)},
            stages=[{"name": "shared_object_compile", "passed": passed}],
            details={"shared_object": str(library_path)},
        )
