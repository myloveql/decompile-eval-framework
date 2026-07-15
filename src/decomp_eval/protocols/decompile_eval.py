from __future__ import annotations

import time
from pathlib import Path

from .base import BaseEvaluationProtocol
from ..datasets.common import command_log
from ..models import ProtocolDescriptor, ValidationResult


class DecompileEvalExitCodeProtocol(BaseEvaluationProtocol):
    descriptor = ProtocolDescriptor(
        protocol_id="decompile_eval_exitcode",
        version="1",
        description="Compile dependencies, candidate, and dataset test as one program; success is exit code zero.",
        capabilities=("candidate_compile", "fixture_link", "behavioral_test", "aggregate_test_program"),
        compile_unit="candidate_dependencies_and_test",
        test_granularity="single_test_program",
        comparator="process_exit_code_zero",
    )

    def validate_reference(self, sample, executor, workdir: Path) -> ValidationResult:
        evidence = self.evaluate_candidate(sample, sample.private_payload["row"]["func"], executor, workdir)
        return ValidationResult(sample.sample_id, evidence.recompilable and evidence.behavioral_pass, evidence)

    def evaluate_candidate(self, sample, code: str, executor, workdir: Path):
        started = time.perf_counter()
        row = sample.private_payload["row"]
        workdir.mkdir(parents=True, exist_ok=True)
        cpp = sample.language in {"cpp", "c++", "cxx"}
        compiler = "g++" if cpp else "gcc"
        flags = self.adapter.cpp_flags if cpp else self.adapter.c_flags
        libraries = self.adapter.cpp_libraries if cpp else self.adapter.c_libraries
        source_path = workdir / ("candidate.cpp" if cpp else "candidate.c")
        object_path = workdir / "candidate.o"
        exe_path = workdir / "candidate.x"
        source_path.write_text(
            str(row.get("func_dep", "")) + "\n" + code + "\n" + str(row.get("test", "")), encoding="utf-8"
        )
        compile_result = executor.run(
            [compiler, f"-{sample.optimization}", *flags, "-c", str(source_path), "-o", str(object_path)],
            cwd=workdir, timeout=self.adapter.timeout,
        )
        logs = {"compile": command_log(compile_result)}
        stages = [{"name": "combined_compile", "passed": not compile_result.timed_out and compile_result.returncode == 0}]
        if compile_result.timed_out or compile_result.returncode != 0:
            return self.evidence(
                reason="compile_timeout" if compile_result.timed_out else "compile_error",
                elapsed_seconds=time.perf_counter() - started, logs=logs, stages=stages,
            )
        link_result = executor.run(
            [compiler, f"-{sample.optimization}", str(object_path), "-o", str(exe_path), *libraries],
            cwd=workdir, timeout=self.adapter.timeout,
        )
        logs["link"] = command_log(link_result)
        stages.append({"name": "fixture_link", "passed": not link_result.timed_out and link_result.returncode == 0})
        if link_result.timed_out or link_result.returncode != 0:
            return self.evidence(
                compile_pass=True, reason="link_timeout" if link_result.timed_out else "link_error",
                elapsed_seconds=time.perf_counter() - started, logs=logs, stages=stages,
            )
        run_result = executor.run([str(exe_path)], cwd=workdir, timeout=self.adapter.timeout)
        logs["tests"] = [command_log(run_result)]
        passed = not run_result.timed_out and run_result.returncode == 0
        stages.append({"name": "behavioral_test", "passed": passed})
        return self.evidence(
            compile_pass=True, link_pass=True, behavioral_pass=passed,
            reason=None if passed else ("test_timeout" if run_result.timed_out else "test_failed"),
            tests_total=1, tests_passed=int(passed), elapsed_seconds=time.perf_counter() - started,
            logs=logs, stages=stages,
            details={"test_program_returncode": run_result.returncode, "timed_out": run_result.timed_out},
        )
