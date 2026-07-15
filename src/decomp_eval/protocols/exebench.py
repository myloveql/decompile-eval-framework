from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .base import BaseEvaluationProtocol
from ..datasets.common import command_log, strict_equal
from ..datasets.exebench import externalize_target, sanitize_dependencies
from ..models import ProtocolDescriptor, ValidationResult


class ExeBenchJsonIOProtocol(BaseEvaluationProtocol):
    descriptor = ProtocolDescriptor(
        protocol_id="exebench_json_io",
        version="1",
        description="Compile candidate separately, link the ExeBench C++ wrapper, and compare every JSON I/O case.",
        capabilities=(
            "candidate_compile", "fixture_link", "behavioral_test", "per_case_test",
            "structured_output", "strict_json_compare",
        ),
        compile_unit="candidate_only",
        test_granularity="per_io_case",
        comparator="strict_recursive_json_with_float_tolerance",
    )

    def validate_reference(self, sample, executor, workdir: Path) -> ValidationResult:
        code = sample.private_payload["row"]["source"]["code"]
        evidence = self.evaluate_candidate(sample, code, executor, workdir)
        return ValidationResult(sample.sample_id, evidence.recompilable and evidence.behavioral_pass, evidence)

    def evaluate_candidate(self, sample, code: str, executor, workdir: Path):
        started = time.perf_counter()
        row = sample.private_payload["row"]
        evaluation = row["evaluation"]
        workdir.mkdir(parents=True, exist_ok=True)
        source_path = workdir / "candidate.c"
        object_path = workdir / "candidate.o"
        source_deps = sanitize_dependencies(evaluation.get("dependencies", ""), for_cpp_wrapper=False)
        source_path.write_text(
            source_deps + "\n" + externalize_target(code, sample.function_name) + "\n", encoding="utf-8"
        )
        compile_result = executor.run(
            ["gcc", "-c", f"-{sample.optimization}", "-std=gnu11", "-fcommon", "-w", "-o", str(object_path), str(source_path)],
            cwd=workdir, timeout=self.adapter.timeout,
        )
        logs: dict[str, Any] = {"compile": command_log(compile_result)}
        stages = [{"name": "candidate_compile", "passed": not compile_result.timed_out and compile_result.returncode == 0}]
        if compile_result.timed_out or compile_result.returncode != 0:
            return self.evidence(
                reason="compile_timeout" if compile_result.timed_out else "compile_error",
                elapsed_seconds=time.perf_counter() - started, logs=logs, stages=stages,
            )

        wrapper_deps = sanitize_dependencies(evaluation.get("dependencies", ""), for_cpp_wrapper=True)
        func_head = evaluation.get("function_head_used_by_wrapper", "").strip()
        deps_path = workdir / "wrapper_deps.c"
        deps_path.write_text(wrapper_deps + f"\nextern {func_head};\n", encoding="utf-8")
        wrapper = evaluation.get("executable_wrapper", "")
        fixed_wrapper, replacements = re.subn(
            r'extern\s*"C"\s*\{\s.*?\s*\}', f'extern "C"\n{{\n#include "{deps_path}"\n}}',
            wrapper, count=1, flags=re.DOTALL,
        )
        if replacements != 1:
            stages.append({"name": "fixture_prepare", "passed": False})
            return self.evidence(
                compile_pass=True, reason="wrapper_rewrite_failed",
                elapsed_seconds=time.perf_counter() - started, logs=logs, stages=stages,
            )
        wrapper_path = workdir / "wrapper.cpp"
        wrapper_path.write_text(fixed_wrapper, encoding="utf-8")
        exe_path = workdir / "candidate.x"
        link_result = executor.run(
            ["g++", "-fpermissive", f"-{sample.optimization}", "-o", str(exe_path), str(wrapper_path),
             str(object_path), f"-I{self.adapter.include_path}", "-lm"],
            cwd=workdir, timeout=self.adapter.timeout,
        )
        logs["link"] = command_log(link_result)
        stages.append({"name": "fixture_link", "passed": not link_result.timed_out and link_result.returncode == 0})
        if link_result.timed_out or link_result.returncode != 0:
            return self.evidence(
                compile_pass=True, reason="link_timeout" if link_result.timed_out else "link_error",
                elapsed_seconds=time.perf_counter() - started, logs=logs, stages=stages,
            )

        io_pairs = evaluation.get("io_pairs", [])
        passed = 0
        test_logs: list[dict[str, Any]] = []
        reason = None
        counts = {"timed_out": 0, "crashed": 0, "mismatched": 0}
        for index, pair in enumerate(io_pairs):
            input_path = workdir / f"input_{index}.json"
            output_path = workdir / f"output_{index}.json"
            input_path.write_text(json.dumps(pair.get("input", {})), encoding="utf-8")
            run_result = executor.run(
                [str(exe_path), str(input_path), str(output_path)], cwd=workdir, timeout=self.adapter.timeout
            )
            entry = command_log(run_result)
            entry["index"] = index
            if run_result.timed_out:
                entry["outcome"] = "timeout"
                counts["timed_out"] += 1
                reason = reason or "test_timeout"
            elif run_result.returncode != 0 or not output_path.exists():
                entry["outcome"] = "runtime_error"
                counts["crashed"] += 1
                reason = reason or "runtime_error"
            else:
                try:
                    actual = json.loads(output_path.read_text(encoding="utf-8"))
                    expected = pair.get("output", {})
                    if strict_equal(actual, expected):
                        passed += 1
                        entry["outcome"] = "pass"
                    else:
                        counts["mismatched"] += 1
                        entry.update({"outcome": "output_mismatch", "expected": expected, "actual": actual})
                        reason = reason or "output_mismatch"
                except (OSError, json.JSONDecodeError) as error:
                    counts["mismatched"] += 1
                    entry.update({"outcome": "invalid_output", "error": str(error)})
                    reason = reason or "invalid_output"
            test_logs.append(entry)
        logs["tests"] = test_logs
        behavioral = bool(io_pairs) and passed == len(io_pairs)
        stages.append({"name": "behavioral_test", "passed": behavioral})
        return self.evidence(
            compile_pass=True, link_pass=True, behavioral_pass=behavioral,
            reason=None if behavioral else (reason or "no_tests"), tests_total=len(io_pairs),
            tests_passed=passed, elapsed_seconds=time.perf_counter() - started, logs=logs,
            stages=stages, details=counts,
        )
