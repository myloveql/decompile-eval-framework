"""Opt-in improvements for Agent4Decompile; the reproduction backend stays unchanged."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from types import MethodType, SimpleNamespace
from typing import Any

from decomp_eval.datasets.common import strict_equal
from decomp_eval.datasets.exebench import externalize_target, sanitize_dependencies
from decomp_eval.models import DecompileRequest, DecompileResult
from plugins.agent4decompile_backend import Agent4DecompileBackend


class ProtocolAlignedExeBenchL3:
    """Run L3 with the same compile/link/comparison semantics as formal evaluation."""

    def __init__(self, request: DecompileRequest, artifact_dir: Path, *, timeout: float):
        if request.compile_context is None:
            raise ValueError("protocol-aligned ExeBench L3 requires compile_context")
        self.request = request
        self.context = request.compile_context
        self.artifact_dir = artifact_dir
        self.timeout = timeout
        self.index = 0

    def _run(self, command: list[str], cwd: Path) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None

    def evaluate_execution_exebench(
        self,
        code: str,
        io_pairs: list[dict[str, Any]],
        cpp_wrapper: str,
        c_deps: str,
        func_head: str,
        exebench_include: str,
    ) -> tuple[bool, str, dict[str, Any]]:
        workdir = self.artifact_dir / f"aligned_{self.index:02d}"
        self.index += 1
        workdir.mkdir(parents=True, exist_ok=True)
        source_path = workdir / "candidate.c"
        object_path = workdir / "candidate.o"
        deps_path = workdir / "wrapper_deps.c"
        wrapper_path = workdir / "wrapper.cpp"
        executable_path = workdir / "candidate.x"

        source_path.write_text(
            f"{self.context.prelude.rstrip()}\n"
            f"{externalize_target(code.strip(), self.request.function_name)}\n",
            encoding="utf-8",
        )
        flags = [
            str(flag)
            for flag in self.context.flags
            if not re.match(r"^-O(?:0|1|2|3|s|z|fast)$", str(flag), re.IGNORECASE)
        ]
        optimization = f"-{str(self.request.optimization).lstrip('-')}"
        compile_command = [
            self.context.compiler,
            "-c",
            optimization,
            *flags,
            "-o",
            str(object_path),
            str(source_path),
        ]
        compiled = self._run(compile_command, workdir)
        if compiled is None:
            return False, "Protocol-aligned L3 candidate compilation timed out", {
                "stage": "candidate_compile",
                "timed_out": True,
            }
        if compiled.returncode != 0:
            return False, (
                "Protocol-aligned L3 candidate compilation failed:\n"
                + compiled.stderr[:1600]
            ), {"stage": "candidate_compile", "returncode": compiled.returncode}

        wrapper_deps = sanitize_dependencies(c_deps, for_cpp_wrapper=True)
        deps_path.write_text(
            f"{wrapper_deps.rstrip()}\nextern {func_head.strip()};\n", encoding="utf-8"
        )
        fixed_wrapper, replacements = re.subn(
            r'extern\s*"C"\s*\{\s.*?\s*\}',
            lambda _: f'extern "C"\n{{\n#include "{deps_path}"\n}}',
            cpp_wrapper,
            count=1,
            flags=re.DOTALL,
        )
        if replacements != 1:
            return False, "Protocol-aligned L3 could not rewrite the ExeBench wrapper", {
                "stage": "fixture_prepare"
            }
        wrapper_path.write_text(fixed_wrapper, encoding="utf-8")
        link_command = [
            "g++",
            "-fpermissive",
            optimization,
            "-o",
            str(executable_path),
            str(wrapper_path),
            str(object_path),
            f"-I{exebench_include}",
            *self.context.libraries,
        ]
        linked = self._run(link_command, workdir)
        if linked is None:
            return False, "Protocol-aligned L3 fixture linking timed out", {
                "stage": "fixture_link",
                "timed_out": True,
            }
        if linked.returncode != 0:
            return False, (
                "Protocol-aligned L3 fixture linking failed:\n" + linked.stderr[:1600]
            ), {"stage": "fixture_link", "returncode": linked.returncode}

        details: dict[str, Any] = {
            "total": len(io_pairs),
            "passed": 0,
            "failed": 0,
            "failures": [],
        }
        for case_index, pair in enumerate(io_pairs):
            input_path = workdir / f"input_{case_index}.json"
            output_path = workdir / f"output_{case_index}.json"
            input_path.write_text(json.dumps(pair.get("input", {})), encoding="utf-8")
            run = self._run(
                [str(executable_path), str(input_path), str(output_path)], workdir
            )
            failure: dict[str, Any] | None = None
            if run is None:
                failure = {"test_id": case_index, "error": "timeout"}
            elif run.returncode != 0 or not output_path.exists():
                failure = {
                    "test_id": case_index,
                    "error": f"runtime exit code {run.returncode}",
                }
            else:
                try:
                    actual = json.loads(output_path.read_text(encoding="utf-8"))
                    expected = pair.get("output", {})
                    if not strict_equal(actual, expected):
                        failure = {
                            "test_id": case_index,
                            "expected": json.dumps(expected, default=str)[:300],
                            "actual": json.dumps(actual, default=str)[:300],
                        }
                except (OSError, json.JSONDecodeError) as error:
                    failure = {"test_id": case_index, "error": str(error)[:300]}
            if failure is None:
                details["passed"] += 1
            else:
                details["failed"] += 1
                details["failures"].append(failure)

        if details["failed"] == 0 and details["total"]:
            return True, f"All {details['total']} protocol-aligned ExeBench tests pass", details
        lines = [
            f"{details['failed']}/{details['total']} protocol-aligned ExeBench tests failed"
        ]
        for failure in details["failures"][:2]:
            lines.append(f"Test #{failure['test_id']}:")
            if "error" in failure:
                lines.append(f"  Error: {failure['error']}")
            else:
                lines.append(f"  Expected: {failure['expected']}")
                lines.append(f"  Actual:   {failure['actual']}")
        return False, "\n".join(lines), details


class ImprovedAgent4DecompileBackend(Agent4DecompileBackend):
    """Separate improved variant; never used by reproduction configurations."""

    version = "agent4decompile-improved-adapter-v1"

    def __init__(self, config: dict[str, Any]):
        self.expose_public_prelude = bool(config.get("expose_public_prelude", True))
        self.protocol_aligned_l3 = bool(config.get("protocol_aligned_l3", True))
        self.stagnation_limit = max(1, int(config.get("stagnation_limit", 2)))
        self._active_request: DecompileRequest | None = None
        super().__init__(config)
        self.version += (
            f":context-{int(self.expose_public_prelude)}"
            f":aligned-l3-{int(self.protocol_aligned_l3)}"
            f":stagnation-{self.stagnation_limit}"
        )
        if self.protocol_aligned_l3:
            self.constraint_evaluator_class = self._aligned_l3_factory

    def _aligned_l3_factory(self, **kwargs: Any) -> ProtocolAlignedExeBenchL3:
        if self._active_request is None:
            raise RuntimeError("improved L3 evaluator was created without an active request")
        return ProtocolAlignedExeBenchL3(
            self._active_request,
            Path(kwargs["temp_dir"]),
            timeout=self.compile_timeout,
        )

    @staticmethod
    def _rank(constraints: dict[str, Any]) -> tuple[int, int, int]:
        if not constraints["syntax"]["pass"]:
            return (0, 0, 0)
        if not constraints["compilation"]["pass"]:
            return (1, 0, 0)
        execution = constraints["execution"]
        if execution["pass"] is True:
            details = execution.get("details") or {}
            return (3, int(details.get("passed", 0)), 0)
        details = execution.get("details") or {}
        return (
            2,
            int(details.get("passed", 0)),
            -int(details.get("failed", 0)),
        )

    def _improved_refine(self, refiner: Any):
        backend = self

        def refine(
            this,
            initial_code,
            binary_name,
            decompiler,
            original_binary_path=None,
            test_cases=None,
            exebench_data=None,
        ):
            current = backend.preprocess(initial_code, decompiler)
            best_code = current
            best_rank = (-1, 0, 0)
            history: list[dict[str, Any]] = []
            seen_states: set[str] = set()
            repeated_candidates = 0

            for iteration in range(this.max_iterations):
                constraints = this.evaluator.evaluate_all(
                    current,
                    original_binary=original_binary_path,
                    test_cases=test_cases,
                    constraint_level=this.constraint_level,
                    exebench_data=exebench_data,
                )
                rank = backend._rank(constraints)
                if rank > best_rank:
                    best_rank, best_code = rank, current
                history.append(
                    {
                        "iteration": iteration,
                        "syntax_pass": constraints["syntax"]["pass"],
                        "compilation_pass": constraints["compilation"]["pass"],
                        "execution_pass": constraints["execution"]["pass"],
                        "score": rank[0],
                        "fine_grained_rank": list(rank),
                    }
                )
                if rank[0] == 3:
                    return SimpleNamespace(
                        success=True,
                        refined_code=current,
                        iterations=iteration + 1,
                        syntax_valid=True,
                        compiles=True,
                        re_executable=True,
                        iteration_history=history,
                        error_message=None,
                    )
                if (
                    constraints["syntax"]["pass"]
                    and constraints["compilation"]["pass"]
                    and constraints["execution"]["pass"] is None
                ):
                    return SimpleNamespace(
                        success=True,
                        refined_code=current,
                        iterations=iteration + 1,
                        syntax_valid=True,
                        compiles=True,
                        re_executable=False,
                        iteration_history=history,
                        error_message=None,
                    )

                state_material = json.dumps(
                    {
                        "code": current,
                        "syntax": constraints["syntax"]["message"],
                        "compilation": constraints["compilation"]["message"],
                        "execution": constraints["execution"]["message"],
                    },
                    sort_keys=True,
                )
                state_hash = hashlib.sha256(state_material.encode()).hexdigest()
                prompt = this._build_prompt(
                    current, constraints, iteration, binary_name, decompiler
                )
                if state_hash in seen_states:
                    prompt += (
                        "\n\n## Stagnation Notice\n"
                        "The previous repair produced the same code and the same failure. "
                        "Use a materially different strategy and do not repeat conflicting "
                        "declarations."
                    )
                seen_states.add(state_hash)
                try:
                    response = this._call_llm(prompt)
                    candidate = this._extract_code(response)
                except Exception as error:
                    return SimpleNamespace(
                        success=False,
                        refined_code=best_code,
                        iterations=iteration + 1,
                        syntax_valid=best_rank[0] >= 1,
                        compiles=best_rank[0] >= 2,
                        re_executable=best_rank[0] >= 3,
                        iteration_history=history,
                        error_message=f"LLM failed at iteration {iteration}: {error}",
                    )
                if hashlib.sha256(candidate.encode()).digest() == hashlib.sha256(
                    current.encode()
                ).digest():
                    repeated_candidates += 1
                else:
                    repeated_candidates = 0
                current = candidate
                if repeated_candidates >= backend.stagnation_limit:
                    return SimpleNamespace(
                        success=False,
                        refined_code=best_code,
                        iterations=iteration + 1,
                        syntax_valid=best_rank[0] >= 1,
                        compiles=best_rank[0] >= 2,
                        re_executable=best_rank[0] >= 3,
                        iteration_history=history,
                        error_message="Stopped after repeated identical candidates",
                    )

            final_constraints = this.evaluator.evaluate_all(
                best_code,
                original_binary=original_binary_path,
                test_cases=test_cases,
                constraint_level=this.constraint_level,
                exebench_data=exebench_data,
            )
            final_rank = backend._rank(final_constraints)
            required_rank = min(backend.constraint_level, 3)
            return SimpleNamespace(
                success=final_rank[0] >= required_rank,
                refined_code=best_code,
                iterations=len(history),
                syntax_valid=final_constraints["syntax"]["pass"],
                compiles=final_constraints["compilation"]["pass"],
                re_executable=final_constraints["execution"]["pass"] is True,
                iteration_history=history,
                error_message=(
                    "Max iterations reached" if final_rank[0] < required_rank else None
                ),
            )

        return MethodType(refine, refiner)

    def _new_refiner(self, evaluator):
        refiner, native_call = super()._new_refiner(evaluator)
        if self.expose_public_prelude and evaluator.context.prelude.strip():
            original_build_prompt = refiner._build_prompt
            public_context = evaluator.context.prelude.strip()

            def build_prompt(code, constraints, iteration, binary_name, decompiler):
                prompt = original_build_prompt(
                    code, constraints, iteration, binary_name, decompiler
                )
                marker = "\n## Current Code"
                context_block = (
                    "\n## Public Compile Context\n"
                    "These declarations are supplied externally. Use their exact types; "
                    "do not redefine them in the candidate.\n```c\n"
                    f"{public_context}\n```\n"
                )
                return prompt.replace(marker, context_block + marker, 1)

            refiner._build_prompt = build_prompt
        refiner.refine = self._improved_refine(refiner)
        return refiner, native_call

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        self._active_request = request
        try:
            result = super().decompile(request, artifact_dir)
            metadata_path = artifact_dir / "agent4_metadata.json"
            if metadata_path.is_file():
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                metadata.update(
                    {
                        "implementation_variant": "improved",
                        "expose_public_prelude": self.expose_public_prelude,
                        "protocol_aligned_l3": self.protocol_aligned_l3,
                        "stagnation_limit": self.stagnation_limit,
                        "candidate_selection": "fine_grained_constraint_rank",
                    }
                )
                metadata_path.write_text(
                    json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            return result
        finally:
            self._active_request = None
