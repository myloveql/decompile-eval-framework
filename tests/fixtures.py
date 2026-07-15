from __future__ import annotations

import time
from pathlib import Path

from decomp_eval.models import AssemblyInput, CanonicalSample, DecompileResult, EvaluationEvidence, ValidationResult
from decomp_eval.models import ProtocolDescriptor
from decomp_eval.protocols.base import BaseEvaluationProtocol
from decomp_eval.util import sha256_json


class FixtureDataset:
    plugin_name = "fixture"
    default_protocol = "tests.fixtures:FixtureProtocol"

    def __init__(self, config, **kwargs):
        self.dataset_id = config["id"]
        self.evaluation_protocol = None

    def iter_samples(self):
        for opt in ("O0", "O1", "O2", "O3"):
            yield CanonicalSample(
                dataset_id=self.dataset_id,
                split="test",
                sample_id=f"fixture:{opt}",
                source_group_id="fixture:group",
                function_name="answer",
                language="c",
                optimization=opt,
                assembly=AssemblyInput("answer:\n ret\n", "intel", "fixture"),
                content_hash=sha256_json({"opt": opt}),
                private_payload={"reference": "int answer(void) { return 7; }"},
            )


class FixtureProtocol(BaseEvaluationProtocol):
    descriptor = ProtocolDescriptor(
        protocol_id="fixture_exitcode", version="1", description="Test fixture protocol",
        capabilities=("candidate_compile", "fixture_link", "behavioral_test"),
        compile_unit="candidate_and_test", test_granularity="single_test_program",
        comparator="process_exit_code_zero",
    )

    def validate_reference(self, sample, executor, workdir):
        evidence = self.evaluate_candidate(
            sample, sample.private_payload["reference"], executor, workdir
        )
        return ValidationResult(sample.sample_id, evidence.recompilable and evidence.behavioral_pass, evidence)

    def evaluate_candidate(self, sample, code, executor, workdir):
        started = time.perf_counter()
        workdir.mkdir(parents=True, exist_ok=True)
        source = workdir / "candidate.c"
        obj = workdir / "candidate.o"
        exe = workdir / "candidate.x"
        source.write_text(code + "\nint main(void) { return answer() == 7 ? 0 : 1; }\n", encoding="utf-8")
        comp = executor.run(["gcc", f"-{sample.optimization}", "-c", str(source), "-o", str(obj)], cwd=workdir, timeout=15)
        if comp.returncode:
            return self.evidence(reason="compile_error")
        link = executor.run(["gcc", str(obj), "-o", str(exe)], cwd=workdir, timeout=15)
        if link.returncode:
            return self.evidence(compile_pass=True, reason="link_error")
        run = executor.run([str(exe)], cwd=workdir, timeout=15)
        passed = run.returncode == 0 and not run.timed_out
        return self.evidence(
            compile_pass=True,
            link_pass=True,
            behavioral_pass=passed,
            reason=None if passed else "test_failed",
            tests_total=1,
            tests_passed=int(passed),
            elapsed_seconds=time.perf_counter() - started,
        )


class FixtureDecompiler:
    version = "fixture-1"

    def __init__(self, config):
        self.value = int(config.get("value", 7))

    def decompile(self, request, artifact_dir):
        assert not hasattr(request, "private_payload")
        code = f"```c\nint {request.function_name}(void) {{ return {self.value}; }}\n```"
        return DecompileResult(success=True, raw_output=code, code=code)
