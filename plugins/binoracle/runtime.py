from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .dependencies import unsupported_direct_dependencies
from .protocol import InputCase, KnownContract, normalize_observation
from .schemas import BinaryFacts
from .security import sanitized_subprocess_environment


class RunnerError(RuntimeError):
    pass


class UnsupportedSample(ValueError):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class RunnerBuild:
    executable: Path
    manifest: dict[str, Any]


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _safe_symbol(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$@]*", value))


def _c_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


class KnownContractManifest:
    def __init__(self, config: dict[str, Any]):
        self.inline_contract = config.get("known_contract")
        self.inline_inputs = config.get("input_cases")
        self.path = Path(config["contract_manifest"]).expanduser().resolve() if config.get(
            "contract_manifest"
        ) else None
        self.payload: dict[str, Any] = {}
        if self.path is not None:
            if not self.path.is_file():
                raise ValueError(f"BinOracle contract_manifest does not exist: {self.path}")
            self.payload = json.loads(self.path.read_text(encoding="utf-8"))
            if int(self.payload.get("schema_version", 1)) != 1:
                raise ValueError("unsupported BinOracle contract manifest schema")

    def resolve(
        self, *, sample_id: str, function_name: str
    ) -> tuple[KnownContract, list[InputCase]]:
        if self.inline_contract is not None:
            record = {"contract": self.inline_contract, "inputs": self.inline_inputs or []}
        else:
            samples = self.payload.get("samples", {})
            functions = self.payload.get("functions", {})
            record = samples.get(sample_id) or functions.get(function_name)
            if record is None:
                raise UnsupportedSample(
                    "unsupported_missing_known_contract",
                    f"no known contract for sample {sample_id} / function {function_name}",
                )
        contract = KnownContract.from_dict(dict(record.get("contract", record)))
        raw_inputs = list(record.get("inputs", []))
        inputs = [InputCase.from_dict(item, contract=contract) for item in raw_inputs]
        if not inputs:
            from .protocol import default_input_case

            inputs = [default_input_case(contract)]
        return contract, inputs


class ABIRunner:
    version = "binoracle-harness-H2"

    def __init__(self, config: dict[str, Any]):
        self.compiler = str(config.get("runner_compiler", "gcc"))
        self.build_timeout = float(config.get("runner_build_timeout", 120))
        self.execution_timeout_ms = int(config.get("runner_execution_timeout_ms", 100))
        self.max_executions = min(1000, max(1, int(config.get("max_executions", 1000))))
        self.runtime_dir = Path(__file__).resolve().parent / "runtime"
        self.candidate_namespace_isolation = bool(
            config.get("candidate_namespace_isolation", True)
        )
        self.candidate_read_only_mount = bool(
            config.get("candidate_read_only_mount", False)
        )

    def prepare(self) -> None:
        if platform.system() != "Linux":
            raise RuntimeError("BinOracle dynamic_audit requires Linux/WSL")
        if platform.machine().lower() not in {"x86_64", "amd64"}:
            raise RuntimeError("BinOracle dynamic_audit requires an x86-64 host")
        if shutil.which(self.compiler) is None:
            raise RuntimeError(f"BinOracle runner compiler not found: {self.compiler}")
        if self.candidate_namespace_isolation:
            unshare = shutil.which("unshare")
            if unshare is None:
                raise RuntimeError(
                    "candidate_namespace_isolation requires the Linux unshare tool"
                )
            probe = subprocess.run(
                [
                    unshare,
                    "--user",
                    "--map-root-user",
                    "--net",
                    "--pid",
                    "--fork",
                    "--kill-child=KILL",
                    "--mount",
                    "--mount-proc",
                    "/bin/true",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                env=sanitized_subprocess_environment(),
            )
            if probe.returncode != 0:
                raise RuntimeError(
                    "candidate namespace isolation is unavailable: " + probe.stderr[-1000:]
                )
        try:
            import elftools  # noqa: F401
        except ImportError as error:
            raise RuntimeError(
                "BinOracle dynamic_audit requires pyelftools; install with: "
                "pip install -e '.[binoracle]'"
            ) from error

    def _binding_source(
        self, facts: BinaryFacts, *, define_weak_globals: bool = False
    ) -> tuple[str, list[dict[str, Any]]]:
        target = facts.target
        if target.get("binding") not in {"GLOBAL", "WEAK"}:
            raise UnsupportedSample(
                "unsupported_nonexported_target",
                f"target symbol binding is {target.get('binding')}",
            )
        if not _safe_symbol(facts.target_function):
            raise UnsupportedSample(
                "unsupported_target_symbol_name", facts.target_function
            )

        globals_: list[dict[str, Any]] = []
        lines = [
            '#include "binoracle_runtime.h"',
            f'extern void binoracle_link_target(void) __asm__("{_c_string(facts.target_function)}");',
            "void *binoracle_target_address(void) { return (void *)&binoracle_link_target; }",
        ]
        for item in facts.global_objects:
            name = str(item.get("name", ""))
            size = int(item.get("size", 0))
            if item.get("binding") not in {"GLOBAL", "WEAK"}:
                continue
            if not name or not _safe_symbol(name) or size <= 0:
                continue
            if size > 256:
                continue
            index = len(globals_)
            if define_weak_globals:
                lines.append(
                    f'unsigned char binoracle_global_{index}[{size}] '
                    f'__asm__("{_c_string(name)}") __attribute__((weak));'
                )
            else:
                lines.append(
                    f'extern unsigned char binoracle_global_{index}[{size}] '
                    f'__asm__("{_c_string(name)}");'
                )
            globals_.append({"name": name, "size": size, "section": item.get("section")})
        if globals_:
            lines.append("struct BinOracleGlobal binoracle_globals[] = {")
            for index, item in enumerate(globals_):
                lines.append(
                    f'    {{"{_c_string(item["name"])}", binoracle_global_{index}, '
                    f'{item["size"]}U}},'
                )
            lines.append("};")
        else:
            lines.append(
                "struct BinOracleGlobal binoracle_globals[1] = {{0, (unsigned char *)0, 0}};"
            )
        lines.append(f"const size_t binoracle_global_count = {len(globals_)}U;")
        return "\n".join(lines) + "\n", globals_

    def build_original(
        self,
        *,
        binary_path: Path,
        facts: BinaryFacts,
        contract: KnownContract,
        stage_dir: Path,
    ) -> RunnerBuild:
        unknown = tuple(
            item["name"]
            for item in facts.dependencies
            if not item.get("supported")
        )
        direct_unknown = unsupported_direct_dependencies(facts.dependencies)
        if unknown:
            raise UnsupportedSample(
                "unsupported_unknown_external_dependency",
                "unknown undefined symbols: " + ", ".join(unknown),
            )
        binding, globals_ = self._binding_source(facts)
        binding_path = stage_dir / "target_binding.c"
        binding_path.write_text(binding, encoding="utf-8")
        executable = stage_dir / "original_runner.x"
        sources = [
            self.runtime_dir / "runner_main.c",
            self.runtime_dir / "deterministic_stubs.c",
            self.runtime_dir / "guard_memory.c",
            self.runtime_dir / "observation.c",
            self.runtime_dir / "abi_trampoline.S",
            binding_path,
            binary_path.resolve(),
        ]
        command = [
            self.compiler,
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-pie",
            "-no-pie",
            "-I",
            str(self.runtime_dir),
            *map(str, sources),
            "-o",
            str(executable),
            "-lm",
        ]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=stage_dir,
                capture_output=True,
                text=True,
                timeout=self.build_timeout,
                check=False,
            )
            timed_out = False
        except subprocess.TimeoutExpired as error:
            completed = None
            timed_out = True
            stdout = error.stdout or ""
            stderr = error.stderr or ""
        else:
            stdout = completed.stdout
            stderr = completed.stderr
        manifest = {
            "schema_version": 1,
            "harness_version": self.version,
            "kind": "original",
            "command": command,
            "returncode": completed.returncode if completed else None,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "elapsed_seconds": time.perf_counter() - started,
            "target": facts.target_function,
            "contract_id": contract.contract_id,
            "globals": globals_,
            "direct_unknown_dependencies": list(direct_unknown),
        }
        _write_json(stage_dir / "runner_build.json", manifest)
        if timed_out:
            raise RunnerError("original runner build timed out")
        if completed is None or completed.returncode != 0 or not executable.is_file():
            raise RunnerError("original runner build failed: " + stderr[-2000:])
        return RunnerBuild(executable, manifest)

    def build_candidate(
        self,
        *,
        candidate_object: Path,
        facts: BinaryFacts,
        contract: KnownContract,
        stage_dir: Path,
    ) -> RunnerBuild:
        binding, globals_ = self._binding_source(facts, define_weak_globals=True)
        binding_path = stage_dir / "target_binding.c"
        binding_path.write_text(binding, encoding="utf-8")
        executable = stage_dir / "candidate_runner.x"
        sources = [
            self.runtime_dir / "runner_main.c",
            self.runtime_dir / "deterministic_stubs.c",
            self.runtime_dir / "guard_memory.c",
            self.runtime_dir / "observation.c",
            self.runtime_dir / "abi_trampoline.S",
            binding_path,
            candidate_object.resolve(),
        ]
        command = [
            self.compiler,
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-pie",
            "-no-pie",
            "-I",
            str(self.runtime_dir),
            *map(str, sources),
            "-o",
            str(executable),
            "-lm",
        ]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=stage_dir,
                capture_output=True,
                text=True,
                timeout=self.build_timeout,
                check=False,
            )
            timed_out = False
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as error:
            completed = None
            timed_out = True
            stdout = error.stdout or ""
            stderr = error.stderr or ""
        manifest = {
            "schema_version": 1,
            "harness_version": self.version,
            "kind": "candidate",
            "command": command,
            "returncode": completed.returncode if completed else None,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "elapsed_seconds": time.perf_counter() - started,
            "target": facts.target_function,
            "contract_id": contract.contract_id,
            "globals": globals_,
        }
        _write_json(stage_dir / "runner_build.json", manifest)
        if timed_out:
            raise RunnerError("candidate runner build timed out")
        if completed is None or completed.returncode != 0 or not executable.is_file():
            raise RunnerError("candidate runner build failed: " + stderr[-2000:])
        return RunnerBuild(executable, manifest)

    def execute(
        self,
        build: RunnerBuild,
        *,
        contract: KnownContract,
        input_case: InputCase,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        payload = json.dumps(input_case.to_dict(), ensure_ascii=False, sort_keys=True)
        command = [
            str(build.executable),
            "--timeout-ms",
            str(self.execution_timeout_ms),
        ]
        isolated = build.manifest.get("kind") == "candidate"
        if isolated and self.candidate_namespace_isolation:
            read_only_wrapper: list[str] = []
            if self.candidate_read_only_mount:
                mount = subprocess.run(
                    [
                        "findmnt",
                        "-n",
                        "-o",
                        "TARGET",
                        "--target",
                        str(build.executable),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                    env=sanitized_subprocess_environment(),
                )
                mount_target = mount.stdout.strip()
                if mount.returncode != 0 or not mount_target or mount_target == "/":
                    raise RunnerError(
                        "candidate read-only mount isolation requires a dedicated "
                        "workspace mount"
                    )
                wrapper = (
                    'mount --make-rprivate / && mount --bind "$1" "$1" && '
                    'mount -o remount,bind,ro "$1" && '
                    'mount -t tmpfs -o size=16m,nosuid,nodev,noexec tmpfs /tmp && '
                    'executable="$2" && shift 2 && cd /tmp && exec "$executable" "$@"'
                )
                read_only_wrapper = ["sh", "-c", wrapper, "sh", mount_target]
            command = [
                "unshare",
                "--user",
                "--map-root-user",
                "--net",
                "--pid",
                "--fork",
                "--kill-child=KILL",
                "--mount",
                "--mount-proc",
                *read_only_wrapper,
                *command,
            ]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                input=payload,
                capture_output=True,
                text=True,
                timeout=max(2.0, self.execution_timeout_ms / 1000.0 + 1.0),
                check=False,
                env=sanitized_subprocess_environment(),
            )
        except subprocess.TimeoutExpired as error:
            raise RunnerError("runner parent process did not enforce its timeout") from error
        record = {
            "command": command,
            "returncode": completed.returncode,
            "stderr": completed.stderr[-4000:],
            "elapsed_seconds": time.perf_counter() - started,
            "candidate_namespace_isolation": isolated
            and self.candidate_namespace_isolation,
            "candidate_read_only_mount": isolated
            and self.candidate_namespace_isolation
            and self.candidate_read_only_mount,
        }
        if completed.returncode != 0:
            raise RunnerError(
                f"runner failed with exit {completed.returncode}: {completed.stderr[-2000:]}"
            )
        try:
            raw = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RunnerError(f"runner emitted invalid JSON: {completed.stdout[-1000:]}") from error
        return normalize_observation(raw, contract=contract, input_case=input_case), record
