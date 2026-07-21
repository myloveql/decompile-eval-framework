from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from decomp_eval.models import DecompileRequest, DecompileResult

from plugins.binoracle import BinOracleEngine
from plugins.binoracle.binary_facts import BinaryFactError
from plugins.binoracle.privacy import find_private_metadata_paths
from plugins.binoracle.runtime import RunnerError, UnsupportedSample


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


class BinOracleBackend:
    version = "binoracle-backend-v3-phase3b"

    def __init__(self, config: dict[str, Any]):
        self.config = dict(config)
        self.strict_privacy = bool(config.get("strict_privacy", True))
        self.engine = BinOracleEngine(config)
        implementation = hashlib.sha256()
        implementation_root = Path(__file__).resolve().parent / "binoracle"
        for path in sorted(
            item
            for item in implementation_root.rglob("*")
            if item.is_file() and item.suffix in {".py", ".c", ".h", ".S", ".json"}
        ):
            implementation.update(path.relative_to(implementation_root).as_posix().encode())
            implementation.update(b"\0")
            implementation.update(path.read_bytes())
            implementation.update(b"\0")
        contract_identity: Any = {
            "known_contract": config.get("known_contract"),
            "input_cases": config.get("input_cases"),
        }
        manifest_path = config.get("contract_manifest")
        if manifest_path:
            resolved_manifest = Path(manifest_path).expanduser().resolve()
            contract_identity = {
                "path": str(resolved_manifest),
                "sha256": hashlib.sha256(resolved_manifest.read_bytes()).hexdigest(),
            }
        contract_hash = hashlib.sha256(
            json.dumps(contract_identity, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        self.version = (
            f"{type(self).version}:impl-{implementation.hexdigest()[:12]}:"
            f"contract-{contract_hash[:12]}"
        )

    def prepare(self, requests: list[DecompileRequest]) -> None:
        self.engine.prepare()

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        if request.binary is None:
            return self._failure("binoracle_missing_binary", "required_inputs must include binary", started)
        if request.pseudocode is None or not request.pseudocode.text.strip():
            return self._failure(
                "binoracle_missing_pseudocode", "required_inputs must include pseudocode", started
            )
        if not request.assembly.text.strip():
            return self._failure(
                "binoracle_missing_assembly", "required_inputs must include assembly", started
            )
        if request.oracle_context is not None:
            return self._failure(
                "binoracle_private_oracle_exposed",
                "strict BinOracle must not request oracle_context",
                started,
            )
        if request.compile_context is not None:
            return self._failure(
                "binoracle_private_compile_context_exposed",
                "strict BinOracle must not request compile_context",
                started,
            )
        leaked = find_private_metadata_paths(request.metadata) if self.strict_privacy else []
        if leaked:
            return self._failure(
                "binoracle_private_metadata_exposed",
                "forbidden public metadata: " + ", ".join(sorted(leaked)),
                started,
            )

        public_audit = {
            "dataset_id": request.dataset_id,
            "sample_id": request.sample_id,
            "source_group_id": request.source_group_id,
            "function_name": request.function_name,
            "optimization": request.optimization,
            "binary": request.binary.path,
            "assembly_view": request.assembly.view,
            "pseudocode_view": request.pseudocode.view,
            "metadata_keys": sorted(request.metadata),
        }
        _write_json(artifact_dir / "binoracle_public_request.json", public_audit)
        try:
            result = self.engine.run(
                binary_path=Path(request.binary.path),
                target_function=request.function_name,
                initial_code=request.pseudocode.text,
                assembly=request.assembly.text,
                assembly_syntax=request.assembly.syntax,
                architecture=request.binary.architecture or "x86_64",
                optimization=request.optimization,
                sample_id=request.sample_id,
                artifact_dir=artifact_dir,
            )
        except BinaryFactError as error:
            return self._failure(
                f"binoracle_{error.reason}",
                str(error),
                started,
                artifact_dir,
                request=request,
            )
        except UnsupportedSample as error:
            return self._failure(
                f"binoracle_{error.reason}",
                str(error),
                started,
                artifact_dir,
                request=request,
            )
        except RunnerError as error:
            return self._failure(
                "binoracle_runner_error",
                str(error),
                started,
                artifact_dir,
                request=request,
            )
        except Exception as error:
            return self._failure(
                "binoracle_internal_error",
                f"{type(error).__name__}: {error}",
                started,
                artifact_dir,
                request=request,
            )

        candidate = result.candidate_code.strip()
        (artifact_dir / "binoracle_initial.c").write_text(
            request.pseudocode.text.rstrip() + "\n", encoding="utf-8"
        )
        (artifact_dir / "binoracle_final.c").write_text(candidate + "\n", encoding="utf-8")
        return DecompileResult(
            success=bool(candidate),
            raw_output=candidate,
            code=candidate,
            reason=None if candidate else "binoracle_empty_candidate",
            log=result.summary,
            elapsed_seconds=time.perf_counter() - started,
            backend_version=self.version,
        )

    def _failure(
        self,
        reason: str,
        log: str,
        started: float,
        artifact_dir: Path | None = None,
        request: DecompileRequest | None = None,
    ) -> DecompileResult:
        if artifact_dir is not None:
            request_metadata = (
                {
                    "sample_id": request.sample_id,
                    "source_group_id": request.source_group_id,
                    "optimization": request.optimization,
                }
                if request is not None
                else {}
            )
            _write_json(
                artifact_dir / "binoracle_metadata.json",
                {
                    "schema_version": 1,
                    "engine_version": self.engine.version,
                    "mode": self.engine.mode,
                    **request_metadata,
                    "unsupported_reason": reason,
                    "error": log,
                    "executions": 0,
                    "generated_tests": 0,
                    "counterexamples": 0,
                    "repair_iterations": 0,
                    "stop_reason": reason,
                },
            )
        return DecompileResult(
            success=False,
            reason=reason,
            log=log,
            elapsed_seconds=time.perf_counter() - started,
            backend_version=self.version,
        )

    def close(self) -> None:
        self.engine.close()
