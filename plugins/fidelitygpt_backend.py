"""FidelityGPT pseudocode refinement with auditable long-function automation."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Any

from decomp_eval.models import DecompileRequest, DecompileResult
from plugins.openai_compatible_backend import extract_candidate_code


_DISTORTION_LABEL_RE = re.compile(r"\bI([1-6])\b", re.IGNORECASE)
_DISTORTION_NUMBER_RE = re.compile(
    r"distortion\s+type(?:\s+number)?\s*[:#-]?\s*([1-6])\b", re.IGNORECASE
)
_OPTIMIZATION_FILES = (
    "FidelityGPT.py",
    "Correction.py",
    "prompt_templates.py",
    "pattern_matcher.py",
    "variabledependency.py",
    "embedding_retriever.py",
    "document_processor.py",
    "fidelity_new.c",
    "fidelity_ghidra.c",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for name in _OPTIMIZATION_FILES:
        path = root / name
        if not path.is_file():
            raise ValueError(f"FidelityGPT source file is missing: {path}")
        digest.update(name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _resolve_root(value: Any) -> Path:
    path = Path(str(value)).expanduser()
    candidates = [path] if path.is_absolute() else [Path.cwd() / path, Path(__file__).parent / path]
    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "FidelityGPT.py").is_file():
            return resolved
    raise ValueError(f"FidelityGPT root does not contain FidelityGPT.py: {value}")


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class _RuntimePromptTemplate:
    """Small runtime compatibility object for loading upstream prompt text only."""

    def __init__(self, template: str):
        self.template = template

    @classmethod
    def from_template(cls, template: str):
        return cls(template)

    def format(self, **values: Any) -> str:
        return self.template.format(**values)


class _RuntimeMessage:
    def __init__(self, content: str):
        self.content = content


def _load_prompt_module(root: Path):
    """Load official prompt factories without requiring the LangChain runtime."""

    modules = {
        "langchain": types.ModuleType("langchain"),
        "langchain.prompts": types.ModuleType("langchain.prompts"),
        "langchain.schema": types.ModuleType("langchain.schema"),
    }
    modules["langchain.prompts"].PromptTemplate = _RuntimePromptTemplate
    for name in ("SystemMessage", "HumanMessage", "AIMessage"):
        setattr(modules["langchain.schema"], name, _RuntimeMessage)
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        module_name = f"_fidelitygpt_prompts_{_sha256_file(root / 'prompt_templates.py')[:12]}"
        spec = importlib.util.spec_from_file_location(module_name, root / "prompt_templates.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("Could not load FidelityGPT prompt_templates.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def _load_pattern_module(root: Path):
    module_name = f"_fidelitygpt_pattern_{_sha256_file(root / 'pattern_matcher.py')[:12]}"
    spec = importlib.util.spec_from_file_location(module_name, root / "pattern_matcher.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load FidelityGPT pattern_matcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_variable_module(root: Path):
    """Load upstream dependency-analysis functions without config/API import side effects."""

    try:
        import networkx as nx
    except ImportError as error:
        raise RuntimeError(
            "Long FidelityGPT functions require networkx; install: pip install -e '.[fidelitygpt]'"
        ) from error
    wanted = {
        "generate_cfg",
        "compute_post_dominators",
        "generate_control_dependence_subgraph",
        "generate_data_dependence_subgraph",
        "extract_variables",
        "extract_variable_definitions",
        "generate_pdg",
        "find_variable_dependencies",
        "create_variable_template",
        "format_prompt",
    }
    source_path = root / "variabledependency.py"
    parsed = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    selected = [
        node
        for node in parsed.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted
    ]
    namespace: dict[str, Any] = {
        "nx": nx,
        "re": re,
        "PromptTemplate": _RuntimePromptTemplate,
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source_path), "exec"), namespace)
    return types.SimpleNamespace(**{name: namespace[name] for name in wanted})


class _CompatibleEndpoint:
    """One independently configurable OpenAI-compatible chat or embedding endpoint."""

    def __init__(self, config: dict[str, Any], *, role: str):
        self.config = dict(config)
        self.role = role
        self.model = str(config.get("model", "")).strip()
        if not self.model:
            raise ValueError(f"FidelityGPT {role}.model is required")
        self.base_url = config.get("base_url")
        self.api_key_env = str(config.get("api_key_env", "OPENAI_API_KEY"))
        self.timeout = float(config.get("timeout", 300))
        self.max_retries = max(0, int(config.get("max_retries", 3)))
        self.temperature = config.get("temperature")
        self.max_tokens = int(config.get("max_tokens", 8000))
        self.extra_body = dict(config.get("extra_body", {}))
        self.default_headers = dict(config.get("default_headers", {}))
        self._client: Any = None

    def _api_key(self) -> str:
        configured = self.config.get("api_key")
        if configured:
            value = str(configured)
            match = re.fullmatch(r"(?:env:|\$\{)([^}]+)\}?", value)
            if match:
                variable = match.group(1)
                key = os.environ.get(variable)
                if not key:
                    raise RuntimeError(f"FidelityGPT {self.role} API variable {variable!r} is unset")
                return key
            return value
        key = os.environ.get(self.api_key_env)
        if not key:
            raise RuntimeError(
                f"FidelityGPT {self.role} API variable {self.api_key_env!r} is unset"
            )
        return key

    def prepare(self) -> None:
        if self._client is not None:
            return
        try:
            from openai import OpenAI
        except ImportError as error:
            raise RuntimeError("Install the API dependency with: pip install -e '.[api]'") from error
        options: dict[str, Any] = {
            "api_key": self._api_key(),
            "timeout": self.timeout,
            "max_retries": self.max_retries,
        }
        if self.base_url:
            options["base_url"] = str(self.base_url)
        if self.default_headers:
            options["default_headers"] = self.default_headers
        self._client = OpenAI(**options)

    @staticmethod
    def _usage(response: Any) -> Any:
        usage = getattr(response, "usage", None)
        if usage is None or isinstance(usage, (dict, list, str, int, float, bool)):
            return usage
        if hasattr(usage, "model_dump"):
            return usage.model_dump()
        return str(usage)

    def chat(self, prompt: str) -> tuple[str, dict[str, Any]]:
        self.prepare()
        parameters: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.max_tokens,
        }
        if self.temperature is not None:
            parameters["temperature"] = self.temperature
        if self.extra_body:
            parameters["extra_body"] = self.extra_body
        response = self._client.chat.completions.create(**parameters)
        choices = getattr(response, "choices", []) or []
        if not choices:
            raise RuntimeError(f"FidelityGPT {self.role} endpoint returned no choices")
        content = getattr(choices[0].message, "content", "") or ""
        if isinstance(content, list):
            content = "".join(
                str(part.get("text", "") if isinstance(part, dict) else getattr(part, "text", ""))
                for part in content
            )
        if not str(content).strip():
            raise RuntimeError(f"FidelityGPT {self.role} endpoint returned empty text")
        return str(content), {
            "request_id": getattr(response, "id", None),
            "finish_reason": getattr(choices[0], "finish_reason", None),
            "usage": self._usage(response),
        }

    def embed(self, texts: list[str]) -> tuple[list[list[float]], dict[str, Any]]:
        self.prepare()
        if not texts:
            return [], {"requests": 0}
        response = self._client.embeddings.create(model=self.model, input=texts)
        ordered = sorted(response.data, key=lambda item: int(getattr(item, "index", 0)))
        vectors = [[float(value) for value in item.embedding] for item in ordered]
        if len(vectors) != len(texts):
            raise RuntimeError(
                f"FidelityGPT embedding endpoint returned {len(vectors)} vectors for {len(texts)} texts"
            )
        return vectors, {
            "request_id": getattr(response, "id", None),
            "usage": self._usage(response),
        }

    def close(self) -> None:
        if self._client is not None:
            close = getattr(self._client, "close", None)
            if close:
                close()
            self._client = None


class FidelityGPTBackend:
    """Full FidelityGPT transfer backend over dataset-provided pseudocode."""

    version = "fidelitygpt-adapter-v1"

    def __init__(self, config: dict[str, Any]):
        if "fidelitygpt_root" not in config:
            raise ValueError("plugin_config.fidelitygpt_root is required")
        self.config = dict(config)
        self.root = _resolve_root(config["fidelitygpt_root"])
        self.source_sha256 = _sha256_tree(self.root)
        self.upstream_commit = self._upstream_commit()
        expected_commit = str(config.get("expected_commit", "")).strip()
        if expected_commit and self.upstream_commit and not self.upstream_commit.startswith(
            expected_commit
        ):
            raise ValueError(
                f"FidelityGPT commit mismatch: expected {expected_commit}, got {self.upstream_commit}"
            )
        self.allowed_languages = {
            str(value).lower() for value in config.get("allowed_languages", ["c"])
        }
        self.knowledge_base = str(config.get("knowledge_base", "auto"))
        self.pattern_weight_database = str(
            config.get("pattern_weight_database", "official_default")
        ).lower()
        if self.pattern_weight_database not in {"official_default", "selected"}:
            raise ValueError("pattern_weight_database must be official_default or selected")
        self.block_size = int(config.get("block_size", 50))
        self.overlap = int(config.get("overlap", 5))
        if self.block_size < 2 or self.overlap < 0 or self.overlap >= self.block_size:
            raise ValueError("FidelityGPT requires block_size >= 2 and 0 <= overlap < block_size")
        self.overlap_conflict_policy = str(
            config.get("overlap_conflict_policy", "fail")
        ).lower()
        if self.overlap_conflict_policy not in {"fail", "union", "first"}:
            raise ValueError("overlap_conflict_policy must be fail, union, or first")
        self.distance = str(config.get("distance", "l2")).lower()
        if self.distance not in {"l2", "cosine"}:
            raise ValueError("distance must be l2 or cosine")
        self.retrieval_k = int(config.get("retrieval_k", 1))
        if self.retrieval_k != 1:
            raise ValueError("The FidelityGPT reproduction path requires retrieval_k: 1")
        self.embedding_batch_size = max(1, int(config.get("embedding_batch_size", 128)))
        cache = config.get("embedding_cache_dir")
        self.embedding_cache_dir = Path(str(cache)).expanduser().resolve() if cache else None

        chat_config = dict(config.get("chat", {}))
        embedding_config = dict(config.get("embedding", {}))
        if not chat_config or not embedding_config:
            raise ValueError("FidelityGPT requires separate chat and embedding configuration")
        variable_overrides = dict(config.get("variable_llm", {}))
        variable_config = {**chat_config, **variable_overrides}
        if "temperature" not in variable_overrides:
            variable_config["temperature"] = 0.5
        self.chat_endpoint = _CompatibleEndpoint(chat_config, role="chat")
        self.embedding_endpoint = _CompatibleEndpoint(embedding_config, role="embedding")
        self.variable_endpoint = _CompatibleEndpoint(variable_config, role="variable_llm")

        self.prompt_module = _load_prompt_module(self.root)
        self.pattern_module = _load_pattern_module(self.root)
        self._variable_module: Any = None
        self._indexes: dict[str, dict[str, Any]] = {}
        version_payload = {
            "source": self.source_sha256,
            "commit": self.upstream_commit,
            "chat": self.chat_endpoint.model,
            "embedding": self.embedding_endpoint.model,
            "variable": self.variable_endpoint.model,
            "block": self.block_size,
            "overlap": self.overlap,
            "conflict": self.overlap_conflict_policy,
            "distance": self.distance,
        }
        fingerprint = hashlib.sha256(
            json.dumps(version_payload, sort_keys=True).encode()
        ).hexdigest()[:16]
        self.version = f"{type(self).version}:{fingerprint}"

    def _upstream_commit(self) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    def _knowledge_base_path(self, request: DecompileRequest) -> Path:
        configured = self.knowledge_base
        kind = configured.lower()
        if kind == "auto":
            producer = " ".join(
                [
                    request.pseudocode.producer if request.pseudocode else "",
                    request.pseudocode.view if request.pseudocode else "",
                ]
            ).lower()
            if "ghidra" in producer:
                kind = "ghidra"
            elif "ida" in producer:
                kind = "ida"
            else:
                raise ValueError(
                    "knowledge_base: auto requires pseudocode producer/view containing ghidra or ida"
                )
        if kind == "ghidra":
            path = self.root / "fidelity_ghidra.c"
        elif kind == "ida":
            path = self.root / "fidelity_new.c"
        else:
            path = Path(str(self.config.get("knowledge_base_path", configured))).expanduser()
            if not path.is_absolute():
                path = self.root / path
        if not path.is_file():
            raise ValueError(f"FidelityGPT knowledge base is missing: {path}")
        return path.resolve()

    def _pattern_database_path(self, selected: Path) -> Path:
        return self.root / "fidelity_new.c" if self.pattern_weight_database == "official_default" else selected

    def prepare(self, requests: list[DecompileRequest]) -> None:
        self.chat_endpoint.prepare()
        self.embedding_endpoint.prepare()
        if any(
            request.pseudocode and len(request.pseudocode.text.splitlines()) > self.block_size
            for request in requests
        ):
            self.variable_endpoint.prepare()
            self._variable_module = _load_variable_module(self.root)
        # Validate knowledge-base routing here, but build embeddings lazily only if a
        # generation call is not satisfied by the framework generation cache.
        for request in requests:
            if request.pseudocode:
                self._knowledge_base_path(request)

    def _cache_path(self, knowledge_base: Path) -> Path | None:
        if self.embedding_cache_dir is None:
            return None
        payload = {
            "knowledge_base_sha256": _sha256_file(knowledge_base),
            "model": self.embedding_endpoint.model,
            "base_url": str(self.embedding_endpoint.base_url or "default"),
        }
        key = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return self.embedding_cache_dir / f"{key}.json"

    def _ensure_index(self, knowledge_base: Path) -> dict[str, Any]:
        key = str(knowledge_base)
        if key in self._indexes:
            return self._indexes[key]
        documents = [line for line in knowledge_base.read_text(encoding="utf-8").splitlines() if line.strip()]
        cache_path = self._cache_path(knowledge_base)
        vectors: list[list[float]] | None = None
        cache_hit = False
        embedding_records: list[dict[str, Any]] = []
        if cache_path and cache_path.is_file():
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if cached.get("documents") == documents:
                vectors = cached.get("vectors")
                cache_hit = isinstance(vectors, list) and len(vectors) == len(documents)
        if not cache_hit:
            vectors = []
            for start in range(0, len(documents), self.embedding_batch_size):
                batch_vectors, record = self.embedding_endpoint.embed(
                    documents[start : start + self.embedding_batch_size]
                )
                vectors.extend(batch_vectors)
                embedding_records.append(record)
            if cache_path:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                _write_json(cache_path, {"documents": documents, "vectors": vectors})
        index = {
            "path": str(knowledge_base),
            "sha256": _sha256_file(knowledge_base),
            "documents": documents,
            "vectors": vectors,
            "cache_hit": cache_hit,
            "embedding_records": embedding_records,
        }
        self._indexes[key] = index
        return index

    def _distance(self, left: list[float], right: list[float]) -> float:
        if len(left) != len(right):
            raise ValueError("Embedding dimensions differ between query and knowledge base")
        if self.distance == "l2":
            return sum((a - b) ** 2 for a, b in zip(left, right))
        dot = sum(a * b for a, b in zip(left, right))
        left_norm = sum(a * a for a in left) ** 0.5
        right_norm = sum(b * b for b in right) ** 0.5
        return 1.0 - dot / (left_norm * right_norm) if left_norm and right_norm else 1.0

    def _retrieve(
        self, selected_lines: list[str], index: dict[str, Any]
    ) -> tuple[list[str], dict[str, Any]]:
        query_vectors, embedding_record = self.embedding_endpoint.embed(selected_lines)
        retrieved: list[str] = []
        matches: list[dict[str, Any]] = []
        for line, vector in zip(selected_lines, query_vectors):
            ranked = sorted(
                (
                    (self._distance(vector, candidate), position)
                    for position, candidate in enumerate(index["vectors"])
                ),
                key=lambda item: (item[0], item[1]),
            )
            distance, position = ranked[0]
            document = index["documents"][position]
            retrieved.append(document)
            matches.append(
                {"query": line, "document_index": position, "distance": distance, "document": document}
            )
        unique = list(dict.fromkeys(retrieved))
        return unique, {"embedding": embedding_record, "matches": matches}

    def _variable_context(self, code: str) -> tuple[str, str | None, dict[str, Any] | None]:
        if self._variable_module is None:
            self._variable_module = _load_variable_module(self.root)
        module = self._variable_module
        pdg, lines = module.generate_pdg(code)
        dependencies: list[str] = []
        for variable in sorted(set(module.extract_variable_definitions(code))):
            found = module.find_variable_dependencies(pdg, variable, lines)
            if found:
                dependencies.append(
                    f"\nDependencies for variable '{variable}':\n" + "\n".join(found)
                )
        if not dependencies:
            return "", None, None
        prompt = module.format_prompt(dependencies)
        response, record = self.variable_endpoint.chat(prompt)
        return response, prompt, record

    def _chunks(self, lines: list[str]) -> list[tuple[int, int, list[str]]]:
        chunks = []
        start = 0
        step = self.block_size - self.overlap
        while start < len(lines):
            end = min(start + self.block_size, len(lines))
            chunks.append((start, end, lines[start:end]))
            if end == len(lines):
                break
            start += step
        return chunks

    @staticmethod
    def _format_documents(documents: list[str]) -> str:
        return "\n\n".join(documents)

    def _detect_block(
        self,
        block: list[str],
        variable_context: str,
        use_variable_prompt: bool,
        knowledge_base: Path,
        index: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any]]:
        pattern_output = io.StringIO()
        with contextlib.redirect_stdout(pattern_output):
            selected = self.pattern_module.match_patterns(
                block, str(self._pattern_database_path(knowledge_base))
            )
        documents, retrieval_record = self._retrieve(selected, index)
        values = {
            "context": self._format_documents(documents),
            "question": "\n".join(block),
        }
        if use_variable_prompt:
            values["Variable_names"] = variable_context
            template = self.prompt_module.create_RAG_promptwithvariable_template()
        else:
            template = self.prompt_module.create_RAG_prompt_template()
        prompt = template.format(**values)
        response, chat_record = self.chat_endpoint.chat(prompt)
        return response, prompt, {
            "selected_lines": selected,
            "pattern_stdout": pattern_output.getvalue(),
            "retrieved_documents": documents,
            "retrieval": retrieval_record,
            "chat": chat_record,
        }

    @staticmethod
    def _normalized_line(line: str) -> str:
        return re.sub(r"\s+", "", line).strip()

    @staticmethod
    def _split_detection_label(line: str) -> tuple[str, tuple[str, ...]]:
        if "//" not in line:
            return line.rstrip(), ()
        code, comment = line.split("//", 1)
        labels = {f"I{value}" for value in _DISTORTION_LABEL_RE.findall(comment)}
        labels.update(f"I{value}" for value in _DISTORTION_NUMBER_RE.findall(comment))
        if not labels:
            return line.rstrip(), ()
        return code.rstrip(), tuple(sorted(labels))

    def _align_detection(
        self, block: list[str], response: str
    ) -> list[tuple[int, tuple[str, ...]]]:
        extracted, _ = extract_candidate_code(response)
        output_records: list[tuple[str, tuple[str, ...]]] = []
        for raw_line in extracted.splitlines():
            line = re.sub(r"^\s*(?:Output|Helpful Answer)\s*:\s*", "", raw_line)
            code, labels = self._split_detection_label(line)
            if self._normalized_line(code):
                output_records.append((code, labels))
        source_records = [
            (index, line) for index, line in enumerate(block) if self._normalized_line(line)
        ]
        if not source_records:
            return []
        needed = len(source_records)
        for start in range(0, len(output_records) - needed + 1):
            window = output_records[start : start + needed]
            if all(
                self._normalized_line(source_line) == self._normalized_line(output_line)
                for (_, source_line), (output_line, _) in zip(source_records, window)
            ):
                return [
                    (source_index, labels)
                    for (source_index, _), (_, labels) in zip(source_records, window)
                ]
        raise ValueError(
            f"FidelityGPT detection output cannot align to its {needed}-line input block"
        )

    def _merge_detections(
        self, lines: list[str], chunks: list[tuple[int, int, list[str]]], responses: list[str]
    ) -> tuple[str, list[dict[str, Any]]]:
        labels_by_line: dict[int, tuple[str, ...]] = {}
        conflicts: list[dict[str, Any]] = []
        for (start, _, block), response in zip(chunks, responses):
            for local_index, labels in self._align_detection(block, response):
                if not labels:
                    continue
                global_index = start + local_index
                previous = labels_by_line.get(global_index)
                if previous is None or previous == labels:
                    labels_by_line[global_index] = labels
                    continue
                conflict = {
                    "line": global_index + 1,
                    "first": list(previous),
                    "later": list(labels),
                }
                conflicts.append(conflict)
                if self.overlap_conflict_policy == "fail":
                    raise ValueError(
                        f"FidelityGPT overlap label conflict at source line {global_index + 1}: "
                        f"{previous} versus {labels}"
                    )
                if self.overlap_conflict_policy == "union":
                    labels_by_line[global_index] = tuple(sorted(set(previous) | set(labels)))
        merged = []
        for index, line in enumerate(lines):
            labels = labels_by_line.get(index, ())
            merged.append(f"{line.rstrip()} // {' '.join(labels)}" if labels else line)
        return "\n".join(merged), conflicts

    @staticmethod
    def _candidate(response: str) -> tuple[str, str]:
        code, policy = extract_candidate_code(response)
        code = re.sub(r"^\s*(?:Output|Helpful Answer)\s*:\s*", "", code, count=1)
        return code.strip(), policy

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        metadata: dict[str, Any] = {
            "implementation": "fidelitygpt_full_adapter",
            "upstream_commit": self.upstream_commit,
            "upstream_source_sha256": self.source_sha256,
            "chat_model": self.chat_endpoint.model,
            "embedding_model": self.embedding_endpoint.model,
            "variable_model": self.variable_endpoint.model,
            "block_size": self.block_size,
            "overlap": self.overlap,
            "overlap_conflict_policy": self.overlap_conflict_policy,
            "pattern_weight_database": self.pattern_weight_database,
            "distance": self.distance,
            "retrieval_k": self.retrieval_k,
            "oracle_assisted": False,
            "chat_base_url": str(self.chat_endpoint.base_url or "provider_default"),
            "embedding_base_url": str(
                self.embedding_endpoint.base_url or "provider_default"
            ),
            "variable_base_url": str(self.variable_endpoint.base_url or "provider_default"),
            "chat_temperature": self.chat_endpoint.temperature,
            "variable_temperature": self.variable_endpoint.temperature,
        }
        if request.oracle_context is not None:
            return DecompileResult(
                success=False,
                reason="fidelitygpt_unexpected_oracle_context",
                log="FidelityGPT must not receive benchmark oracle data",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        if request.language.lower() not in self.allowed_languages:
            return DecompileResult(
                success=False,
                reason="fidelitygpt_unsupported_language",
                log=f"FidelityGPT supports {sorted(self.allowed_languages)}, got {request.language}",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        if request.pseudocode is None or not request.pseudocode.text.strip():
            return DecompileResult(
                success=False,
                reason="fidelitygpt_missing_pseudocode",
                log="required_inputs must include pseudocode",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        try:
            code = request.pseudocode.text.strip()
            lines = code.splitlines()
            (artifact_dir / "fidelitygpt_input.c").write_text(code + "\n", encoding="utf-8")
            knowledge_base = self._knowledge_base_path(request)
            index = self._ensure_index(knowledge_base)
            chunks = self._chunks(lines)
            long_function = len(lines) > self.block_size
            variable_context = ""
            variable_prompt = None
            variable_record = None
            if long_function:
                try:
                    variable_context, variable_prompt, variable_record = self._variable_context(
                        code
                    )
                    if variable_prompt:
                        (artifact_dir / "variable_prompt.txt").write_text(
                            variable_prompt, encoding="utf-8"
                        )
                        (artifact_dir / "variable_response.txt").write_text(
                            variable_context, encoding="utf-8"
                        )
                except Exception as variable_error:
                    # FidelityGPT.py catches every variable-dependency failure and
                    # continues chunk detection with an empty Variable_names value.
                    variable_context = ""
                    variable_record = {
                        "failed_open": True,
                        "error_type": type(variable_error).__name__,
                        "error": repr(variable_error),
                    }
                    (artifact_dir / "variable_error.txt").write_text(
                        repr(variable_error), encoding="utf-8"
                    )

            detection_responses: list[str] = []
            chunk_records: list[dict[str, Any]] = []
            for chunk_index, (start, end, block) in enumerate(chunks):
                response, prompt, record = self._detect_block(
                    block, variable_context, long_function, knowledge_base, index
                )
                detection_responses.append(response)
                (artifact_dir / f"detection_{chunk_index:02d}_input.c").write_text(
                    "\n".join(block) + "\n", encoding="utf-8"
                )
                (artifact_dir / f"detection_{chunk_index:02d}_prompt.txt").write_text(
                    prompt, encoding="utf-8"
                )
                (artifact_dir / f"detection_{chunk_index:02d}_response.txt").write_text(
                    response, encoding="utf-8"
                )
                record.update({"chunk": chunk_index, "start_line": start + 1, "end_line": end})
                chunk_records.append(record)

            if long_function:
                detection, conflicts = self._merge_detections(
                    lines, chunks, detection_responses
                )
                merge_policy = "source_line_aligned_overlap_merge"
            else:
                detection = detection_responses[0]
                conflicts = []
                merge_policy = "not_required"
            (artifact_dir / "fidelitygpt_detection_merged.c").write_text(
                detection + "\n", encoding="utf-8"
            )
            correction_template = self.prompt_module.create_RAG_correction_template()
            correction_prompt = correction_template.format(context="", question=detection)
            correction_response, correction_record = self.chat_endpoint.chat(correction_prompt)
            (artifact_dir / "correction_prompt.txt").write_text(
                correction_prompt, encoding="utf-8"
            )
            (artifact_dir / "correction_response.txt").write_text(
                correction_response, encoding="utf-8"
            )
            candidate, extraction_policy = self._candidate(correction_response)
            (artifact_dir / "fidelitygpt_final.c").write_text(
                candidate + ("\n" if candidate else ""), encoding="utf-8"
            )
            metadata.update(
                {
                    "pseudocode_producer": request.pseudocode.producer,
                    "pseudocode_view": request.pseudocode.view,
                    "line_count": len(lines),
                    "long_function": long_function,
                    "chunk_count": len(chunks),
                    "chunk_merge_policy": merge_policy,
                    "chunk_overlap_conflicts": conflicts,
                    "knowledge_base": str(knowledge_base),
                    "knowledge_base_sha256": index["sha256"],
                    "knowledge_base_documents": len(index["documents"]),
                    "knowledge_base_embedding_cache_hit": index["cache_hit"],
                    "knowledge_base_embedding_records": index["embedding_records"],
                    "variable_llm": variable_record,
                    "chunks": chunk_records,
                    "correction": correction_record,
                    "candidate_extraction_policy": extraction_policy,
                }
            )
            _write_json(artifact_dir / "fidelitygpt_metadata.json", metadata)
            if not candidate:
                return DecompileResult(
                    success=False,
                    reason="fidelitygpt_empty_correction",
                    log="FidelityGPT correction returned no candidate code",
                    elapsed_seconds=time.perf_counter() - started,
                    backend_version=self.version,
                )
            return DecompileResult(
                success=True,
                raw_output=correction_response,
                code=candidate,
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        except Exception as error:
            metadata.update({"error_type": type(error).__name__, "error": repr(error)})
            _write_json(artifact_dir / "fidelitygpt_metadata.json", metadata)
            return DecompileResult(
                success=False,
                reason="fidelitygpt_failed",
                log=repr(error),
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

    def close(self) -> None:
        self.chat_endpoint.close()
        self.embedding_endpoint.close()
        self.variable_endpoint.close()
