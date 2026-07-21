from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _elf_type(path: Path) -> int | None:
    data = path.read_bytes()[:20]
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[5] not in (1, 2):
        return None
    return int.from_bytes(data[16:18], "little" if data[5] == 1 else "big")


def build_dataset(
    source: Path,
    output: Path,
    object_root: Path,
    *,
    compiler: str,
    limit: int | None = None,
) -> dict[str, Any]:
    payload = json.loads(source.read_text(encoding="utf-8"))
    samples = list(payload.get("samples", []))
    selected_samples = samples[:limit] if limit is not None else samples
    # A limited build is a real smoke dataset, not a mixed file whose unbuilt rows
    # still point at the original PIE executables.
    payload["samples"] = selected_samples
    failures: list[dict[str, str]] = []
    built = 0
    object_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="binoracle_build_") as temp:
        temporary = Path(temp)
        for index, row in enumerate(selected_samples):
            sample_id = str(row.get("sample_id", f"sample-{index}"))
            assembly = str(
                (row.get("assembly") or {}).get("full_translation_unit_assembly", "")
            )
            if not assembly.strip():
                failures.append({"sample_id": sample_id, "reason": "missing_full_assembly"})
                row["binary"] = {}
                continue
            safe_name = sample_id.replace(":", "_").replace("/", "_").replace("\\", "_")
            assembly_path = temporary / f"{safe_name}.s"
            object_path = object_root / f"{safe_name}.o"
            assembly_path.write_text(assembly, encoding="utf-8")
            completed = subprocess.run(
                [compiler, "-c", str(assembly_path), "-o", str(object_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode != 0:
                failures.append(
                    {
                        "sample_id": sample_id,
                        "reason": "assemble_failed",
                        "stderr": completed.stderr[-2000:],
                    }
                )
                object_path.unlink(missing_ok=True)
                row["binary"] = {}
                continue
            if _elf_type(object_path) != 1:
                failures.append({"sample_id": sample_id, "reason": "output_not_et_rel"})
                object_path.unlink(missing_ok=True)
                row["binary"] = {}
                continue
            row["binary"] = {
                "path": object_path.resolve().as_posix(),
                "sha256": _sha256(object_path),
                "size_bytes": object_path.stat().st_size,
                "format": "ELF-REL",
                "architecture": "x86_64",
            }
            built += 1

    payload["binoracle_object_build"] = {
        "source": str(source.resolve()),
        "compiler": compiler,
        "built": built,
        "failed": len(failures),
        "failures": failures,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload["binoracle_object_build"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild ExeBench full assembly as BinOracle ET_REL objects."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--object-root", required=True, type=Path)
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    report = build_dataset(
        args.input,
        args.output,
        args.object_root,
        compiler=args.compiler,
        limit=args.limit,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
