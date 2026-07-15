from __future__ import annotations

from typing import Any

from ..models import EvaluationEvidence, ProtocolDescriptor


class BaseEvaluationProtocol:
    descriptor = ProtocolDescriptor(
        protocol_id="base",
        version="1",
        description="Base evaluation protocol",
        capabilities=(),
        compile_unit="unknown",
        test_granularity="unknown",
        comparator="unknown",
    )

    def __init__(self, config: dict[str, Any], *, adapter: Any, base_dir: Any):
        self.config = config
        self.adapter = adapter
        self.base_dir = base_dir

    def evidence(self, **values: Any) -> EvaluationEvidence:
        return EvaluationEvidence(
            protocol_id=self.descriptor.protocol_id,
            protocol_version=self.descriptor.version,
            capabilities=self.descriptor.capabilities,
            **values,
        )

    def failure_evidence(self, reason: str, **details: Any) -> EvaluationEvidence:
        return self.evidence(reason=reason, details=details)
