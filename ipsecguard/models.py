from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    category: str
    derivation: str
    description: str
    source_field: str | None = None
    raw_value: Any | None = None
    confidence: float | None = None
    citation: str | None = None
    likelihood: str = "medium"
    impact: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if self.confidence is not None:
            payload["confidence_pct"] = round(self.confidence * 100, 1)
        return payload


@dataclass(slots=True)
class AnalysisArtifacts:
    executive_report_id: str
    technical_report_id: str


@dataclass(slots=True)
class AnalysisResult:
    score: int
    subscores: dict[str, int]
    findings: list[Finding]
    threat_matrix: dict[str, list[dict[str, Any]]]
    reports: AnalysisArtifacts
    session_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "subscores": self.subscores,
            "findings": [finding.to_dict() for finding in self.findings],
            "threat_matrix": self.threat_matrix,
            "report_ids": {
                "executive": self.reports.executive_report_id,
                "technical": self.reports.technical_report_id,
            },
            "session_summary": self.session_summary,
        }
