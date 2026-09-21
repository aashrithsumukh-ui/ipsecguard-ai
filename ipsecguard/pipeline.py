from __future__ import annotations

from pathlib import Path

from ipsecguard.features.esp import extract_flow_features
from ipsecguard.ml.anomaly import load_or_create_model, score_anomaly
from ipsecguard.ml.explain import top_contributions
from ipsecguard.ml.heuristics import anomaly_to_finding, infer_cipher_family, infer_mode
from ipsecguard.ml.traffic_classifier import MODEL_PATH, load_model, predict_traffic
from ipsecguard.models import AnalysisResult, Finding
from ipsecguard.parser.ike import extract_findings
from ipsecguard.reports.render import render_reports
from ipsecguard.scoring.rules import score_findings


def _traffic_finding(label: str, confidence: float, shap_values: list[dict]) -> Finding:
    return Finding(
        title="Traffic class inferred",
        severity="info",
        category="traffic",
        derivation="inferred",
        description="Traffic mix inferred from encrypted ESP size and timing metadata.",
        source_field="esp.feature_vector",
        raw_value=label,
        confidence=confidence,
        citation="XGBoost on held-out config split",
        likelihood="medium",
        impact="low",
        metadata={"shap_top_features": shap_values},
    )


def analyze_capture(pcap_path: str | Path) -> AnalysisResult:
    observed_findings, parser_summary = extract_findings(pcap_path)
    features = extract_flow_features(pcap_path)
    inferred_findings: list[Finding] = []
    session_summary = {**parser_summary, "flow_count": int(len(features))}
    if not features.empty:
        primary = features.iloc[0].to_dict()
        inferred_findings.append(infer_mode(primary))
        inferred_findings.append(infer_cipher_family(primary))
        anomaly_model = load_or_create_model(features)
        anomaly_score = score_anomaly(anomaly_model, features)
        inferred_findings.append(anomaly_to_finding(anomaly_score))
        session_summary["anomaly_score"] = anomaly_score
        if MODEL_PATH.exists():
            model = load_model()
            traffic_label, confidence = predict_traffic(model, features)
            shap_values = top_contributions(model, features)
            inferred_findings.append(_traffic_finding(traffic_label, confidence, shap_values))
            session_summary["traffic_label"] = traffic_label
    findings = observed_findings + inferred_findings
    findings.sort(key=lambda finding: {"high": 0, "medium": 1, "low": 2, "info": 3}.get(finding.severity, 4))
    score, subscores, threat_matrix = score_findings(findings)
    placeholder = AnalysisResult(
        score=score,
        subscores=subscores,
        findings=findings,
        threat_matrix=threat_matrix,
        reports=None,  # type: ignore[arg-type]
        session_summary=session_summary,
    )
    artifacts = render_reports(placeholder)
    return AnalysisResult(
        score=score,
        subscores=subscores,
        findings=findings,
        threat_matrix=threat_matrix,
        reports=artifacts,
        session_summary=session_summary,
    )
