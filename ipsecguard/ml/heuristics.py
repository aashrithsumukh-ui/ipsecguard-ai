from __future__ import annotations

from ipsecguard.models import Finding


def infer_mode(feature_row: dict) -> Finding:
    overhead = float(feature_row.get("size_mean", 0.0))
    consistency = float(feature_row.get("overhead_consistency", 0.0))
    tunnel_score = min(max((overhead - 170.0) / 80.0, 0.0), 1.0)
    confidence = min(0.55 + 0.35 * max(tunnel_score, consistency), 0.95)
    mode = "tunnel" if tunnel_score >= 0.45 else "transport"
    return Finding(
        title="ESP mode inferred",
        severity="medium",
        category="metadata_exposure",
        derivation="inferred",
        description="Tunnel-vs-transport mode inferred from consistent ESP packet overhead.",
        source_field="esp.packet_overhead",
        raw_value=mode,
        confidence=confidence,
        citation="Heuristic inference from ESP metadata",
        likelihood="medium",
        impact="medium",
        metadata={"heuristic": "overhead_consistency"},
    )


def infer_cipher_family(feature_row: dict) -> Finding:
    mod4 = float(feature_row.get("size_mod_4_ratio", 0.0))
    mod8 = float(feature_row.get("size_mod_8_ratio", 0.0))
    mod16 = float(feature_row.get("size_mod_16_ratio", 0.0))
    if mod8 > 0.95 and mod16 < 0.7:
        family = "3des-family"
        confidence = min(0.55 + 0.35 * mod8, 0.93)
    elif mod16 > 0.92:
        family = "aes-cbc-family"
        confidence = min(0.60 + 0.30 * mod16, 0.95)
    else:
        family = "aes-gcm-family"
        confidence = min(0.55 + 0.30 * max(mod4, 1 - mod16), 0.90)
    return Finding(
        title="ESP cipher family inferred",
        severity="medium",
        category="crypto_strength",
        derivation="inferred",
        description=(
            "ESP cipher family inferred from payload-length alignment and IV/padding patterns."
        ),
        source_field="esp.length_alignment",
        raw_value=family,
        confidence=confidence,
        citation="Heuristic inference from ESP metadata",
        likelihood="medium",
        impact="medium",
        metadata={"heuristic": "length_alignment"},
    )


def anomaly_to_finding(anomaly_score: float) -> Finding:
    severity = "high" if anomaly_score >= 0.75 else "medium" if anomaly_score >= 0.45 else "low"
    likelihood = "high" if anomaly_score >= 0.75 else "medium"
    return Finding(
        title="Traffic anomaly inferred",
        severity=severity,
        category="metadata_exposure",
        derivation="inferred",
        description="Isolation Forest anomaly score derived from encrypted ESP flow metadata.",
        source_field="esp.anomaly_score",
        raw_value=round(anomaly_score, 3),
        confidence=min(0.55 + anomaly_score * 0.35, 0.95),
        citation="Isolation Forest on ESP metadata",
        likelihood=likelihood,
        impact="medium",
    )
