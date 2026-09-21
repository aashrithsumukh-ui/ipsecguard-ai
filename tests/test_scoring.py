from ipsecguard.models import Finding
from ipsecguard.scoring.rules import score_findings


def test_scoring_applies_expected_deductions():
    findings = [
        Finding("Observed ike enc", "high", "crypto_strength", "observed", "", raw_value="3DES"),
        Finding("Observed integ", "high", "crypto_strength", "observed", "", raw_value="HMAC-MD5-96"),
        Finding("IKEv1 aggressive mode observed", "high", "metadata_exposure", "observed", "", raw_value="aggressive-mode"),
    ]
    score, subscores, _ = score_findings(findings)
    assert score < 100
    assert subscores["crypto_strength"] <= 55
    assert subscores["metadata_exposure"] <= 70
