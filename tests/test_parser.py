from pathlib import Path

from ipsecguard.parser.ike import extract_findings

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_PCAP = BASE_DIR / "samples" / "cfg0_icmp_transport_3des-family_3des_dh2_pfsoff.pcap"


def test_ikev2_parser_emits_observed_fields():
    findings, summary = extract_findings(SAMPLE_PCAP)
    observed = {
        (finding.source_field, finding.raw_value)
        for finding in findings
        if finding.derivation == "observed"
    }
    assert ("ike_version", "2.0") in observed
    assert any(field == "ike_enc" for field, _ in observed)
    assert any(field == "ike_integ" for field, _ in observed)
    assert any(field == "dh_group" for field, _ in observed)
    assert summary["has_esp"] is True


def test_parser_never_labels_esp_cipher_or_mode_as_observed():
    findings, _ = extract_findings(SAMPLE_PCAP)
    observed_fields = {
        finding.source_field for finding in findings if finding.derivation == "observed"
    }
    assert "esp_cipher" not in observed_fields
    assert "mode" not in observed_fields
    assert "auth_method" not in observed_fields
