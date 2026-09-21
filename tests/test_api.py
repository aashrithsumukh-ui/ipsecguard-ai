from pathlib import Path

from fastapi.testclient import TestClient

from ipsecguard.api.main import app

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_PCAP = BASE_DIR / "samples" / "cfg0_icmp_transport_3des-family_3des_dh2_pfsoff.pcap"


def test_analyze_smoke():
    client = TestClient(app)
    with SAMPLE_PCAP.open("rb") as handle:
        response = client.post("/analyze", files={"file": (SAMPLE_PCAP.name, handle, "application/vnd.tcpdump.pcap")})
    assert response.status_code == 200
    body = response.json()
    assert "score" in body
    assert "report_ids" in body
    assert any(finding["derivation"] == "observed" for finding in body["findings"])
    assert any(finding["derivation"] == "inferred" for finding in body["findings"])
