import asyncio
from io import BytesIO
from pathlib import Path

import pytest
from fastapi import HTTPException, UploadFile
from fastapi.testclient import TestClient

from ipsecguard.api.main import analyze, app

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_PCAP = BASE_DIR / "samples" / "cfg0_icmp_transport_3des-family_3des_dh2_pfsoff.pcap"


def test_analyze_smoke():
    client = TestClient(app)
    with SAMPLE_PCAP.open("rb") as handle:
        response = client.post(
            "/analyze", files={"file": (SAMPLE_PCAP.name, handle, "application/vnd.tcpdump.pcap")}
        )
    assert response.status_code == 200
    body = response.json()
    assert "score" in body
    assert "report_ids" in body
    assert any(finding["derivation"] == "observed" for finding in body["findings"])
    assert any(finding["derivation"] == "inferred" for finding in body["findings"])
    report_response = client.get(f"/reports/{body['report_ids']['executive']}/executive")
    assert report_response.status_code == 200
    assert (
        "text/html" in report_response.headers["content-type"]
        or "application/pdf" in report_response.headers["content-type"]
    )


def test_analyze_rejects_invalid_uploads():
    client = TestClient(app)
    response = client.post("/analyze", files={"file": ("bad.txt", b"not-a-pcap", "text/plain")})
    assert response.status_code == 400


def test_analyze_rejects_missing_filename():
    upload = UploadFile(file=BytesIO(b"not-a-pcap"), filename=None)
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(analyze(upload))
    assert exc_info.value.status_code == 400


def test_missing_report_returns_404():
    client = TestClient(app)
    response = client.get("/reports/missing/executive")
    assert response.status_code == 404
