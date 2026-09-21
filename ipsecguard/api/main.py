from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse

from ipsecguard.db.repository import AnalysisRepository
from ipsecguard.pipeline import analyze_capture
from ipsecguard.utils import REPORTS_DIR

app = FastAPI(title="IPsecGuard AI")
repository = AnalysisRepository()
BASE_DIR = Path(__file__).resolve().parent.parent.parent
INDEX_PATH = BASE_DIR / "frontend" / "index.html"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_PATH.read_text(encoding="utf-8")


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> dict:
    if not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Please upload a .pcap file")
    with NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
        handle.write(await file.read())
        temp_path = Path(handle.name)
    result = analyze_capture(temp_path)
    executive_html = REPORTS_DIR / f"{result.reports.executive_report_id}-executive.html"
    technical_html = REPORTS_DIR / f"{result.reports.technical_report_id}-technical.html"
    repository.save_report(result.reports.executive_report_id, "executive", str(executive_html), result.to_dict())
    repository.save_report(result.reports.technical_report_id, "technical", str(technical_html), result.to_dict())
    return result.to_dict()


@app.get("/reports/{report_id}/{kind}")
def get_report(report_id: str, kind: str) -> FileResponse:
    record = repository.get_report(report_id, kind)
    if record is None:
        raise HTTPException(status_code=404, detail="Report not found")
    path = Path(record.path)
    pdf_path = path.with_suffix(".pdf")
    target = pdf_path if pdf_path.exists() else path
    media_type = "application/pdf" if target.suffix == ".pdf" else "text/html"
    return FileResponse(target, media_type=media_type, filename=target.name)
