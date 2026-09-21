from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import DateTime, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from ipsecguard.utils import DATA_DIR

DATABASE_URL = f"sqlite:///{DATA_DIR / 'results.db'}"
engine = create_engine(DATABASE_URL, future=True)


class Base(DeclarativeBase):
    pass


class AnalysisRecord(Base):
    __tablename__ = "analysis_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    path: Mapped[str] = mapped_column(Text())
    payload_json: Mapped[str] = mapped_column(Text())
    created_at: Mapped[datetime] = mapped_column(
        DateTime(), default=lambda: datetime.now(UTC).replace(tzinfo=None)
    )


class AnalysisRepository:
    def __init__(self) -> None:
        Base.metadata.create_all(engine)

    def save_report(self, report_id: str, kind: str, path: str, payload: dict) -> None:
        with Session(engine) as session:
            session.add(
                AnalysisRecord(id=report_id, kind=kind, path=path, payload_json=json.dumps(payload))
            )
            session.commit()

    def get_report(self, report_id: str, kind: str) -> AnalysisRecord | None:
        with Session(engine) as session:
            return session.scalar(
                select(AnalysisRecord).where(
                    AnalysisRecord.id == report_id,
                    AnalysisRecord.kind == kind,
                )
            )
