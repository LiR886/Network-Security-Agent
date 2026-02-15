from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, DateTime, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    status: Mapped[str] = mapped_column(String(32), default="open")
    risk_level: Mapped[str] = mapped_column(String(16))
    max_score: Mapped[int] = mapped_column(Integer, default=0)  # stored as score*1000
    summary: Mapped[str] = mapped_column(Text, default="")
    report: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    kind: Mapped[str] = mapped_column(String(32), default="packet_batch")
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)


class ActionRecord(Base):
    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    incident_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)


class Feedback(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    label: Mapped[int] = mapped_column(Integer)  # 0 normal, 1 anomaly, 2 confirmed threat
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)


@dataclass
class Storage:
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]

    @classmethod
    def from_url(cls, url: str) -> "Storage":
        engine = create_async_engine(url, pool_pre_ping=True)
        sm = async_sessionmaker(engine, expire_on_commit=False)
        return cls(engine=engine, sessionmaker=sm)

    async def init(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def add_event(self, kind: str, payload: Dict[str, Any]) -> int:
        async with self.sessionmaker() as s:
            e = Event(kind=kind, payload=payload)
            s.add(e)
            await s.commit()
            await s.refresh(e)
            return int(e.id)

    async def create_incident(
        self,
        risk_level: str,
        max_score: float,
        summary: str,
        report: Dict[str, Any],
    ) -> int:
        async with self.sessionmaker() as s:
            inc = Incident(
                risk_level=risk_level,
                max_score=int(round(max_score * 1000)),
                summary=summary,
                report=report,
            )
            s.add(inc)
            await s.commit()
            await s.refresh(inc)
            return int(inc.id)

    async def add_actions(self, incident_id: Optional[int], actions: List[Dict[str, Any]]) -> None:
        async with self.sessionmaker() as s:
            for a in actions:
                s.add(ActionRecord(incident_id=incident_id, action=a))
            await s.commit()

    async def list_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        async with self.sessionmaker() as s:
            rows = (await s.execute(select(Incident).order_by(Incident.id.desc()).limit(limit))).scalars().all()
            out: List[Dict[str, Any]] = []
            for r in rows:
                out.append(
                    {
                        "id": r.id,
                        "created_at": r.created_at.isoformat(),
                        "status": r.status,
                        "risk_level": r.risk_level,
                        "max_score": r.max_score / 1000.0,
                        "summary": r.summary,
                        "report": r.report,
                    }
                )
            return out

    async def get_incident(self, incident_id: int) -> Optional[Dict[str, Any]]:
        async with self.sessionmaker() as s:
            inc = await s.get(Incident, incident_id)
            if not inc:
                return None
            acts = (
                await s.execute(select(ActionRecord).where(ActionRecord.incident_id == incident_id).order_by(ActionRecord.id))
            ).scalars().all()
            actions = [a.action for a in acts]
            return {
                "id": inc.id,
                "created_at": inc.created_at.isoformat(),
                "status": inc.status,
                "risk_level": inc.risk_level,
                "max_score": inc.max_score / 1000.0,
                "summary": inc.summary,
                "report": inc.report,
                "actions": actions,
            }

    async def add_feedback(self, label: int, payload: Dict[str, Any]) -> int:
        async with self.sessionmaker() as s:
            fb = Feedback(label=int(label), payload=payload)
            s.add(fb)
            await s.commit()
            await s.refresh(fb)
            return int(fb.id)


