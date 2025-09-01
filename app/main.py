import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import FastAPI, Depends, Header, HTTPException, status, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import text, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db import init_engine, get_engine, get_sessionmaker
from models import Base, Job, JobStatus
from schemas import (
    JobCreate, JobOut, JobDetail, JobUpdateRunning, JobUpdateSucceeded, JobUpdateFailed
)

API_KEY = os.getenv("API_KEY", "dev123")
LOCK_TTL_SECONDS = int(os.getenv("LOCK_TTL_SECONDS", "120"))
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://jobs:jobs@localhost:5432/jobs")

app = FastAPI(title="NB Queue API", version="1.0.0")


# ---------- Security ----------
async def require_api_key(x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return True

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------- Lifespan ----------
@app.on_event("startup")
async def on_startup():
    init_engine(DATABASE_URL)
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ---------- Health ----------
@app.get("/health")
async def health():
    return {"ok": True}


# ---------- Helpers ----------
def job_to_detail(j: Job) -> JobDetail:
    return JobDetail(
        id=j.id, prompt=j.prompt, url=j.url, options=j.options, status=j.status,
        result=j.result, error=j.error, created_at=j.created_at, updated_at=j.updated_at,
        claimed_by=j.claimed_by, claimed_at=j.claimed_at, lock_until=j.lock_until, attempts=j.attempts
    )


# ---------- Endpoints ----------

@app.post("/api/jobs", response_model=JobOut, status_code=201, dependencies=[Depends(require_api_key)])
async def create_job(payload: JobCreate):
    Session = get_sessionmaker()
    async with Session() as s:
        j = Job(prompt=payload.prompt, url=payload.url, options=payload.options, status=JobStatus.PENDING)
        s.add(j)
        await s.commit()
        await s.refresh(j)
        return JobOut(id=j.id, status=j.status)


@app.post("/api/jobs/claim", dependencies=[Depends(require_api_key)])
async def claim_job(x_agent_id: Annotated[str | None, Header(alias="X-Agent-Id")] = None):
    if not x_agent_id:
        raise HTTPException(400, "X-Agent-Id is required")
    now = utcnow()
    lock_until = now + timedelta(seconds=LOCK_TTL_SECONDS)

    Session = get_sessionmaker()
    async with Session() as s:
        async with s.begin():
            stmt = text("""
                WITH candidate AS (
                    SELECT id
                    FROM jobs
                    WHERE status = 'PENDING'
                       OR (lock_until IS NOT NULL AND lock_until < :now AND status IN ('CLAIMED','RUNNING'))
                    ORDER BY created_at ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE jobs j
                SET status = 'CLAIMED',
                    claimed_by = :agent_id,
                    claimed_at = :now,
                    lock_until = :lock_until,
                    attempts = j.attempts + 1,
                    updated_at = :now
                FROM candidate c
                WHERE j.id = c.id
                RETURNING j.id, j.prompt, j.url, j.options, j.status, j.result, j.error,
                          j.created_at, j.updated_at, j.claimed_by, j.claimed_at, j.lock_until, j.attempts
            """).bindparams(now=now, lock_until=lock_until, agent_id=x_agent_id)
            result = await s.execute(stmt)
            row = result.mappings().first()

        if not row:
            # 204 ДОЛЖЕН быть БЕЗ ТЕЛА, иначе uvicorn ругается
            return Response(status_code=204)

        return {
            "id": row["id"],
            "prompt": row["prompt"],
            "url": row["url"],
            "options": row["options"],
            "status": row["status"],
            "result": row["result"],
            "error": row["error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "claimed_by": row["claimed_by"],
            "claimed_at": row["claimed_at"],
            "lock_until": row["lock_until"],
            "attempts": row["attempts"],
        }


class UpdatePayload(BaseModel):
    status: str
    result: dict | None = None
    error: str | None = None


@app.post("/api/jobs/{job_id}/update", dependencies=[Depends(require_api_key)])
async def update_job(job_id: uuid.UUID,
                     payload: UpdatePayload,
                     x_agent_id: Annotated[str | None, Header(alias="X-Agent-Id")] = None):
    if not x_agent_id:
        raise HTTPException(400, "X-Agent-Id is required")

    Session = get_sessionmaker()
    now = utcnow()
    async with Session() as s:
        # Читаем
        j = await s.get(Job, job_id)
        if not j:
            raise HTTPException(404, "Job not found")

        # Агент должен совпасть
        if j.claimed_by != x_agent_id:
            raise HTTPException(409, "Job is claimed by another agent")

        # Финальные статусы не трогаем
        if j.status in (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED):
            return job_to_detail(j)

        # Обновляем
        new_status = payload.status.upper()
        match new_status:
            case "RUNNING":
                if j.status not in (JobStatus.CLAIMED, JobStatus.RUNNING):
                    raise HTTPException(409, f"Invalid transition {j.status} -> RUNNING")
                j.status = JobStatus.RUNNING
                j.lock_until = now + timedelta(seconds=int(os.getenv("LOCK_TTL_SECONDS", "120")))
            case "SUCCEEDED":
                j.status = JobStatus.SUCCEEDED
                j.result = payload.result or {}
                j.lock_until = None
            case "FAILED":
                j.status = JobStatus.FAILED
                j.error = payload.error or "unknown error"
                j.lock_until = None
            case _:
                raise HTTPException(400, "Unsupported status")

        j.updated_at = now
        await s.commit()
        await s.refresh(j)
        return job_to_detail(j)


@app.get("/api/jobs/{job_id}", response_model=JobDetail)
async def get_job(job_id: uuid.UUID):
    Session = get_sessionmaker()
    async with Session() as s:
        j = await s.get(Job, job_id)
        if not j:
            raise HTTPException(404, "Job not found")
        return job_to_detail(j)


@app.get("/api/jobs", response_model=list[JobDetail])
async def list_jobs(status: str | None = Query(None, pattern="^(PENDING|CLAIMED|RUNNING|SUCCEEDED|FAILED|CANCELLED)$")):
    Session = get_sessionmaker()
    async with Session() as s:
        q = select(Job)
        if status:
            q = q.where(Job.status == JobStatus(status))
        q = q.order_by(Job.created_at.asc())
        res = (await s.execute(q)).scalars().all()
        return [job_to_detail(j) for j in res]
