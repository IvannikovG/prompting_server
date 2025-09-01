from datetime import datetime
from pydantic import BaseModel, Field
from typing import Any
from uuid import UUID
from models import JobStatus

class JobCreate(BaseModel):
    prompt: str
    url: str | None = None
    options: dict[str, Any] | None = None

class JobOut(BaseModel):
    id: UUID
    status: JobStatus

class JobDetail(BaseModel):
    id: UUID
    prompt: str
    url: str | None
    options: dict | None
    status: JobStatus
    result: dict | None
    error: str | None
    created_at: datetime
    updated_at: datetime
    claimed_by: str | None
    claimed_at: datetime | None
    lock_until: datetime | None
    attempts: int

class JobUpdateRunning(BaseModel):
    status: JobStatus = Field(pattern="RUNNING")

class JobUpdateSucceeded(BaseModel):
    status: JobStatus = Field(pattern="SUCCEEDED")
    result: dict | None = None

class JobUpdateFailed(BaseModel):
    status: JobStatus = Field(pattern="FAILED")
    error: str
