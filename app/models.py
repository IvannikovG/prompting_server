from datetime import datetime
from sqlalchemy import (
    Column, String, Text, Integer, DateTime, Enum, Index, JSON, func, text, CheckConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
import enum
import uuid

from db import Base

class JobStatus(str, enum.Enum):
    PENDING   = "PENDING"
    CLAIMED   = "CLAIMED"
    RUNNING   = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED    = "FAILED"
    CANCELLED = "CANCELLED"

class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    prompt: Mapped[str]   = mapped_column(Text, nullable=False)
    url: Mapped[str | None] = mapped_column(String, nullable=True)
    options: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus, name="job_status"), nullable=False, default=JobStatus.PENDING)

    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error:  Mapped[str | None]  = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    claimed_by: Mapped[str | None] = mapped_column(String, nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lock_until: Mapped[datetime | None]  = mapped_column(DateTime(timezone=True), nullable=True)

    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))

    __table_args__ = (
        Index("ix_jobs_status_created_at", "status", "created_at"),
        CheckConstraint("status IN ('PENDING','CLAIMED','RUNNING','SUCCEEDED','FAILED','CANCELLED')", name="status_enum_check"),
    )
