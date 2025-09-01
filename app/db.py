from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

Base = declarative_base()

_engine: AsyncEngine | None = None
SessionLocal: async_sessionmaker[AsyncSession] | None = None

def init_engine(database_url: str):
    global _engine, SessionLocal
    _engine = create_async_engine(database_url, echo=False, pool_pre_ping=True, future=True)
    SessionLocal = async_sessionmaker(bind=_engine, expire_on_commit=False)

def get_engine() -> AsyncEngine:
    assert _engine is not None, "DB engine not initialized"
    return _engine

def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    assert SessionLocal is not None, "DB sessionmaker not initialized"
    return SessionLocal
