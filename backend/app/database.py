"""Async SQLAlchemy database primitives."""

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings


class Base(DeclarativeBase):
    pass


def create_engine(database_url: str | None = None) -> AsyncEngine:
    """Build an engine; accepts sqlite+aiosqlite URLs for isolated tests."""
    url = database_url or get_settings().database_url
    kwargs: dict[str, object] = {"pool_pre_ping": not url.startswith("sqlite+")}
    if url.startswith("sqlite+"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_async_engine(url, **kwargs)


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
