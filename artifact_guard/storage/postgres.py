"""PostgreSQL storage layer for Artifact Guard."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncGenerator
from uuid import UUID

import asyncpg


@dataclass
class DatabaseConfig:
    """Database connection configuration."""

    host: str = "localhost"
    port: int = 5432
    user: str = "artifact_guard"
    password: str = "secure_password"
    database: str = "artifact_guard"
    min_size: int = 2
    max_size: int = 10
    command_timeout: int = 60


class DatabasePool:
    """Manages PostgreSQL connection pool."""

    def __init__(self, config: DatabaseConfig | None = None):
        self.config = config or DatabaseConfig()
        self._pool: asyncpg.Pool | None = None

    async def create_pool(self) -> None:
        """Create the connection pool."""
        self._pool = await asyncpg.create_pool(
            host=self.config.host,
            port=self.config.port,
            user=self.config.user,
            password=self.config.password,
            database=self.config.database,
            min_size=self.config.min_size,
            max_size=self.config.max_size,
            command_timeout=self.config.command_timeout,
        )

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None

    @asynccontextmanager
    async def acquire(
        self,
    ) -> AsyncGenerator[asyncpg.Connection, None]:
        """Acquire a connection from the pool."""
        if not self._pool:
            raise RuntimeError("Pool not initialized")
        async with self._pool.acquire() as conn:
            yield conn

    @property
    def is_initialized(self) -> bool:
        """Check if pool is initialized."""
        return self._pool is not None


@dataclass
class AnalysisRecord:
    """Database record for an analysis."""

    analysis_id: UUID
    correlation_id: UUID
    artifact_type: str
    artifact_value: str
    artifact_hash: str
    idempotency_key: str
    verdict: str
    risk_score: float
    status: str  # pending, processing, completed, failed
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None
    source_system: str | None = None
    source_chat_hash: str | None = None
    source_message_hash: str | None = None
    context_excerpt: str | None = None


@dataclass
class IndicatorRecord:
    """Database record for an indicator."""

    id: UUID
    analysis_id: UUID
    name: str
    score: float
    severity: str
    explanation: str
    evidence_ids: list[UUID]
    created_at: datetime


class AnalysisRepository:
    """Repository for analysis records."""

    def __init__(self, db: DatabasePool):
        self.db = db

    async def create_analysis(
        self,
        analysis_id: UUID,
        correlation_id: UUID,
        artifact_type: str,
        artifact_value: str,
        artifact_hash: str,
        idempotency_key: str,
        source_system: str | None = None,
        source_chat_hash: str | None = None,
        source_message_hash: str | None = None,
        context_excerpt: str | None = None,
    ) -> AnalysisRecord:
        """Create a new analysis record."""
        now = datetime.now(timezone.utc)
        record = AnalysisRecord(
            analysis_id=analysis_id,
            correlation_id=correlation_id,
            artifact_type=artifact_type,
            artifact_value=artifact_value,
            artifact_hash=artifact_hash,
            idempotency_key=idempotency_key,
            verdict="PENDING",
            risk_score=0.0,
            status="pending",
            created_at=now,
            updated_at=now,
            completed_at=None,
            error_message=None,
            source_system=source_system,
            source_chat_hash=source_chat_hash,
            source_message_hash=source_message_hash,
            context_excerpt=context_excerpt,
        )

        async with self.db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO analyses (
                    analysis_id, correlation_id, artifact_type, artifact_value,
                    artifact_hash, idempotency_key, verdict, risk_score, status,
                    created_at, updated_at, source_system, source_chat_hash,
                    source_message_hash, context_excerpt
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                """,
                record.analysis_id,
                record.correlation_id,
                record.artifact_type,
                record.artifact_value,
                record.artifact_hash,
                record.idempotency_key,
                record.verdict,
                record.risk_score,
                record.status,
                record.created_at,
                record.updated_at,
                record.source_system,
                record.source_chat_hash,
                record.source_message_hash,
                record.context_excerpt,
            )

        return record

    async def get_by_idempotency_key(
        self, key: str
    ) -> AnalysisRecord | None:
        """Get analysis by idempotency key (for deduplication)."""
        async with self.db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM analyses WHERE idempotency_key = $1", key
            )
            if not row:
                return None
            return self._row_to_record(row)

    async def get_by_analysis_id(
        self, analysis_id: UUID
    ) -> AnalysisRecord | None:
        """Get analysis by ID."""
        async with self.db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM analyses WHERE analysis_id = $1", analysis_id
            )
            if not row:
                return None
            return self._row_to_record(row)

    async def update_status(
        self,
        analysis_id: UUID,
        status: str,
        error_message: str | None = None,
    ) -> None:
        """Update analysis status."""
        now = datetime.now(timezone.utc)
        async with self.db.acquire() as conn:
            await conn.execute(
                """
                UPDATE analyses
                SET status = $1, updated_at = $2, error_message = $3
                WHERE analysis_id = $4
                """,
                status,
                now,
                error_message,
                analysis_id,
            )

    async def complete_analysis(
        self,
        analysis_id: UUID,
        verdict: str,
        risk_score: float,
    ) -> None:
        """Mark analysis as completed with verdict."""
        now = datetime.now(timezone.utc)
        async with self.db.acquire() as conn:
            await conn.execute(
                """
                UPDATE analyses
                SET verdict = $1, risk_score = $2, status = 'completed',
                    updated_at = $3, completed_at = $3
                WHERE analysis_id = $4
                """,
                verdict,
                risk_score,
                now,
                analysis_id,
            )

    async def fail_analysis(
        self, analysis_id: UUID, error_message: str
    ) -> None:
        """Mark analysis as failed."""
        now = datetime.now(timezone.utc)
        async with self.db.acquire() as conn:
            await conn.execute(
                """
                UPDATE analyses
                SET status = 'failed', error_message = $1,
                    updated_at = $2
                WHERE analysis_id = $3
                """,
                error_message,
                now,
                analysis_id,
            )

    async def save_indicator(self, indicator: IndicatorRecord) -> None:
        """Save an indicator to the database."""
        async with self.db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO indicators (
                    id, analysis_id, name, score, severity,
                    explanation, evidence_ids, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                indicator.id,
                indicator.analysis_id,
                indicator.name,
                indicator.score,
                indicator.severity,
                indicator.explanation,
                indicator.evidence_ids,
                indicator.created_at,
            )

    async def get_indicators(
        self, analysis_id: UUID
    ) -> list[IndicatorRecord]:
        """Get all indicators for an analysis."""
        async with self.db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM indicators WHERE analysis_id = $1", analysis_id
            )
            return [self._row_to_indicator(row) for row in rows]

    def _row_to_record(self, row: asyncpg.Record) -> AnalysisRecord:
        """Convert database row to AnalysisRecord."""
        return AnalysisRecord(
            analysis_id=row["analysis_id"],
            correlation_id=row["correlation_id"],
            artifact_type=row["artifact_type"],
            artifact_value=row["artifact_value"],
            artifact_hash=row["artifact_hash"],
            idempotency_key=row["idempotency_key"],
            verdict=row["verdict"],
            risk_score=row["risk_score"],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            completed_at=row.get("completed_at"),
            error_message=row.get("error_message"),
            source_system=row.get("source_system"),
            source_chat_hash=row.get("source_chat_hash"),
            source_message_hash=row.get("source_message_hash"),
            context_excerpt=row.get("context_excerpt"),
        )

    def _row_to_indicator(self, row: asyncpg.Record) -> IndicatorRecord:
        """Convert database row to IndicatorRecord."""
        return IndicatorRecord(
            id=row["id"],
            analysis_id=row["analysis_id"],
            name=row["name"],
            score=row["score"],
            severity=row["severity"],
            explanation=row["explanation"],
            evidence_ids=row["evidence_ids"] or [],
            created_at=row["created_at"],
        )


async def init_database(pool: DatabasePool) -> None:
    """Initialize database schema."""
    async with pool.acquire() as conn:
        # Create analyses table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id UUID PRIMARY KEY,
                correlation_id UUID NOT NULL,
                artifact_type VARCHAR(50) NOT NULL,
                artifact_value TEXT NOT NULL,
                artifact_hash VARCHAR(64) NOT NULL,
                idempotency_key VARCHAR(64) UNIQUE NOT NULL,
                verdict VARCHAR(50) NOT NULL DEFAULT 'PENDING',
                risk_score REAL NOT NULL DEFAULT 0.0,
                status VARCHAR(50) NOT NULL DEFAULT 'pending',
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                completed_at TIMESTAMPTZ,
                error_message TEXT,
                source_system VARCHAR(100),
                source_chat_hash VARCHAR(64),
                source_message_hash VARCHAR(64),
                context_excerpt TEXT
            )
        """)

        # Create indicators table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                id UUID PRIMARY KEY,
                analysis_id UUID NOT NULL REFERENCES analyses(analysis_id),
                name VARCHAR(200) NOT NULL,
                score REAL NOT NULL,
                severity VARCHAR(50) NOT NULL,
                explanation TEXT NOT NULL,
                evidence_ids UUID[] DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL
            )
        """)

        # Create indexes for performance
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_idempotency
            ON analyses(idempotency_key)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_correlation
            ON analyses(correlation_id)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_status
            ON analyses(status)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_created_at
            ON analyses(created_at DESC)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_indicators_analysis
            ON indicators(analysis_id)
        """)
