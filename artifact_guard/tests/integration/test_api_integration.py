"""Integration tests for FastAPI application."""
import pytest
from uuid import uuid4
from httpx import AsyncClient, ASGITransport

from api.app import create_app
from domain.artifact import ArtifactType
from storage.postgres import DatabaseConfig, DatabasePool


@pytest.fixture
async def app():
    """Create test application with mocked database."""
    app = create_app()
    # Mock database pool for tests
    app.state.db_pool = None
    yield app


@pytest.fixture
async def client(app):
    """Create test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_check(client):
    """Test health check endpoint."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_submit_url_artifact(client):
    """Test submitting a URL artifact."""
    payload = {
        "artifact_type": "url",
        "value": "https://example.com/login",
        "context_excerpt": "User shared this link in chat",
        "source_chat_id": 12345,
        "source_message_id": 67890,
    }

    response = await client.post("/api/v1/artifacts/submit", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert "analysis_id" in data
    assert "correlation_id" in data
    assert data["status"] in ["pending", "duplicate"]


@pytest.mark.asyncio
async def test_submit_domain_artifact(client):
    """Test submitting a domain artifact."""
    payload = {
        "artifact_type": "domain",
        "value": "suspicious-domain.xyz",
        "context_excerpt": "Domain mentioned in suspicious message",
    }

    response = await client.post("/api/v1/artifacts/submit", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert "analysis_id" in data


@pytest.mark.asyncio
async def test_submit_invalid_artifact(client):
    """Test submitting an invalid artifact (too long)."""
    payload = {
        "artifact_type": "url",
        "value": "https://" + "a" * 5000,  # Too long
    }

    response = await client.post("/api/v1/artifacts/submit", json=payload)
    assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_get_nonexistent_analysis(client):
    """Test getting a nonexistent analysis."""
    fake_id = uuid4()
    response = await client.get(f"/api/v1/analyses/{fake_id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_deduplication(client):
    """Test that duplicate submissions are detected."""
    payload = {
        "artifact_type": "url",
        "value": "https://duplicate-test.com",
        "context_excerpt": "Testing deduplication",
    }

    # First submission
    response1 = await client.post("/api/v1/artifacts/submit", json=payload)
    assert response1.status_code == 202
    data1 = response1.json()

    # Second submission (should be duplicate)
    response2 = await client.post("/api/v1/artifacts/submit", json=payload)
    assert response2.status_code == 202
    data2 = response2.json()

    # Both should return the same analysis_id
    if data1["status"] == "pending" and data2["status"] == "duplicate":
        assert data1["analysis_id"] == data2["analysis_id"]
