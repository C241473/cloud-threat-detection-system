import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import Base, get_db

# Shared in-memory SQLite engine with StaticPool for API testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def setup_test_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

client = TestClient(app)

def test_dashboard_stats_endpoint():
    """Verify GET /api/dashboard/stats returns correct JSON structure."""
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "failed_logins" in data
    assert "total_threats" in data
    assert "system_metrics" in data

def test_log_ingestion_endpoint():
    """Verify POST /api/logs ingests log entries correctly."""
    payload = {
        "ip_address": "10.0.0.77",
        "username": "api_test_user",
        "event_type": "LOGIN_SUCCESS",
        "status": "SUCCESS",
        "details": "Integration test login"
    }
    response = client.post("/api/logs", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["ip_address"] == "10.0.0.77"
    assert data["event_type"] == "LOGIN_SUCCESS"

def test_threat_list_endpoint():
    """Verify GET /api/threats returns threat lists."""
    response = client.get("/api/threats")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
