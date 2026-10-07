"""
Tests for OWASP ZAP API endpoints
"""
import pytest
import time
from app import create_app
from app.models.database import db


@pytest.fixture
def app():
    app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SECRET_KEY': 'test-secret'
    })
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_zap_health_endpoint(client):
    """Test health check of ZAP daemon endpoint."""
    res = client.get('/api/zap/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "daemon" in data
    assert "connected" in data["daemon"]


def test_zap_quickstart_endpoint(client):
    """Test retrieval of ZAP daemon quickstart commands."""
    res = client.get('/api/zap/quickstart')
    assert res.status_code == 200
    data = res.get_json()
    assert "docker_command" in data
    assert "zaproxy/zap-stable" in data["docker_command"]


def test_zap_scan_simulation_flow(client):
    """Test initiating a scan task with simulation and monitoring completion."""
    res = client.post('/api/zap/scan', json={
        "target_url": "https://pentest-ground.com:4280",
        "simulate": True
    })
    assert res.status_code == 202
    data = res.get_json()
    assert data["status"] == "success"
    task_id = data["task_id"]
    assert task_id.startswith("zap-task-")

    # Poll status until finished
    for _ in range(20):
        t_res = client.get(f'/api/zap/tasks/{task_id}')
        assert t_res.status_code == 200
        t_data = t_res.get_json()["task"]
        if t_data["status"] == "COMPLETED":
            assert t_data["progress"] == 100
            assert t_data["scan_id"] is not None
            assert "scan" in t_data
            assert t_data["scan"]["release_status"] == "BLOCK"
            assert t_data["scan"]["total_findings"] >= 4
            break
        time.sleep(0.5)
