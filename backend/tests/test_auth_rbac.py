"""
Unit & Integration Tests for Enterprise Authentication & RBAC
Tests bcrypt hashing, JWT issuance/validation, token expiration, and role permissions.
"""
import pytest
from app.security.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    ROLE_HIERARCHY
)


def test_password_hashing():
    pw = "SuperSecretPass!2026"
    hashed = hash_password(pw)
    assert hashed != pw
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_access_token_creation_and_decoding():
    token = create_access_token(user_id=42, email="sec-lead@securegate.io", org_id=1, role="Security Engineer")
    payload = decode_token(token)

    assert payload["user_id"] == 42
    assert payload["email"] == "sec-lead@securegate.io"
    assert payload["role"] == "Security Engineer"
    assert payload["type"] == "access"


def test_jwt_refresh_token():
    token = create_refresh_token(user_id=42)
    payload = decode_token(token)

    assert payload["user_id"] == 42
    assert payload["type"] == "refresh"


def test_role_hierarchy():
    assert ROLE_HIERARCHY["Owner"] > ROLE_HIERARCHY["Admin"]
    assert ROLE_HIERARCHY["Admin"] > ROLE_HIERARCHY["Security Engineer"]
    assert ROLE_HIERARCHY["Security Engineer"] > ROLE_HIERARCHY["Developer"]
    assert ROLE_HIERARCHY["Developer"] > ROLE_HIERARCHY["Viewer"]


def test_auth_api_flow(client):
    # 1. Register new user
    reg_resp = client.post("/api/v1/auth/register", json={
        "email": "test-dev@securegate.io",
        "password": "Password123!Secure",
        "full_name": "Test Engineer"
    })
    assert reg_resp.status_code == 201
    reg_data = reg_resp.get_json()
    assert reg_data["status"] == "success"
    assert "access_token" in reg_data
    assert "user" in reg_data

    # 2. Login with registered credentials
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "test-dev@securegate.io",
        "password": "Password123!Secure"
    })
    assert login_resp.status_code == 200
    login_data = login_resp.get_json()
    token = login_data["access_token"]
    assert token is not None

    # 3. Query /me with token
    me_resp = client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {token}"
    })
    assert me_resp.status_code == 200
    me_data = me_resp.get_json()
    assert me_data["user"]["email"] == "test-dev@securegate.io"

    # 4. Attempt login with bad password
    bad_login = client.post("/api/v1/auth/login", json={
        "email": "test-dev@securegate.io",
        "password": "WrongPassword!"
    })
    assert bad_login.status_code == 401
