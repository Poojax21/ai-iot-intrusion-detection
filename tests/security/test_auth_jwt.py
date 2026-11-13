"""
Comprehensive Security & JWT Authentication Tests for Phase 6.
Tests password policy, Argon2id verification, access/refresh tokens,
rotation, and reuse detection.
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.auth.security import hash_password, verify_password, validate_password_strength


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_password_policy_and_hasher():
    # Complexity validation
    valid, _ = validate_password_strength("Str0ng!Passw0rd")
    assert valid is True

    too_short, msg = validate_password_strength("Short1!")
    assert too_short is False
    assert "8 characters" in msg

    no_digit, _ = validate_password_strength("NoDigitHere!@#")
    assert no_digit is False

    no_special, _ = validate_password_strength("NoSpecialChar123")
    assert no_special is False

    # Argon2id hashing & verification
    plain = "SecureTestPassword123!"
    h = hash_password(plain)
    assert h.startswith("$argon2id$")
    assert verify_password(plain, h) is True
    assert verify_password("WrongPassword123!", h) is False


def test_registration_and_login_lifecycle(client):
    suffix = int(time.time() * 1000)
    email = f"admin_{suffix}@pahredaar.sec"
    password = "SuperSecurePassword123!"
    org_name = f"Enterprise Org {suffix}"

    # 1. Register new Admin user
    reg_resp = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Security Administrator",
            "organization_name": org_name,
        },
    )
    assert reg_resp.status_code == 201
    tokens = reg_resp.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # 2. Duplicate registration should fail
    dup_resp = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Duplicate User",
            "organization_name": org_name,
        },
    )
    assert dup_resp.status_code == 400

    # 3. Authenticate with correct credentials
    login_resp = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200
    login_tokens = login_resp.json()
    assert "access_token" in login_tokens

    # 4. Authenticate with incorrect credentials
    bad_login = client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongPassword123!"},
    )
    assert bad_login.status_code == 401

    # 5. Access profile /api/auth/me
    me_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 200
    user_info = me_resp.json()
    assert user_info["email"] == email
    assert user_info["role"] == "admin"
    assert user_info["organization_name"] == org_name
    assert "manage:sensors" in user_info["permissions"]


def test_refresh_token_rotation_and_reuse_detection(client):
    suffix = int(time.time() * 1000)
    email = f"analyst_{suffix}@pahredaar.sec"
    password = "SuperSecurePassword123!"

    reg_resp = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Sec Analyst",
            "organization_name": f"SOC Team {suffix}",
        },
    )
    assert reg_resp.status_code == 201
    initial_rt = reg_resp.json()["refresh_token"]

    # 1. Normal rotation: use initial refresh token to obtain a new pair
    rot_resp = client.post(
        "/api/auth/refresh",
        json={"refresh_token": initial_rt},
    )
    assert rot_resp.status_code == 200
    new_tokens = rot_resp.json()
    new_rt = new_tokens["refresh_token"]
    assert new_rt != initial_rt

    # 2. Reuse Detection: present the revoked initial refresh token again
    reuse_resp = client.post(
        "/api/auth/refresh",
        json={"refresh_token": initial_rt},
    )
    assert reuse_resp.status_code == 401
    assert "reuse detected" in reuse_resp.json()["detail"].lower()

    # 3. Family Revocation: verify the newly issued token was also invalidated due to reuse detection
    family_killed_resp = client.post(
        "/api/auth/refresh",
        json={"refresh_token": new_rt},
    )
    assert family_killed_resp.status_code == 401
