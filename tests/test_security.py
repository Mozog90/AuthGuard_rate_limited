"""Focused API security tests; every test gets a separate temporary SQLite DB."""

import pytest
from fastapi.testclient import TestClient

from app import main as authguard


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(authguard, "DATABASE_PATH", tmp_path / "authguard_test.db")
    with TestClient(authguard.app) as test_client:
        yield test_client


def register_user(client, username="student", password="GoodPassword123!"):
    response = client.post(
        "/api/register", json={"username": username, "password": password}
    )
    assert response.status_code == 201


@pytest.mark.parametrize(
    "username,password",
    [("", "GoodPassword123!"), ("student", "")],
)
def test_registration_rejects_empty_inputs(client, username, password):
    response = client.post(
        "/api/register", json={"username": username, "password": password}
    )
    assert response.status_code == 400
    with authguard.database() as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


@pytest.mark.parametrize(
    "username,password",
    [("", "GoodPassword123!"), ("student", "")],
)
def test_login_rejects_empty_inputs_without_creating_session(client, username, password):
    register_user(client)
    response = client.post(
        "/api/login", json={"username": username, "password": password}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password"}
    assert client.get("/api/user").status_code == 401


def test_sql_like_input_cannot_bypass_login_or_damage_database(client):
    register_user(client)
    for username, password in [
        ("' OR 1=1 --", "anything"),
        ("student", "' OR '1'='1"),
        ('"; DROP TABLE users; --', "anything"),
    ]:
        response = client.post(
            "/api/login", json={"username": username, "password": password}
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid username or password"}

    with authguard.database() as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    assert client.post(
        "/api/login", json={"username": "student", "password": "GoodPassword123!"}
    ).status_code == 200


def test_bad_username_and_bad_password_have_same_generic_error(client):
    register_user(client)
    responses = [
        client.post("/api/login", json={"username": "student", "password": "wrong"}),
        client.post("/api/login", json={"username": "notarealuser", "password": "wrong"}),
    ]
    for response in responses:
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid username or password"}
        assert "password_hash" not in response.text


def test_logged_out_endpoints_return_401(client):
    for path in ("/api/user", "/api/admin", "/dashboard", "/admin"):
        assert client.get(path).status_code == 401


def test_regular_user_is_forbidden_from_admin_api_and_page(client):
    register_user(client)
    login = client.post(
        "/api/login", json={"username": "student", "password": "GoodPassword123!"}
    )
    assert login.status_code == 200
    assert client.get("/api/user").status_code == 200
    assert client.get("/dashboard").status_code == 200
    assert client.get("/api/admin").status_code == 403
    assert client.get("/admin").status_code == 403


def test_admin_can_access_both_roles_resources(client):
    with authguard.database() as connection:
        connection.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("localadmin", authguard.hash_password("AdminPassword123!"), "admin"),
        )
    response = client.post(
        "/api/login", json={"username": "localadmin", "password": "AdminPassword123!"}
    )
    assert response.status_code == 200
    for path in ("/api/user", "/api/admin", "/dashboard", "/admin"):
        assert client.get(path).status_code == 200


def test_registration_cannot_assign_admin_role(client):
    response = client.post(
        "/api/register",
        json={"username": "student", "password": "GoodPassword123!", "role": "admin"},
    )
    assert response.status_code == 422
    with authguard.database() as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_rate_limit_429_and_recovery_after_simulated_cooldown(client):
    register_user(client)
    bad = {"username": "student", "password": "incorrect"}
    for _ in range(4):
        assert client.post("/api/login", json=bad).status_code == 401
    blocked = client.post("/api/login", json=bad)
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0

    good = {"username": "student", "password": "GoodPassword123!"}
    assert client.post("/api/login", json=good).status_code == 429

    # Advance the temporary DB's block timestamp; no real 30-second wait needed.
    with authguard.database() as connection:
        connection.execute(
            "UPDATE login_attempts SET blocked_until = 0 WHERE username = ?",
            ("student",),
        )
    assert client.post("/api/login", json=good).status_code == 200
    with authguard.database() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username = ?", ("student",)
        ).fetchone()[0] == 0


def test_logout_invalidates_server_side_session(client):
    register_user(client)
    assert client.post(
        "/api/login", json={"username": "student", "password": "GoodPassword123!"}
    ).status_code == 200
    former_cookie = client.cookies.get(authguard.COOKIE_NAME)
    assert former_cookie
    assert client.get("/api/user").status_code == 200
    assert client.post("/api/logout").status_code == 200
    assert client.get("/api/user").status_code == 401
    # Replaying the old cookie must still fail because SQLite session was deleted.
    client.cookies.set(authguard.COOKIE_NAME, former_cookie)
    assert client.get("/api/user").status_code == 401


def test_password_is_stored_as_argon2id_hash_not_plaintext(client):
    register_user(client)
    with authguard.database() as connection:
        saved = connection.execute(
            "SELECT password_hash, role FROM users WHERE username = ?", ("student",)
        ).fetchone()
    assert saved["password_hash"].startswith("$argon2id$")
    assert saved["password_hash"] != "GoodPassword123!"
    assert saved["role"] == "user"

