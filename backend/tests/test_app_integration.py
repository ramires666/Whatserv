import html
import re
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


ADMIN_AUTH = ("admin", "a-very-long-admin-password")
INTERNAL_TOKEN = "i" * 32


def make_app():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        admin_username=ADMIN_AUTH[0],
        admin_password=ADMIN_AUTH[1],
        internal_api_token=INTERNAL_TOKEN,
        access_token_pepper="p" * 32,
        fernet_key=Fernet.generate_key().decode(),
        qr_fernet_key=Fernet.generate_key().decode(),
        public_base_url="https://whatserv.test",
        auto_create_schema=True,
    )
    return create_app(settings_override=settings)


def extract_csrf(body: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert match
    return match.group(1)


def extract_capability_path(body: str) -> str:
    match = re.search(r'id="capability-url">([^<]+)</div>', body)
    assert match
    return urlsplit(html.unescape(match.group(1))).path


def test_full_account_qr_message_and_totp_flow():
    with TestClient(make_app()) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/admin").status_code == 401

        admin = client.get("/admin", auth=ADMIN_AUTH)
        assert admin.status_code == 200
        csrf = extract_csrf(admin.text)

        created = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": csrf,
                "label": "Primary",
                "phone": "+1 (415) 555-2671",
                "totp_secret": "JBSW Y3DP EHPK 3PXP",
            },
        )
        assert created.status_code == 200
        capability_path = extract_capability_path(created.text)
        assert "/inbox/14155552671/" in capability_path

        assert client.get("/api/internal/accounts").status_code == 401
        headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
        accounts = client.get("/api/internal/accounts", headers=headers).json()["items"]
        assert len(accounts) == 1
        account_id = accounts[0]["id"]

        state = client.post(
            f"/api/internal/accounts/{account_id}/state",
            headers=headers,
            json={"state": "pending_qr", "qr_code": "test-whatsapp-qr-value"},
        )
        assert state.status_code == 200
        qr = client.get(f"/admin/accounts/{account_id}/qr.png", auth=ADMIN_AUTH)
        assert qr.status_code == 200
        assert qr.headers["content-type"] == "image/png"
        assert qr.content.startswith(b"\x89PNG")
        admin_with_qr = client.get("/admin", auth=ADMIN_AUTH)
        assert f"/admin/accounts/{account_id}/qr.png" in admin_with_qr.text
        assert "test-whatsapp-qr-value" not in admin_with_qr.text

        payload = {
            "account_id": account_id,
            "external_id": "wamid-test-1",
            "sender_phone": "14155550123",
            "body": "hello from WhatsApp",
            "received_at": "2026-07-20T10:30:00Z",
            "message_type": "conversation",
            "raw_metadata": {"push_name": "Sender", "ignored_secret": "must-not-persist"},
        }
        accepted = client.post("/api/internal/messages", headers=headers, json=payload)
        duplicate = client.post("/api/internal/messages", headers=headers, json=payload)
        assert accepted.json() == {"accepted": True, "duplicate": False}
        assert duplicate.json() == {"accepted": False, "duplicate": True}

        inbox = client.get(capability_path)
        assert inbox.status_code == 200
        assert inbox.headers["cache-control"].startswith("no-store")
        assert inbox.headers["referrer-policy"] == "no-referrer"
        assert "+•••••••2671" in inbox.text
        assert "JBSWY3DPEHPK3PXP" not in inbox.text

        snapshot = client.get(capability_path.replace("/inbox/", "/api/public/") + "/snapshot")
        assert snapshot.status_code == 200
        body = snapshot.json()
        assert body["whatsapp_state"] == "pending_qr"
        assert body["messages"][0]["body"] == "hello from WhatsApp"
        assert len(body["totp"]["code"]) == 6
        assert 1 <= body["totp"]["valid_for"] <= 30

        rotated = client.post(
            f"/admin/accounts/{account_id}/rotate-link",
            auth=ADMIN_AUTH,
            data={"csrf_token": extract_csrf(admin_with_qr.text)},
        )
        assert rotated.status_code == 200
        assert extract_capability_path(rotated.text) != capability_path
        assert client.get(capability_path).status_code == 404


def test_admin_csrf_and_invalid_capability_fail_closed():
    with TestClient(make_app()) as client:
        response = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": "invalid",
                "label": "Nope",
                "phone": "+14155552671",
                "totp_secret": "",
            },
        )
        assert response.status_code == 403
        assert client.get("/inbox/14155552671/not-a-real-token").status_code == 404
