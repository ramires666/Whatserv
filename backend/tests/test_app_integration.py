import html
import re
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models import Account
from app.totp import totp_code


ADMIN_AUTH = ("admin", "a-very-long-admin-password")
INTERNAL_TOKEN = "i" * 32
LOGIN_EMAIL = "account@arbitrary-domain.local"
LOGIN_PASSWORD = "correct horse battery staple"


def make_app():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        admin_username=ADMIN_AUTH[0],
        admin_password=ADMIN_AUTH[1],
        internal_api_token=INTERNAL_TOKEN,
        access_token_pepper="p" * 32,
        fernet_key=Fernet.generate_key().decode(),
        qr_fernet_key=Fernet.generate_key().decode(),
        credential_fernet_key=Fernet.generate_key().decode(),
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
        assert '<details id="create-account-panel" class="panel create-account-disclosure">' in admin.text
        assert 'class="create-account-trigger"' in admin.text
        assert "Ввести аккаунт" in admin.text
        assert admin.text.index("Данные аккаунта</legend>") < admin.text.index("Google Authenticator</legend>")
        assert admin.text.index("Google Authenticator</legend>") < admin.text.index("WhatsApp</legend>")
        assert 'type="password"' in admin.text
        assert "otpauth://totp" in admin.text
        csrf = extract_csrf(admin.text)

        created = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": csrf,
                "login_email": LOGIN_EMAIL,
                "login_password": LOGIN_PASSWORD,
                "owner_name": "Иван",
                "comment": "Основной Codex-аккаунт",
                "phone": "+1 (415) 555-2671",
                "totp_secret": "JBSW Y3DP EHPK 3PXP",
                "totp_current_code": totp_code("JBSWY3DPEHPK3PXP"),
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

        assert client.get(f"/admin/accounts/{account_id}/credentials").status_code == 401
        admin_credentials = client.get(
            f"/admin/accounts/{account_id}/credentials", auth=ADMIN_AUTH
        )
        assert admin_credentials.json() == {
            "email": LOGIN_EMAIL,
            "password": LOGIN_PASSWORD,
        }
        admin_capability = client.get(
            f"/admin/accounts/{account_id}/capability", auth=ADMIN_AUTH
        )
        assert urlsplit(admin_capability.json()["url"]).path == capability_path
        assert LOGIN_PASSWORD not in admin_capability.text

        state = client.post(
            f"/api/internal/accounts/{account_id}/state",
            headers=headers,
            json={
                "state": "pending_qr",
                "account_name": "Рабочий WhatsApp",
                "qr_code": "test-whatsapp-qr-value",
            },
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
            "raw_metadata": {
                "remote_jid": "14155550123@s.whatsapp.net",
                "participant": "14155550123@s.whatsapp.net",
                "push_name": "Sender",
                "ignored_secret": "must-not-persist",
            },
        }
        accepted = client.post("/api/internal/messages", headers=headers, json=payload)
        duplicate = client.post("/api/internal/messages", headers=headers, json=payload)
        assert accepted.json() == {"accepted": True, "duplicate": False}
        assert duplicate.json() == {"accepted": False, "duplicate": True}

        inbox = client.get(capability_path)
        assert inbox.status_code == 200
        assert inbox.headers["cache-control"].startswith("no-store")
        assert inbox.headers["referrer-policy"] == "no-referrer"
        assert "+14155552671" in inbox.text
        assert "Рабочий WhatsApp" in inbox.text
        assert "Аккаунт добавлен" in inbox.text
        assert LOGIN_EMAIL in inbox.text
        assert LOGIN_PASSWORD not in inbox.text
        assert 'id="totp-code"' in inbox.text
        assert "JBSWY3DPEHPK3PXP" not in inbox.text

        snapshot = client.get(capability_path.replace("/inbox/", "/api/public/") + "/snapshot")
        assert snapshot.status_code == 200
        body = snapshot.json()
        assert body["whatsapp_state"] == "pending_qr"
        assert body["messages"][0]["body"] == "hello from WhatsApp"
        assert body["messages"][0]["sender_name"] == "Sender"
        assert body["messages"][0]["sender_phone"] == "+14155550123"
        assert body["messages"][0]["sender_jid"] == "14155550123@s.whatsapp.net"
        assert len(body["totp"]["code"]) == 6
        assert 1 <= body["totp"]["valid_for"] <= 30
        assert body["totp"]["server_time"] < body["totp"]["valid_until"]

        credentials = client.get(
            capability_path.replace("/inbox/", "/api/public/") + "/credentials"
        )
        assert credentials.status_code == 200
        assert credentials.headers["cache-control"].startswith("no-store")
        assert credentials.json() == {"email": LOGIN_EMAIL, "password": LOGIN_PASSWORD}

        admin_after_create = client.get("/admin", auth=ADMIN_AUTH)
        assert LOGIN_EMAIL in admin_after_create.text
        assert "Рабочий WhatsApp" in admin_after_create.text
        assert "У кого: <strong>Иван</strong>" in admin_after_create.text
        assert "Основной Codex-аккаунт" in admin_after_create.text
        assert "Добавлен:" in admin_after_create.text
        assert LOGIN_PASSWORD not in admin_after_create.text
        assert capability_path in admin_after_create.text
        assert f'<details id="account-{account_id}" class="panel account-card"' in admin_after_create.text
        assert 'class="account-card-summary"' in admin_after_create.text
        assert 'class="primary-button open-capability-link"' in admin_after_create.text
        assert 'data-capability-url=' not in admin_after_create.text
        assert 'target="_blank"' in admin_after_create.text
        assert 'data-copy-value="https://whatserv.test/inbox/' in admin_after_create.text
        assert "/static/admin.js?v=" in admin_after_create.text

        assert client.get("/admin/account-summaries").status_code == 401
        summaries = client.get("/admin/account-summaries", auth=ADMIN_AUTH).json()
        summary = summaries["items"][0]
        assert summary["account_id"] == account_id
        assert len(summary["totp"]) == 6
        assert summary["latest_message"]["body"] == "hello from WhatsApp"
        assert summary["latest_message"]["sender_name"] == "Sender"
        assert summary["latest_message"]["sender_phone"] == "+14155550123"

        metadata = client.post(
            f"/admin/accounts/{account_id}/metadata",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={
                "csrf_token": extract_csrf(admin_after_create.text),
                "owner_name": "Пётр",
                "comment": "Резервный аккаунт",
            },
        )
        assert metadata.status_code == 303
        updated_admin = client.get("/admin", auth=ADMIN_AUTH)
        assert "У кого: <strong>Пётр</strong>" in updated_admin.text
        assert "Резервный аккаунт" in updated_admin.text

        rotated = client.post(
            f"/admin/accounts/{account_id}/rotate-link",
            auth=ADMIN_AUTH,
            data={"csrf_token": extract_csrf(admin_with_qr.text)},
        )
        assert rotated.status_code == 200
        assert extract_capability_path(rotated.text) != capability_path
        rotated_path = extract_capability_path(rotated.text)
        visible_rotated = client.get(
            f"/admin/accounts/{account_id}/capability", auth=ADMIN_AUTH
        )
        assert urlsplit(visible_rotated.json()["url"]).path == rotated_path
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


def test_totp_is_expected_by_default_but_can_be_explicitly_omitted():
    with TestClient(make_app()) as client:
        admin = client.get("/admin", auth=ADMIN_AUTH)
        csrf = extract_csrf(admin.text)
        oversized_password = "P" * 1025
        bad_password = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": csrf,
                "login_email": LOGIN_EMAIL,
                "login_password": oversized_password,
                "phone": "+14155552671",
                "without_totp": "true",
            },
        )
        assert bad_password.status_code == 422
        assert oversized_password not in bad_password.text

        missing = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": csrf,
                "login_email": LOGIN_EMAIL,
                "login_password": LOGIN_PASSWORD,
                "phone": "+14155552671",
                "totp_secret": "",
            },
        )
        assert missing.status_code == 422
        assert "TOTP нужен по умолчанию" in missing.text
        assert '<details id="create-account-panel" class="panel create-account-disclosure" open>' in missing.text
        assert "JBSWY3DPEHPK3PXP" not in missing.text

        oversized_secret = "A" * 2049
        oversized = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(missing.text),
                "login_email": LOGIN_EMAIL,
                "login_password": LOGIN_PASSWORD,
                "phone": "+14155552671",
                "totp_secret": oversized_secret,
                "totp_current_code": "123456",
            },
        )
        assert oversized.status_code == 422
        assert oversized_secret not in oversized.text

        headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
        assert client.get("/api/internal/accounts", headers=headers).json()["items"] == []

        created = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(missing.text),
                "login_email": LOGIN_EMAIL,
                "login_password": LOGIN_PASSWORD,
                "phone": "+14155552671",
                "totp_secret": "",
                "without_totp": "true",
            },
        )
        assert created.status_code == 200
        capability_path = extract_capability_path(created.text)
        snapshot = client.get(capability_path.replace("/inbox/", "/api/public/") + "/snapshot")
        assert snapshot.status_code == 200
        assert snapshot.json()["totp"] is None
        admin_without_totp = client.get("/admin", auth=ADMIN_AUTH)
        assert 'data-summary-totp=' not in admin_without_totp.text
        assert "Ввести TOTP" in admin_without_totp.text
        inbox_without_totp = client.get(capability_path)
        assert "TOTP НЕ ВВЕДЁН" in inbox_without_totp.text
        assert 'id="totp-code"' in inbox_without_totp.text
        assert 'id="totp-code" class="totp-code"' in inbox_without_totp.text
        assert "disabled hidden" in inbox_without_totp.text

        account_id = client.get(
            "/api/internal/accounts", headers=headers
        ).json()["items"][0]["id"]

        async def clear_legacy_credentials():
            async with client.app.state.session_factory() as session:
                account = await session.get(Account, account_id)
                account.login_email = None
                account.encrypted_login_password = None
                await session.commit()

        client.portal.call(clear_legacy_credentials)
        legacy_admin = client.get("/admin", auth=ADMIN_AUTH)
        assert "Пароль не введён" in legacy_admin.text
        assert "Ввести пароль" in legacy_admin.text
        assert 'data-reveal-credentials=' not in legacy_admin.text
        assert 'data-copy-target="admin-password-' not in legacy_admin.text
        legacy_inbox = client.get(capability_path)
        assert "НЕ ВВЕДЁН" in legacy_inbox.text
        assert 'id="reveal-password"' not in legacy_inbox.text
        assert 'id="copy-password"' not in legacy_inbox.text


def test_admin_can_add_replace_and_remove_totp_without_revealing_secret():
    secret = "JBSWY3DPEHPK3PXP"
    uri = (
        "otpauth://totp/Example:alice%40example.com?"
        f"secret={secret}&issuer=Example"
    )
    with TestClient(make_app()) as client:
        admin = client.get("/admin", auth=ADMIN_AUTH)
        created = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(admin.text),
                "login_email": LOGIN_EMAIL,
                "login_password": LOGIN_PASSWORD,
                "phone": "+14155552671",
                "without_totp": "true",
            },
        )
        capability_path = extract_capability_path(created.text)
        snapshot_path = capability_path.replace("/inbox/", "/api/public/") + "/snapshot"

        headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
        account_id = client.get("/api/internal/accounts", headers=headers).json()["items"][0]["id"]
        admin_without_totp = client.get("/admin", auth=ADMIN_AUTH)
        assert "без TOTP" in admin_without_totp.text

        updated = client.post(
            f"/admin/accounts/{account_id}/totp",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={
                "csrf_token": extract_csrf(admin_without_totp.text),
                "totp_secret": uri,
                "totp_current_code": totp_code(secret),
            },
        )
        assert updated.status_code == 303
        assert secret not in updated.text
        assert uri not in updated.text
        assert len(client.get(snapshot_path).json()["totp"]["code"]) == 6

        admin_with_totp = client.get("/admin", auth=ADMIN_AUTH)
        assert "TOTP настроен" in admin_with_totp.text
        assert secret not in admin_with_totp.text
        assert uri not in admin_with_totp.text

        replacement_secret = "GEZDGNBVGY3TQOJQ"
        actual_replacement_code = totp_code(replacement_secret)
        wrong_replacement_code = (
            actual_replacement_code[:-1]
            + str((int(actual_replacement_code[-1]) + 1) % 10)
        )
        invalid_replacement = client.post(
            f"/admin/accounts/{account_id}/totp",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(admin_with_totp.text),
                "totp_secret": replacement_secret,
                "totp_current_code": wrong_replacement_code,
            },
        )
        assert invalid_replacement.status_code == 422
        assert "Секрет не изменён" in invalid_replacement.text
        assert replacement_secret not in invalid_replacement.text
        assert wrong_replacement_code not in invalid_replacement.text
        assert len(client.get(snapshot_path).json()["totp"]["code"]) == 6

        unconfirmed_removal = client.post(
            f"/admin/accounts/{account_id}/totp/remove",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(invalid_replacement.text),
                "confirmation": "нет",
            },
        )
        assert unconfirmed_removal.status_code == 422
        assert len(client.get(snapshot_path).json()["totp"]["code"]) == 6

        removed = client.post(
            f"/admin/accounts/{account_id}/totp/remove",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={
                "csrf_token": extract_csrf(unconfirmed_removal.text),
                "confirmation": "УДАЛИТЬ",
            },
        )
        assert removed.status_code == 303
        assert client.get(snapshot_path).json()["totp"] is None


def test_whatsapp_logout_requires_double_confirmation_and_durable_worker_ack():
    with TestClient(make_app()) as client:
        admin = client.get("/admin", auth=ADMIN_AUTH)
        created = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(admin.text),
                "login_email": LOGIN_EMAIL,
                "login_password": LOGIN_PASSWORD,
                "phone": "+14155552671",
                "without_totp": "true",
            },
        )
        assert created.status_code == 200

        internal_headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
        account = client.get("/api/internal/accounts", headers=internal_headers).json()["items"][0]
        account_id = account["id"]
        assert account["logout_command_id"] is None

        online = client.post(
            f"/api/internal/accounts/{account_id}/state",
            headers=internal_headers,
            json={"state": "online"},
        )
        assert online.status_code == 200

        admin_account = client.get("/admin", auth=ADMIN_AUTH)
        assert "Разлогинить и перепривязать WhatsApp" in admin_account.text
        assert 'data-confirm="Точно разлогинить WhatsApp +14155552671?' in admin_account.text
        csrf = extract_csrf(admin_account.text)

        wrong_phone = client.post(
            f"/admin/accounts/{account_id}/whatsapp/logout",
            auth=ADMIN_AUTH,
            data={"csrf_token": csrf, "confirmation_phone": "+14155550000"},
        )
        assert wrong_phone.status_code == 422
        assert "WhatsApp не разлогинен" in wrong_phone.text
        account = client.get("/api/internal/accounts", headers=internal_headers).json()["items"][0]
        assert account["logout_command_id"] is None
        assert account["wa_state"] == "online"

        requested = client.post(
            f"/admin/accounts/{account_id}/whatsapp/logout",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={
                "csrf_token": extract_csrf(wrong_phone.text),
                "confirmation_phone": "+14155552671",
            },
        )
        assert requested.status_code == 303
        account = client.get("/api/internal/accounts", headers=internal_headers).json()["items"][0]
        command_id = account["logout_command_id"]
        assert command_id
        assert account["wa_state"] == "logout_requested"

        stale_state = client.post(
            f"/api/internal/accounts/{account_id}/state",
            headers=internal_headers,
            json={"state": "online"},
        )
        assert stale_state.json()["reason"] == "logout_pending"
        account = client.get("/api/internal/accounts", headers=internal_headers).json()["items"][0]
        assert account["wa_state"] == "logout_requested"

        stale_ack = client.post(
            f"/api/internal/accounts/{account_id}/commands/logout/00000000-0000-4000-8000-000000000000/ack",
            headers=internal_headers,
        )
        assert stale_ack.json()["reason"] == "stale_command"
        account = client.get("/api/internal/accounts", headers=internal_headers).json()["items"][0]
        assert account["logout_command_id"] == command_id

        acknowledged = client.post(
            f"/api/internal/accounts/{account_id}/commands/logout/{command_id}/ack",
            headers=internal_headers,
        )
        assert acknowledged.json() == {"ok": True}
        account = client.get("/api/internal/accounts", headers=internal_headers).json()["items"][0]
        assert account["logout_command_id"] is None
        assert account["wa_state"] == "logged_out"
