import html
import re
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models import Account
from app.totp import totp_code, verify_totp_code


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
        assert 'name="totp_current_code"' not in admin.text
        assert "data-create-whatsapp-login hidden" in admin.text
        admin_script = client.get("/static/admin.js")
        assert "createForm?.addEventListener('submit'" in admin_script.text
        assert "event.preventDefault()" in admin_script.text
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
                "label": "Основной аккаунт",
                "phone": "+1 (415) 555-2671",
                "totp_secret": "JBSW Y3DP EHPK 3PXP",
                "start_whatsapp": "true",
            },
        )
        assert created.status_code == 200
        capability_path = extract_capability_path(created.text)
        assert re.fullmatch(
            r"/inbox/[0-9a-f-]{36}/[^/]+",
            capability_path,
        )

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
        assert "+1 (415) 555-2671" in inbox.text
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
        assert "Основной аккаунт" in admin_after_create.text
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
                "phone": "+1 (415) 555-2672",
                "label": "Резервный WhatsApp",
                "owner_name": "Пётр",
                "comment": "Резервный аккаунт",
            },
        )
        assert metadata.status_code == 303
        updated_admin = client.get("/admin", auth=ADMIN_AUTH)
        assert "+1 (415) 555-2672" in updated_admin.text
        assert capability_path in updated_admin.text
        assert "Резервный WhatsApp" in updated_admin.text
        assert "У кого: <strong>Пётр</strong>" in updated_admin.text
        assert "Резервный аккаунт" in updated_admin.text

        credentials_update = client.post(
            f"/admin/accounts/{account_id}/credentials",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={
                "csrf_token": extract_csrf(updated_admin.text),
                "login_email": "changed@arbitrary-domain.local",
                "login_password": "",
            },
        )
        assert credentials_update.status_code == 303
        assert client.get(
            f"/admin/accounts/{account_id}/credentials", auth=ADMIN_AUTH
        ).json() == {
            "email": "changed@arbitrary-domain.local",
            "password": LOGIN_PASSWORD,
        }
        assert "Резервный WhatsApp" in client.get("/admin", auth=ADMIN_AUTH).text

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


def test_phone_is_optional_freeform_metadata_and_whatsapp_requires_explicit_start():
    with TestClient(make_app()) as client:
        admin = client.get("/admin", auth=ADMIN_AUTH)
        created = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(admin.text),
                "login_email": LOGIN_EMAIL,
                "login_password": LOGIN_PASSWORD,
                "without_totp": "true",
            },
        )
        assert created.status_code == 200
        capability_path = extract_capability_path(created.text)
        disabled_inbox = client.get(capability_path)
        assert disabled_inbox.status_code == 200
        assert "Телефон не указан" in disabled_inbox.text

        internal_headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
        account = client.get(
            "/api/internal/accounts", headers=internal_headers
        ).json()["items"][0]
        account_id = account["id"]
        assert account["phone_e164"] is None
        assert account["enabled"] is False
        assert account["wa_state"] == "disabled"

        account_admin = client.get("/admin", auth=ADMIN_AUTH)
        assert f'action="/admin/accounts/{account_id}/whatsapp/connect"' not in account_admin.text
        assert "Введите телефон в данных аккаунта" in account_admin.text

        blocked = client.post(
            f"/admin/accounts/{account_id}/whatsapp/connect",
            auth=ADMIN_AUTH,
            data={"csrf_token": extract_csrf(account_admin.text)},
        )
        assert blocked.status_code == 422
        assert "Сначала введите телефон" in blocked.text

        arbitrary_phone = "внутренний номер / доб. 12"
        updated = client.post(
            f"/admin/accounts/{account_id}/metadata",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={
                "csrf_token": extract_csrf(blocked.text),
                "phone": arbitrary_phone,
                "label": "Произвольный телефон",
                "owner_name": "",
                "comment": "",
            },
        )
        assert updated.status_code == 303
        updated_admin = client.get("/admin", auth=ADMIN_AUTH)
        assert arbitrary_phone in updated_admin.text
        assert f'action="/admin/accounts/{account_id}/whatsapp/connect"' in updated_admin.text

        started = client.post(
            f"/admin/accounts/{account_id}/whatsapp/connect",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={"csrf_token": extract_csrf(updated_admin.text)},
        )
        assert started.status_code == 303
        started_account = client.get(
            "/api/internal/accounts", headers=internal_headers
        ).json()["items"][0]
        assert started_account["enabled"] is True
        assert started_account["wa_state"] == "new"


def test_email_is_the_unique_account_identity_and_form_metadata_survives_errors():
    shared_phone = "один телефон для двух аккаунтов"
    with TestClient(make_app()) as client:
        admin = client.get("/admin", auth=ADMIN_AUTH)
        first = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(admin.text),
                "login_email": LOGIN_EMAIL,
                "login_password": LOGIN_PASSWORD,
                "phone": shared_phone,
                "without_totp": "true",
            },
        )
        assert first.status_code == 200
        second = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(client.get('/admin', auth=ADMIN_AUTH).text),
                "login_email": "second@arbitrary-domain.local",
                "login_password": LOGIN_PASSWORD,
                "phone": shared_phone,
                "without_totp": "true",
            },
        )
        assert second.status_code == 200

        duplicate = client.post(
            "/admin/accounts",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(client.get('/admin', auth=ADMIN_AUTH).text),
                "login_email": LOGIN_EMAIL.upper(),
                "login_password": LOGIN_PASSWORD,
                "phone": "совсем другой телефон",
                "label": "Сохранённое название",
                "owner_name": "Сохранённый владелец",
                "comment": "Сохранённый комментарий",
                "without_totp": "true",
            },
        )
        assert duplicate.status_code == 409
        assert "Этот email уже привязан" in duplicate.text
        assert 'value="Сохранённое название"' in duplicate.text
        assert 'value="Сохранённый владелец"' in duplicate.text
        assert "Сохранённый комментарий" in duplicate.text
        assert 'name="without_totp" type="checkbox" value="true" checked' in duplicate.text
        assert "data-create-whatsapp-login hidden" not in duplicate.text
        assert LOGIN_PASSWORD not in duplicate.text

        accounts = client.get(
            "/api/internal/accounts",
            headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"},
        ).json()["items"]
        assert len(accounts) == 2
        assert [item["phone_e164"] for item in accounts] == [shared_phone, shared_phone]


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
        invalid_replacement = client.post(
            f"/admin/accounts/{account_id}/totp",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(admin_with_totp.text),
                "totp_secret": "not-a-valid-base32-secret!",
            },
        )
        assert invalid_replacement.status_code == 422
        assert "Секрет не изменён" in invalid_replacement.text
        assert "not-a-valid-base32-secret!" not in invalid_replacement.text
        assert len(client.get(snapshot_path).json()["totp"]["code"]) == 6

        replaced = client.post(
            f"/admin/accounts/{account_id}/totp",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={
                "csrf_token": extract_csrf(invalid_replacement.text),
                "totp_secret": replacement_secret,
            },
        )
        assert replaced.status_code == 303
        assert verify_totp_code(
            replacement_secret,
            client.get(snapshot_path).json()["totp"]["code"],
        )
        admin_after_replacement = client.get("/admin", auth=ADMIN_AUTH)

        unconfirmed_removal = client.post(
            f"/admin/accounts/{account_id}/totp/remove",
            auth=ADMIN_AUTH,
            data={
                "csrf_token": extract_csrf(admin_after_replacement.text),
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


def test_whatsapp_qr_request_is_always_visible_idempotent_and_durable():
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
        assert account["enabled"] is False

        disabled_admin = client.get("/admin", auth=ADMIN_AUTH)
        assert "Войти через QR WhatsApp" in disabled_admin.text
        connected = client.post(
            f"/admin/accounts/{account_id}/whatsapp/connect",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={"csrf_token": extract_csrf(disabled_admin.text)},
        )
        assert connected.status_code == 303

        online = client.post(
            f"/api/internal/accounts/{account_id}/state",
            headers=internal_headers,
            json={"state": "online"},
        )
        assert online.status_code == 200

        admin_account = client.get("/admin", auth=ADMIN_AUTH)
        assert "Получить новый QR WhatsApp" in admin_account.text
        assert 'name="confirmation_phone"' not in admin_account.text
        csrf = extract_csrf(admin_account.text)

        disabled = client.post(
            f"/admin/accounts/{account_id}/toggle",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={"csrf_token": csrf},
        )
        assert disabled.status_code == 303
        disabled_admin = client.get("/admin", auth=ADMIN_AUTH)
        assert "Войти через QR WhatsApp" in disabled_admin.text
        account = client.get("/api/internal/accounts", headers=internal_headers).json()["items"][0]
        assert account["logout_command_id"] is None
        assert account["wa_state"] == "disabled"

        requested = client.post(
            f"/admin/accounts/{account_id}/whatsapp/logout",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={"csrf_token": extract_csrf(disabled_admin.text)},
        )
        assert requested.status_code == 303
        account = client.get("/api/internal/accounts", headers=internal_headers).json()["items"][0]
        command_id = account["logout_command_id"]
        assert command_id
        assert account["enabled"] is True
        assert account["wa_state"] == "logout_requested"

        repeated = client.post(
            f"/admin/accounts/{account_id}/whatsapp/logout",
            auth=ADMIN_AUTH,
            follow_redirects=False,
            data={"csrf_token": extract_csrf(disabled_admin.text)},
        )
        assert repeated.status_code == 303
        repeated_account = client.get(
            "/api/internal/accounts", headers=internal_headers
        ).json()["items"][0]
        assert repeated_account["logout_command_id"] == command_id

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
