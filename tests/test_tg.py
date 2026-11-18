import pytest

from alta_onetime.tg import (
    SESSION_TTL,
    LoginError,
    TgUser,
    UsedHashes,
    make_session,
    read_session,
    session_key,
    verify_login,
    widget_hash,
)

TOKEN = "123456:TEST-TOKEN"
NOW = 1_800_000_000


def signed(**fields: str) -> dict[str, str]:
    base = {"id": "9000001", "first_name": "Ivan", "username": "Test_Reviewer", "auth_date": str(NOW - 10)}
    base.update(fields)
    return {**base, "hash": widget_hash(base, TOKEN)}


def test_valid_login_gives_lowercase_username():
    assert verify_login(signed(), TOKEN, NOW) == TgUser(9000001, "test_reviewer")


def test_tampered_field_is_rejected():
    data = signed()
    data["username"] = "someone_else"
    with pytest.raises(LoginError, match="bad_signature"):
        verify_login(data, TOKEN, NOW)


def test_signature_from_other_bot_is_rejected():
    data = signed()
    with pytest.raises(LoginError, match="bad_signature"):
        verify_login(data, "999:OTHER", NOW)


def test_login_older_than_hour_is_rejected():
    with pytest.raises(LoginError, match="expired"):
        verify_login(signed(auth_date=str(NOW - 3601)), TOKEN, NOW)


def test_account_without_username_is_rejected():
    data = {"id": "9000001", "first_name": "Ivan", "auth_date": str(NOW)}
    with pytest.raises(LoginError, match="no_username"):
        verify_login({**data, "hash": widget_hash(data, TOKEN)}, TOKEN, NOW)


def test_session_roundtrip():
    key = session_key(TOKEN)
    cookie = make_session(TgUser(1, "ivan_testov"), key, NOW)
    assert read_session(cookie, key, NOW + 60) == TgUser(1, "ivan_testov")


def test_session_expires_after_30_minutes():
    key = session_key(TOKEN)
    assert read_session(make_session(TgUser(1, "ivan_testov"), key, NOW), key, NOW + SESSION_TTL + 1) is None


def test_forged_session_is_rejected():
    key = session_key(TOKEN)
    cookie = make_session(TgUser(1, "ivan_testov"), session_key("999:OTHER"), NOW)
    assert read_session(cookie, key, NOW) is None


def test_login_older_than_five_minutes_is_expired():
    with pytest.raises(LoginError, match="expired"):
        verify_login(signed(auth_date=str(NOW - 301)), TOKEN, NOW)


def test_same_widget_hash_is_accepted_only_once():
    used = UsedHashes()
    data = signed()
    verify_login(data, TOKEN, NOW, used)
    with pytest.raises(LoginError, match="replayed"):
        verify_login(data, TOKEN, NOW + 1, used)


def test_used_hash_is_forgotten_after_it_expires():
    used = UsedHashes()
    assert used.claim("h", NOW)
    assert used.claim("h", NOW + 301)
