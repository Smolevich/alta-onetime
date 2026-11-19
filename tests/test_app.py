import base64
import json
import os

import pytest
from starlette.testclient import TestClient

from alta_onetime.main import MAX_CIPHERTEXT, create_app, parse_recipients
from alta_onetime.store import MAX_ATTEMPTS, TTL_SECONDS, Store
from alta_onetime.tg import widget_hash

TOKEN = "123456:TEST-TOKEN"


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


RIGHT = os.urandom(32)
WRONG = os.urandom(32)
CIPHERTEXT = os.urandom(1000)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def events_path(tmp_path) -> str:
    return str(tmp_path / "events.jsonl")


def login(client: TestClient, username: str, tg_id: int = 9000001) -> None:
    fields = {"id": str(tg_id), "username": username, "auth_date": str(int(client.app_clock()))}
    params = {**fields, "hash": widget_hash(fields, TOKEN)}
    res = client.get("/check/api/tg-login", params=params, follow_redirects=False)
    assert res.status_code == 303 and "alta_check" in res.cookies


def make_client(clock: Clock, events_path: str) -> TestClient:
    c = TestClient(
        create_app(Store(clock=clock), events_path=events_path, bot_token=TOKEN), base_url="https://testserver"
    )
    c.app_clock = clock
    return c


@pytest.fixture
def client(clock: Clock, events_path: str) -> TestClient:
    c = make_client(clock, events_path)
    login(c, "Test_Reviewer")
    return c


def events(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def headers(**extra: str) -> dict[str, str]:
    base = {
        "X-Salt": b64(os.urandom(16)),
        "X-IV": b64(os.urandom(12)),
        "X-Verifier": b64(RIGHT),
        "X-To": "@Test_Reviewer",
        "X-Files": "2",
    }
    return {**base, **extra}


def upload(client: TestClient, body: bytes = CIPHERTEXT) -> str:
    res = client.post("/check/api/upload", content=body, headers=headers())
    assert res.status_code == 201
    return res.json()["id"]


def open_(client: TestClient, item_id: str, verifier: bytes = RIGHT):
    return client.post(f"/check/api/open/{item_id}", json={"v": b64(verifier)})


def test_open_returns_ciphertext(client):
    assert open_(client, upload(client)).content == CIPHERTEXT


def test_second_open_is_404(client):
    item_id = upload(client)
    open_(client, item_id)
    assert open_(client, item_id).status_code == 404


def test_meta_is_404_after_open(client):
    item_id = upload(client)
    open_(client, item_id)
    assert client.get(f"/check/api/meta/{item_id}").status_code == 404


def test_wrong_password_does_not_delete(client):
    item_id = upload(client)
    for _ in range(MAX_ATTEMPTS - 1):
        assert open_(client, item_id, WRONG).status_code == 403
    assert open_(client, item_id).content == CIPHERTEXT


def test_wrong_password_reports_attempts_left(client):
    assert open_(client, upload(client), WRONG).json()["left"] == MAX_ATTEMPTS - 1


def test_fifth_wrong_password_deletes(client):
    item_id = upload(client)
    for _ in range(MAX_ATTEMPTS):
        open_(client, item_id, WRONG)
    assert open_(client, item_id).status_code == 404


def test_unopened_expires_after_24h(client, clock):
    item_id = upload(client)
    clock.now += TTL_SECONDS
    login(client, "test_reviewer")
    assert open_(client, item_id).status_code == 404


def test_unopened_lives_just_under_24h(client, clock):
    item_id = upload(client)
    clock.now += TTL_SECONDS - 1
    login(client, "test_reviewer")
    assert open_(client, item_id).status_code == 200


def test_oversized_upload_rejected(client):
    res = client.post(
        "/check/api/upload",
        content=b"x" * (MAX_CIPHERTEXT + 1),
        headers=headers(),
    )
    assert res.status_code == 413


def test_upload_without_verifier_rejected(client):
    res = client.post("/check/api/upload", content=CIPHERTEXT, headers={"X-Salt": b64(os.urandom(16))})
    assert res.status_code == 400


@pytest.mark.parametrize("path", ["/check/", "/check/v/abc", "/check/api/meta/abc"])
def test_pages_are_noindex(client, path):
    assert "noindex" in client.get(path).headers["x-robots-tag"]


def test_upload_page_has_meta_robots(client):
    assert '<meta name="robots" content="noindex' in client.get("/check/").text


def test_open_with_garbage_body_is_400(client):
    res = client.post(f"/check/api/open/{upload(client)}", content=b"not json")
    assert res.status_code == 400


def test_sixty_megabytes_of_files_fit(client):
    assert upload(client, os.urandom(60 * 1024 * 1024 + 1000))


def test_pdfjs_module_served_as_javascript(client):
    assert "javascript" in client.get("/check/static/vendor/pdf.min.mjs").headers["content-type"]


def test_upload_without_recipient_rejected(client):
    res = client.post("/check/api/upload", content=CIPHERTEXT, headers=headers(**{"X-To": ""}))
    assert res.status_code == 400


def test_created_event_has_only_id_and_sizes(client, events_path):
    item_id = upload(client)
    created = [e for e in events(events_path) if e["event"] == "created"][0]
    assert {k: v for k, v in created.items() if k != "ts"} == {
        "event": "created",
        "id": item_id,
        "files": 2,
        "bytes": len(CIPHERTEXT),
    }


def test_event_log_has_no_tg_ids(client, events_path):
    item_id = upload(client)
    open_(client, item_id, WRONG)
    client.cookies.clear()
    login(client, "someone_else", tg_id=9000002)
    open_(client, item_id)
    text = open(events_path, encoding="utf-8").read()
    assert "9000001" not in text and "9000002" not in text


def test_nicks_appear_only_in_foreign_events(client, events_path):
    item_id = upload(client)
    open_(client, item_id, WRONG)
    client.cookies.clear()
    login(client, "someone_else", tg_id=9000002)
    open_(client, item_id)
    lines = [json.dumps(e) for e in events(events_path) if e["event"] != "foreign"]
    assert not any(n in line.lower() for line in lines for n in ("test_reviewer", "someone_else"))


def test_failed_login_logs_nothing_from_the_request(clock, events_path):
    c = make_client(clock, events_path)
    fields = {"id": "9000077", "username": "forger_nick", "auth_date": str(int(clock())), "hash": "00" * 32}
    c.get("/check/api/tg-login", params=fields, follow_redirects=False)
    text = open(events_path, encoding="utf-8").read()
    assert "9000077" not in text and "forger_nick" not in text


def test_log_info_does_not_echo_events(client, caplog):
    with caplog.at_level("DEBUG"):
        upload(client)
    assert "test_reviewer" not in caplog.text


def test_open_returns_sender_nick_from_session(client):
    res = open_(client, upload(client))
    assert res.headers["x-from"] == "test_reviewer"


def test_sender_header_cannot_override_telegram_username(client):
    res = client.post(
        "/check/api/upload", content=CIPHERTEXT, headers=headers(**{"X-From": "forged_sender"})
    )
    assert open_(client, res.json()["id"]).headers["x-from"] == "test_reviewer"


def test_fourth_active_link_is_429_with_reason(client):
    for _ in range(3):
        upload(client)
    res = client.post("/check/api/upload", content=CIPHERTEXT, headers=headers())
    assert (res.status_code, res.json()["error"]) == (429, "too_many_links")


def test_opening_a_link_frees_a_slot(client):
    ids = [upload(client) for _ in range(3)]
    open_(client, ids[0])
    assert upload(client)


def test_link_limit_is_per_sender(client):
    for _ in range(3):
        upload(client)
    client.cookies.clear()
    login(client, "another_sender", tg_id=9000003)
    assert upload(client)


def test_recipient_outside_allowlist_is_rejected(clock, events_path):
    c = TestClient(
        create_app(
            Store(clock=clock),
            events_path=events_path,
            bot_token=TOKEN,
            allowed_recipients=parse_recipients("@Alice_Rev, bob_rev"),
        ),
        base_url="https://testserver",
    )
    c.app_clock = clock
    login(c, "Test_Reviewer")
    res = c.post("/check/api/upload", content=CIPHERTEXT, headers=headers())
    assert res.status_code == 403


def test_recipient_inside_allowlist_is_accepted(clock, events_path):
    c = TestClient(
        create_app(
            Store(clock=clock),
            events_path=events_path,
            bot_token=TOKEN,
            allowed_recipients=parse_recipients("@Test_Reviewer"),
        ),
        base_url="https://testserver",
    )
    c.app_clock = clock
    login(c, "Test_Reviewer")
    assert upload(c)


def test_empty_allowlist_means_anyone():
    assert parse_recipients("") == frozenset()


def test_four_char_nick_is_rejected(client):
    res = client.post("/check/api/upload", content=CIPHERTEXT, headers=headers(**{"X-To": "abcd"}))
    assert res.status_code == 400


def test_meta_is_rate_limited_per_cf_ip(client):
    ip = {"CF-Connecting-IP": "203.0.113.7"}
    codes = [client.get("/check/api/meta/nope", headers=ip).status_code for _ in range(21)]
    assert codes[-1] == 429 and set(codes[:-1]) == {404}


def test_rate_limit_does_not_mix_different_ips(client):
    for _ in range(20):
        client.get("/check/api/meta/nope", headers={"CF-Connecting-IP": "203.0.113.7"})
    assert client.get("/check/api/meta/nope", headers={"CF-Connecting-IP": "203.0.113.8"}).status_code == 404


def test_open_is_rate_limited(client):
    codes = [client.post("/check/api/open/nope", json={"v": b64(RIGHT)}).status_code for _ in range(21)]
    assert codes[-1] == 429


def test_tg_login_is_rate_limited(clock, events_path):
    c = make_client(clock, events_path)
    codes = [c.get("/check/api/tg-login", follow_redirects=False).status_code for _ in range(21)]
    assert codes[-1] == 429


def test_rate_limit_recovers_with_time(client, clock):
    for _ in range(21):
        client.get("/check/api/meta/nope")
    clock.now += 60
    assert client.get("/check/api/meta/nope").status_code == 404


def test_tenth_upload_in_an_hour_passes_and_eleventh_is_429(client):
    for _ in range(10):
        item_id = upload(client)
        open_(client, item_id)
    assert client.post("/check/api/upload", content=CIPHERTEXT, headers=headers()).status_code == 429


def test_replayed_login_hash_does_not_set_session(clock, events_path):
    c = make_client(clock, events_path)
    fields = {"id": "9000001", "username": "test_reviewer", "auth_date": str(int(clock()))}
    params = {**fields, "hash": widget_hash(fields, TOKEN)}
    c.get("/check/api/tg-login", params=params, follow_redirects=False)
    c.cookies.clear()
    res = c.get("/check/api/tg-login", params=params, follow_redirects=False)
    assert "alta_check" not in res.cookies and c.get("/check/api/me").status_code == 401


@pytest.mark.parametrize("path", ["/check/", "/check/api/me", "/check/static/view.js"])
@pytest.mark.parametrize(
    "name,value",
    [
        ("strict-transport-security", "max-age=31536000"),
        ("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()"),
        ("cross-origin-resource-policy", "same-origin"),
    ],
)
def test_hardening_headers_everywhere(client, path, name, value):
    assert client.get(path).headers[name] == value


@pytest.mark.parametrize("path", ["/check/", "/check/api/me", "/check/static/view.js"])
def test_no_opener_policy(client, path):
    # COOP рвёт window.opener у popup oauth.telegram.org из iframe виджета: вход перестаёт работать.
    assert "cross-origin-opener-policy" not in client.get(path).headers


def test_static_is_cached_for_a_day(client):
    assert client.get("/check/static/view.js").headers["cache-control"] == "public, max-age=86400"


@pytest.mark.parametrize("path", ["/check/", "/check/v/abc", "/check/api/me"])
def test_pages_and_api_stay_no_store(client, path):
    assert client.get(path).headers["cache-control"] == "no-store"


def test_upload_without_login_rejected(clock, events_path):
    res = make_client(clock, events_path).post("/check/api/upload", content=CIPHERTEXT, headers=headers())
    assert res.status_code == 401


def test_open_without_login_rejected(client, clock, events_path):
    item_id = upload(client)
    assert open_(make_client(clock, events_path), item_id).status_code == 401


def test_other_telegram_user_gets_no_ciphertext(client):
    item_id = upload(client)
    client.cookies.clear()
    login(client, "someone_else", tg_id=9000002)
    res = open_(client, item_id)
    assert (res.status_code, res.json()["error"]) == (403, "other")


def test_other_telegram_user_is_told_whom_the_link_is_for(client):
    item_id = upload(client)
    client.cookies.clear()
    login(client, "someone_else", tg_id=9000002)
    assert open_(client, item_id).json()["to"] == "test_reviewer"


def test_foreign_event_names_recipient_and_reader(client, events_path):
    item_id = upload(client)
    client.cookies.clear()
    login(client, "someone_else", tg_id=9000002)
    open_(client, item_id)
    foreign = [e for e in events(events_path) if e["event"] == "foreign"]
    assert [(e["id"], e["to"], e["by"]) for e in foreign] == [(item_id, "test_reviewer", "someone_else")]


def test_other_telegram_user_does_not_spend_attempts(client):
    item_id = upload(client)
    client.cookies.clear()
    login(client, "someone_else", tg_id=9000002)
    for _ in range(MAX_ATTEMPTS + 1):
        open_(client, item_id)
    client.cookies.clear()
    login(client, "test_reviewer")
    assert open_(client, item_id).content == CIPHERTEXT


def test_forged_login_sets_no_session(clock, events_path):
    c = make_client(clock, events_path)
    fields = {"id": "1", "username": "test_reviewer", "auth_date": str(int(clock())), "hash": "00" * 32}
    c.get("/check/api/tg-login", params=fields, follow_redirects=False)
    assert c.get("/check/api/me").status_code == 401


def test_open_and_wrong_attempts_are_logged(client, events_path):
    item_id = upload(client)
    open_(client, item_id, WRONG)
    open_(client, item_id)
    assert [e["event"] for e in events(events_path) if e["event"] != "login"] == [
        "created",
        "wrong",
        "opened",
        "deleted",
    ]


def test_log_never_contains_ciphertext_or_verifier(client, events_path):
    item_id = upload(client)
    open_(client, item_id)
    text = open(events_path, encoding="utf-8").read()
    assert b64(CIPHERTEXT[:32]) not in text and b64(RIGHT) not in text


def test_logout_clears_session_cookie(client):
    res = client.post("/check/api/logout")
    assert res.status_code == 200
    assert 'alta_check=""' in res.headers["set-cookie"] or "Max-Age=0" in res.headers["set-cookie"]


def test_logout_ends_the_session(client):
    client.post("/check/api/logout")
    assert client.get("/check/api/me").status_code == 401


def restartable_client(clock: Clock, events_path: str, store_dir) -> TestClient:
    app = create_app(Store(clock=clock), events_path=events_path, bot_token=TOKEN, store_dir=str(store_dir))
    c = TestClient(app, base_url="https://testserver")
    c.app_clock = clock
    return c


def test_link_survives_restart(clock, events_path, tmp_path):
    with restartable_client(clock, events_path, tmp_path / "state") as before:
        login(before, "test_reviewer")
        item_id = upload(before)
    with restartable_client(clock, events_path, tmp_path / "state") as after:
        login(after, "test_reviewer")
        assert open_(after, item_id).content == CIPHERTEXT


def test_wrong_attempts_survive_restart(clock, events_path, tmp_path):
    with restartable_client(clock, events_path, tmp_path / "state") as before:
        login(before, "test_reviewer")
        item_id = upload(before)
        open_(before, item_id, WRONG)
    with restartable_client(clock, events_path, tmp_path / "state") as after:
        login(after, "test_reviewer")
        assert open_(after, item_id, WRONG).json()["left"] == MAX_ATTEMPTS - 2


def test_restored_link_does_not_come_back_after_crash(clock, events_path, tmp_path):
    with restartable_client(clock, events_path, tmp_path / "state") as before:
        login(before, "test_reviewer")
        item_id = upload(before)
    with restartable_client(clock, events_path, tmp_path / "state") as after:
        login(after, "test_reviewer")
        open_(after, item_id)
        # Второй процесс поднимается, не дождавшись штатной остановки первого, как после падения.
        with restartable_client(clock, events_path, tmp_path / "state") as after_crash:
            login(after_crash, "test_reviewer")
            assert open_(after_crash, item_id).status_code == 404


def test_expired_link_is_not_saved_on_restart(clock, events_path, tmp_path):
    with restartable_client(clock, events_path, tmp_path / "state") as before:
        login(before, "test_reviewer")
        item_id = upload(before)
        clock.now += TTL_SECONDS
    with restartable_client(clock, events_path, tmp_path / "state") as after:
        login(after, "test_reviewer")
        assert open_(after, item_id).status_code == 404
