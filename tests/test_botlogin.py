import json

import pytest
from starlette.testclient import TestClient

from alta_onetime.botlogin import NONCE_TTL
from alta_onetime.main import create_app
from alta_onetime.store import Store

TOKEN = "123456:TEST-TOKEN"
BOT = ("654321:LOGIN-BOT", "alta_login_bot", "hook-secret-1")
HOOK = f"/check/api/tg-bot/{BOT[2]}"


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def events_path(tmp_path) -> str:
    return str(tmp_path / "events.jsonl")


def make_client(clock: Clock, events_path: str, login_bot=BOT) -> TestClient:
    app = create_app(Store(clock=clock), events_path=events_path, bot_token=TOKEN, login_bot=login_bot)
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def client(clock: Clock, events_path: str) -> TestClient:
    return make_client(clock, events_path)


def start(client: TestClient) -> str:
    res = client.post("/check/api/bot-login")
    assert res.status_code == 200
    return res.json()["nonce"]


def press_start(client: TestClient, nonce: str, username: str | None = "Test_Reviewer") -> dict:
    sender = {"id": 9000001, "is_bot": False, **({"username": username} if username else {})}
    update = {"update_id": 1, "message": {"text": f"/start {nonce}", "from": sender, "chat": {"id": 9000001}}}
    res = client.post(HOOK, json=update, headers={"X-Telegram-Bot-Api-Secret-Token": BOT[2]})
    assert res.status_code == 200
    return res.json()


def status(client: TestClient, nonce: str):
    return client.get("/check/api/bot-login/status", params={"n": nonce})


def test_start_returns_deep_link_with_long_nonce(client):
    body = client.post("/check/api/bot-login").json()
    assert body["url"] == f"https://t.me/alta_login_bot?start={body['nonce']}" and len(body["nonce"]) >= 22


def test_pending_until_bot_confirms(client):
    nonce = start(client)
    assert status(client, nonce).status_code == 202


def test_confirmed_nonce_gives_session(client):
    nonce = start(client)
    press_start(client, nonce)
    assert status(client, nonce).status_code == 200
    assert client.get("/check/api/me").json() == {"username": "test_reviewer"}


def test_bot_replies_in_webhook_response(client):
    reply = press_start(client, start(client))
    assert (reply["method"], reply["chat_id"]) == ("sendMessage", 9000001)


def test_nonce_is_single_use(client):
    nonce = start(client)
    press_start(client, nonce)
    status(client, nonce)
    assert status(client, nonce).status_code == 410


def test_second_start_does_not_rebind_nonce(client):
    nonce = start(client)
    press_start(client, nonce, "first_user")
    press_start(client, nonce, "intruder_x")
    status(client, nonce)
    assert client.get("/check/api/me").json() == {"username": "first_user"}


def test_nonce_expires(client, clock):
    nonce = start(client)
    clock.now += NONCE_TTL + 1
    press_start(client, nonce)
    assert status(client, nonce).status_code == 410


def test_no_session_without_challenge_cookie(client):
    nonce = start(client)
    press_start(client, nonce)
    other = TestClient(client.app, base_url="https://testserver")
    assert (status(other, nonce).status_code, other.get("/check/api/me").status_code) == (410, 401)


def test_user_without_username_gets_no_session(client):
    nonce = start(client)
    press_start(client, nonce, None)
    assert (status(client, nonce).json(), client.get("/check/api/me").status_code) == ({"error": "no_username"}, 401)


@pytest.mark.parametrize(
    ("path", "header"),
    [(HOOK, None), (HOOK, "wrong"), ("/check/api/tg-bot/wrong", BOT[2])],
)
def test_webhook_without_secret_is_forbidden(client, path, header):
    headers = {"X-Telegram-Bot-Api-Secret-Token": header} if header else {}
    assert client.post(path, json={}, headers=headers).status_code == 403


def test_start_is_rate_limited(client):
    codes = [client.post("/check/api/bot-login").status_code for _ in range(12)]
    assert codes[-1] == 429


def test_without_env_bot_button_is_hidden(clock, events_path):
    c = make_client(clock, events_path, login_bot=None)
    assert (c.get("/check/api/login-config").json(), c.post("/check/api/bot-login").status_code) == (
        {"bot": None},
        404,
    )


def test_with_env_config_names_bot(client):
    assert client.get("/check/api/login-config").json() == {"bot": "alta_login_bot"}


def test_log_has_no_nonce_or_nick(client, events_path):
    nonce = start(client)
    press_start(client, nonce)
    status(client, nonce)
    with open(events_path, encoding="utf-8") as f:
        text = f.read()
    assert nonce not in text and "test_reviewer" not in text.lower() and json.loads(text.splitlines()[-1])
