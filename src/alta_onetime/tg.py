"""Вход через Telegram Login Widget и короткая сессия в подписанной cookie.

Токен бота нужен только для проверки подписи виджета; к Bot API сервис не обращается.
"""

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass

AUTH_MAX_AGE = 300
SESSION_TTL = 30 * 60


@dataclass(frozen=True)
class TgUser:
    id: int
    username: str


class LoginError(Exception):
    """Подпись не сошлась, данные устарели или у пользователя нет username."""


def check_string(fields: Mapping[str, str]) -> str:
    return "\n".join(f"{k}={fields[k]}" for k in sorted(fields) if k != "hash")


def widget_hash(fields: Mapping[str, str], bot_token: str) -> str:
    secret = hashlib.sha256(bot_token.encode()).digest()
    return hmac.new(secret, check_string(fields).encode(), hashlib.sha256).hexdigest()


class UsedHashes:
    """Хеши виджета, уже принятые на вход: повтор той же ссылки входа не проходит."""

    def __init__(self) -> None:
        self.expires: dict[str, float] = {}

    def claim(self, value: str, now: float) -> bool:
        """True при первом предъявлении хеша; запись живёт, пока хеш не устареет сам."""
        self.expires = {h: t for h, t in self.expires.items() if t > now}
        if value in self.expires:
            return False
        self.expires[value] = now + AUTH_MAX_AGE
        return True


def verify_login(
    fields: Mapping[str, str], bot_token: str, now: float, used: UsedHashes | None = None
) -> TgUser:
    """Проверяет данные виджета по https://core.telegram.org/widgets/login#checking-authorization."""
    if not fields.get("hash") or not hmac.compare_digest(widget_hash(fields, bot_token), fields["hash"]):
        raise LoginError("bad_signature")
    auth_date = fields.get("auth_date", "")
    if not auth_date.isdigit() or now - int(auth_date) > AUTH_MAX_AGE:
        raise LoginError("expired")
    username = (fields.get("username") or "").lower()
    if not username:
        raise LoginError("no_username")
    if used is not None and not used.claim(fields["hash"], now):
        raise LoginError("replayed")
    return TgUser(int(fields["id"]), username)


def session_key(bot_token: str) -> bytes:
    return hmac.new(bot_token.encode(), b"alta-check/session/v1", hashlib.sha256).digest()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_session(user: TgUser, key: bytes, now: float) -> str:
    body = b64(json.dumps({"id": user.id, "u": user.username, "exp": int(now) + SESSION_TTL}).encode())
    return f"{body}.{b64(hmac.new(key, body.encode(), hashlib.sha256).digest())}"


def read_session(cookie: str | None, key: bytes, now: float) -> TgUser | None:
    if not cookie or cookie.count(".") != 1:
        return None
    body, sig = cookie.split(".")
    try:
        expected = hmac.new(key, body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, unb64(sig)):
            return None
        data = json.loads(unb64(body))
    except (binascii.Error, ValueError):
        return None
    if not isinstance(data, dict) or data.get("exp", 0) < now:
        return None
    return TgUser(int(data["id"]), str(data["u"]))
