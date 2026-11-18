"""Вход через бота по deep link: браузер получает nonce, человек жмёт Start, вебхук связывает его с аккаунтом.

Виджет в чужом браузере просит телефон и код; здесь получатель только нажимает кнопку в своём Telegram.
Nonce живёт только в памяти: рестарт сервиса просто требует войти заново.
"""

import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum

from alta_onetime.tg import TgUser

NONCE_TTL = 5 * 60
# 24 байта = 192 бита; base64url даёт 32 символа — в пределах 64, которые Telegram пропускает в /start.
NONCE_BYTES = 24
START = "/start "


class Status(Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    NO_USERNAME = "no_username"
    GONE = "gone"


@dataclass
class Pending:
    created: float
    user: TgUser | None = None
    no_username: bool = False


def challenge_for(nonce: str) -> str:
    """Значение куки-челленджа: хеш nonce, чтобы сам nonce в куке не лежал."""
    return hashlib.sha256(nonce.encode()).hexdigest()


@dataclass
class BotLogins:
    clock: Callable[[], float]
    pending: dict[str, Pending] = field(default_factory=dict)

    def prune(self) -> None:
        now = self.clock()
        self.pending = {n: p for n, p in self.pending.items() if now - p.created < NONCE_TTL}

    def create(self) -> str:
        self.prune()
        nonce = secrets.token_urlsafe(NONCE_BYTES)
        self.pending[nonce] = Pending(self.clock())
        return nonce

    def confirm(self, nonce: str, tg_id: int, username: str | None) -> bool:
        """Связывает nonce с аккаунтом из /start; повторное подтверждение не перезаписывает первое."""
        self.prune()
        item = self.pending.get(nonce)
        if item is None or item.user is not None or item.no_username:
            return False
        if not username:
            item.no_username = True
            return True
        item.user = TgUser(tg_id, username.lower())
        return True

    def take(self, nonce: str, challenge: str | None) -> tuple[Status, TgUser | None]:
        """Статус для браузера; подтверждённый nonce отдаётся один раз и гасится."""
        self.prune()
        item = self.pending.get(nonce)
        if item is None or not challenge or not hmac.compare_digest(challenge_for(nonce), challenge):
            return Status.GONE, None
        if item.no_username:
            del self.pending[nonce]
            return Status.NO_USERNAME, None
        if item.user is None:
            return Status.PENDING, None
        del self.pending[nonce]
        return Status.CONFIRMED, item.user


def start_payload(update: Mapping[str, object]) -> tuple[str, int, int, str | None] | None:
    """Из апдейта Telegram: (nonce, chat_id, from.id, from.username) для «/start <nonce>», иначе None."""
    message = update.get("message")
    if not isinstance(message, dict):
        return None
    text = message.get("text")
    sender = message.get("from")
    chat = message.get("chat")
    if not isinstance(text, str) or not text.startswith(START):
        return None
    if not isinstance(sender, dict) or not isinstance(chat, dict):
        return None
    if not isinstance(sender.get("id"), int) or not isinstance(chat.get("id"), int):
        return None
    username = sender.get("username")
    nick = username if isinstance(username, str) else None
    return text[len(START) :].strip(), chat["id"], sender["id"], nick
