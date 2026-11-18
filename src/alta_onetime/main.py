"""Одноразовый просмотр документов: сервер хранит только шифротекст, ключ остаётся у людей."""

import asyncio
import base64
import binascii
import contextlib
import hmac
import json
import mimetypes
import os
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from alta_onetime.botlogin import NONCE_TTL as BOT_NONCE_TTL
from alta_onetime.botlogin import BotLogins, Status, challenge_for, start_payload
from alta_onetime.ratelimit import RateLimiter
from alta_onetime.store import MAX_ACTIVE_PER_SENDER, OpenResult, Store
from alta_onetime.tg import (
    SESSION_TTL,
    LoginError,
    TgUser,
    UsedHashes,
    make_session,
    read_session,
    session_key,
    verify_login,
)

PREFIX = "/check"
STATIC = Path(__file__).parent / "static"
MAX_FILES_BYTES = 60 * 1024 * 1024
# Сверх файлов — заголовок контейнера и тег GCM.
MAX_CIPHERTEXT = MAX_FILES_BYTES + 64 * 1024
SALT_LEN = 16
IV_LEN = 12
VERIFIER_LEN = 32
SWEEP_EVERY = 60

COOKIE = "alta_check"
CHALLENGE_COOKIE = "alta_login"
NEXT_PATH = re.compile(r"/check/(v/[A-Za-z0-9_-]{1,64})?")
CSP = (
    "default-src 'none'; script-src 'self' https://telegram.org; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; worker-src 'self'; frame-src https://oauth.telegram.org; object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}
STATIC_CACHE = "public, max-age=86400"

IP_BURST = 20
IP_WINDOW = 60.0
UPLOADS_PER_HOUR = 10
BOT_LOGINS_BURST = 10
BOT_LOGINS_WINDOW = 600.0
BOT_DONE = "Готово, вернитесь на страницу."
BOT_NO_USERNAME = "В вашем Telegram не задан username. Задайте его в настройках и попробуйте снова."
HOUR = 3600.0
# pdf.js — ES-модули .mjs; без JS-типа браузер их не исполнит (nosniff).
mimetypes.add_type("text/javascript", ".mjs")
NICK = re.compile(r"[a-z0-9_]{5,32}")
MAX_FILES = 5


def clean_nick(value: str | None) -> str | None:
    nick = (value or "").strip().lstrip("@").lower()
    return nick if NICK.fullmatch(nick) else None


def clean_count(value: str | None, upper: int) -> int | None:
    return int(value) if value and value.isdigit() and 1 <= int(value) <= upper else None


def parse_recipients(value: str | None) -> frozenset[str]:
    """Ники через запятую → множество; пустая строка — ограничения нет."""
    return frozenset(n for n in (clean_nick(part) for part in (value or "").split(",")) if n)


def client_ip(request: Request) -> str:
    return request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "")


class EventLog:
    """Append-only JSONL: тип события, время, id ссылки, числа — без ников, tg_id, содержимого, паролей."""

    def __init__(self, path: str | None) -> None:
        self.path = path

    def write(self, event: str, **fields: object) -> None:
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(line, ensure_ascii=False) + "\n")


def b64decode(value: str | None, length: int) -> bytes | None:
    """base64url без паддинга → байты нужной длины, иначе None."""
    if not value:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == length else None


def b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


async def read_capped(request: Request, limit: int) -> bytes | None:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            return None
    return bytes(body)


def error(message: str, status: int) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def create_app(
    store: Store | None = None,
    events_path: str | None = None,
    bot_token: str | None = None,
    allowed_recipients: frozenset[str] | None = None,
    login_bot: tuple[str, str, str] | None = None,
) -> Starlette:
    """login_bot — (токен, username, секрет вебхука) бота для входа по deep link; без него только виджет."""
    store = store or Store()
    if allowed_recipients is None:
        allowed_recipients = parse_recipients(os.environ.get("ALLOWED_RECIPIENTS"))
    used_hashes = UsedHashes()
    ip_limit = RateLimiter(IP_BURST, IP_WINDOW, store.clock)
    upload_limit = RateLimiter(UPLOADS_PER_HOUR, HOUR, store.clock)
    bot_start_limit = RateLimiter(BOT_LOGINS_BURST, BOT_LOGINS_WINDOW, store.clock)
    bot_logins = BotLogins(store.clock)

    def too_fast(request: Request) -> Response | None:
        return None if ip_limit.allow(client_ip(request)) else error("rate_limited", 429)
    events = EventLog(events_path or os.environ.get("EVENTS_LOG"))
    token = bot_token or os.environ.get("TG_BOT_TOKEN", "")
    if login_bot is None:
        names = ("LOGIN_BOT_TOKEN", "LOGIN_BOT_USERNAME", "LOGIN_WEBHOOK_SECRET")
        bot_token_, bot_name, bot_secret = (os.environ.get(k, "") for k in names)
        login_bot = (bot_token_, bot_name, bot_secret) if bot_token_ and bot_name and bot_secret else None
    key = session_key(token) if token else b""
    # Сессию подписывает тот же ключ, что и у виджета: кука одна, откуда бы ни пришёл вход.
    bot_username = login_bot[1].lstrip("@") if login_bot and key else ""
    webhook_secret = login_bot[2] if bot_username and login_bot else ""

    def set_session(response: Response, user: TgUser) -> None:
        response.set_cookie(
            COOKIE,
            make_session(user, key, store.clock()),
            max_age=SESSION_TTL,
            path=PREFIX,
            secure=True,
            httponly=True,
            samesite="strict",
        )

    def current_user(request: Request) -> TgUser | None:
        return read_session(request.cookies.get(COOKIE), key, store.clock()) if key else None

    async def tg_login(request: Request) -> Response:
        """Сюда виджет Telegram перенаправляет после входа (data-auth-url)."""
        if (limited := too_fast(request)) is not None:
            return limited
        fields = {k: v for k, v in request.query_params.items() if k != "next"}
        next_path = request.query_params.get("next", f"{PREFIX}/")
        if not NEXT_PATH.fullmatch(next_path):
            next_path = f"{PREFIX}/"
        if not token:
            return RedirectResponse(f"{next_path}#login=off", status_code=303)
        try:
            user = verify_login(fields, token, store.clock(), used_hashes)
        except LoginError as e:
            events.write("login_failed", reason=str(e))
            return RedirectResponse(f"{next_path}#login={e}", status_code=303)
        events.write("login")
        response = RedirectResponse(next_path, status_code=303)
        set_session(response, user)
        return response

    async def login_config(request: Request) -> Response:
        return JSONResponse({"bot": bot_username or None})

    async def bot_login_start(request: Request) -> Response:
        if not bot_username:
            return error("off", 404)
        if (limited := too_fast(request)) is not None:
            return limited
        if not bot_start_limit.allow(client_ip(request)):
            return error("rate_limited", 429)
        nonce = bot_logins.create()
        events.write("bot_login_started")
        response = JSONResponse({"nonce": nonce, "url": f"https://t.me/{bot_username}?start={nonce}"})
        response.set_cookie(
            CHALLENGE_COOKIE,
            challenge_for(nonce),
            max_age=int(BOT_NONCE_TTL),
            path=PREFIX,
            secure=True,
            httponly=True,
            samesite="strict",
        )
        return response

    async def bot_login_status(request: Request) -> Response:
        if not bot_username:
            return error("off", 404)
        if (limited := too_fast(request)) is not None:
            return limited
        nonce = request.query_params.get("n", "")
        status, user = bot_logins.take(nonce, request.cookies.get(CHALLENGE_COOKIE))
        if status is Status.PENDING:
            return JSONResponse({"status": "pending"}, status_code=202)
        if status is Status.GONE:
            return error("gone", 410)
        response = (
            error("no_username", 403) if status is Status.NO_USERNAME else JSONResponse({"status": "ok"})
        )
        response.delete_cookie(CHALLENGE_COOKIE, path=PREFIX, secure=True, httponly=True, samesite="strict")
        if status is Status.CONFIRMED and user is not None:
            events.write("login", via="bot")
            set_session(response, user)
        else:
            events.write("login_failed", reason="no_username", via="bot")
        return response

    async def bot_webhook(request: Request) -> Response:
        path_ok = bool(webhook_secret) and hmac.compare_digest(request.path_params["secret"], webhook_secret)
        header = request.headers.get("x-telegram-bot-api-secret-token", "")
        if not path_ok or not hmac.compare_digest(header, webhook_secret):
            events.write("webhook_rejected")
            return error("forbidden", 403)
        try:
            update = await request.json()
        except ValueError:
            return JSONResponse({})
        parsed = start_payload(update) if isinstance(update, dict) else None
        if parsed is None:
            return JSONResponse({})
        nonce, chat_id, tg_id, username = parsed
        if not bot_logins.confirm(nonce, tg_id, username):
            events.write("bot_login_unknown")
            return JSONResponse({})
        events.write("bot_login_confirmed")
        # Ответ прямо в теле вебхука: Telegram сам выполнит sendMessage, исходящих вызовов к API нет.
        text = BOT_DONE if username else BOT_NO_USERNAME
        return JSONResponse({"method": "sendMessage", "chat_id": chat_id, "text": text})

    async def me(request: Request) -> Response:
        user = current_user(request)
        if user is None:
            return error("login", 401)
        return JSONResponse({"username": user.username})

    async def logout(request: Request) -> Response:
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE, path=PREFIX, secure=True, httponly=True, samesite="strict")
        return response

    async def upload(request: Request) -> Response:
        user = current_user(request)
        if user is None:
            return error("login", 401)
        if not upload_limit.allow(str(user.id)):
            return error("rate_limited", 429)
        if store.active_for(user.id) >= MAX_ACTIVE_PER_SENDER:
            return error("too_many_links", 429)
        salt = b64decode(request.headers.get("x-salt"), SALT_LEN)
        iv = b64decode(request.headers.get("x-iv"), IV_LEN)
        verifier = b64decode(request.headers.get("x-verifier"), VERIFIER_LEN)
        to = clean_nick(request.headers.get("x-to"))
        files = clean_count(request.headers.get("x-files"), MAX_FILES)
        if salt is None or iv is None or verifier is None or to is None or files is None:
            return error("bad_request", 400)
        if allowed_recipients and to not in allowed_recipients:
            return error("recipient_not_allowed", 403)
        body = await read_capped(request, MAX_CIPHERTEXT)
        if body is None:
            return error("too_large", 413)
        if len(body) < 17:
            return error("bad_request", 400)
        store.sweep()
        if not store.has_room(len(body)):
            return error("full", 503)
        item_id = store.put(body, salt, iv, verifier, to, user.username, user.id)
        events.write("created", id=item_id, files=files, bytes=len(body))
        return JSONResponse({"id": item_id}, status_code=201)

    async def meta(request: Request) -> Response:
        if (limited := too_fast(request)) is not None:
            return limited
        item = store.peek(request.path_params["item_id"])
        if item is None:
            return error("gone", 404)
        return JSONResponse({"salt": b64encode(item.salt), "size": len(item.ciphertext)})

    async def open_item(request: Request) -> Response:
        if (limited := too_fast(request)) is not None:
            return limited
        item_id = request.path_params["item_id"]
        try:
            payload = await request.json()
        except ValueError:
            return error("bad_request", 400)
        verifier = b64decode(payload.get("v") if isinstance(payload, dict) else None, VERIFIER_LEN)
        if verifier is None:
            return error("bad_request", 400)
        user = current_user(request)
        if user is None:
            return error("login", 401)
        item = store.peek(item_id)
        if item is not None and item.to != user.username:
            events.write("foreign", id=item_id)
            return error("other", 403)
        opened = store.open(item_id, verifier)
        if opened.result is OpenResult.GONE:
            if opened.burned:
                events.write("wrong", id=item_id, left=0)
                events.write("deleted", id=item_id, reason="attempts")
            return error("gone", 404)
        if opened.result is OpenResult.WRONG:
            events.write("wrong", id=item_id, left=opened.attempts_left)
            return JSONResponse({"error": "wrong", "left": opened.attempts_left}, status_code=403)
        assert opened.item is not None
        events.write("opened", id=item_id)
        events.write("deleted", id=item_id, reason="opened")
        return Response(
            opened.item.ciphertext,
            media_type="application/octet-stream",
            headers={"X-IV": b64encode(opened.item.iv), "X-From": opened.item.sender},
        )

    async def upload_page(request: Request) -> Response:
        return FileResponse(STATIC / "upload.html")

    async def view_page(request: Request) -> Response:
        return FileResponse(STATIC / "view.html")

    async def to_slash(request: Request) -> Response:
        return RedirectResponse(f"{PREFIX}/", status_code=301)

    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.update(HEADERS)
        if request.url.path.startswith(f"{PREFIX}/static/") and response.status_code == 200:
            response.headers["Cache-Control"] = STATIC_CACHE
        return response

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async def sweeper() -> None:
            while True:
                await asyncio.sleep(SWEEP_EVERY)
                ip_limit.prune()
                upload_limit.prune()
                bot_start_limit.prune()
                bot_logins.prune()
                for item_id in store.sweep():
                    events.write("deleted", id=item_id, reason="expired")

        task = asyncio.create_task(sweeper())
        yield
        task.cancel()

    routes = [
        Route(PREFIX, to_slash),
        Route(f"{PREFIX}/", upload_page),
        Route(f"{PREFIX}/v/{{item_id}}", view_page),
        Route(f"{PREFIX}/api/upload", upload, methods=["POST"]),
        Route(f"{PREFIX}/api/tg-login", tg_login),
        Route(f"{PREFIX}/api/me", me),
        Route(f"{PREFIX}/api/login-config", login_config),
        Route(f"{PREFIX}/api/bot-login", bot_login_start, methods=["POST"]),
        Route(f"{PREFIX}/api/bot-login/status", bot_login_status),
        Route(f"{PREFIX}/api/tg-bot/{{secret}}", bot_webhook, methods=["POST"]),
        Route(f"{PREFIX}/api/logout", logout, methods=["POST"]),
        Route(f"{PREFIX}/api/meta/{{item_id}}", meta),
        Route(f"{PREFIX}/api/open/{{item_id}}", open_item, methods=["POST"]),
        Mount(f"{PREFIX}/static", StaticFiles(directory=STATIC), name="static"),
    ]
    return Starlette(
        routes=routes,
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=security_headers)],
        lifespan=lifespan,
    )
