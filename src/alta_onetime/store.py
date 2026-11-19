"""Хранилище шифротекстов в памяти: одноразовая выдача, лимит попыток, срок жизни.

Содержимое и пароли сюда не попадают: только шифротекст, соль, IV и хеш верификатора.
На диск записи попадают только на время перезапуска сервиса (save_items / load_items).
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

TTL_SECONDS = 24 * 3600
MAX_ATTEMPTS = 5
MAX_TOTAL_BYTES = 500 * 1024 * 1024
MAX_ITEMS = 300
MAX_ACTIVE_PER_SENDER = 3


@dataclass
class Item:
    ciphertext: bytes
    salt: bytes
    iv: bytes
    verifier_hash: bytes
    created: float
    to: str = ""
    sender: str = ""
    sender_id: int = 0
    attempts_left: int = MAX_ATTEMPTS


class OpenResult(Enum):
    OK = "ok"
    WRONG = "wrong"
    GONE = "gone"


@dataclass
class Opened:
    result: OpenResult
    item: Item | None = None
    attempts_left: int = 0
    burned: bool = False


def hash_verifier(verifier: bytes) -> bytes:
    return hashlib.sha256(verifier).digest()


@dataclass
class Store:
    clock: Callable[[], float] = time.time
    items: dict[str, Item] = field(default_factory=dict)

    def total_bytes(self) -> int:
        return sum(len(i.ciphertext) for i in self.items.values())

    def sweep(self) -> list[str]:
        """Удаляет просроченные; возвращает их id."""
        now = self.clock()
        expired = [k for k, v in self.items.items() if now - v.created >= TTL_SECONDS]
        for k in expired:
            del self.items[k]
        return expired

    def has_room(self, size: int) -> bool:
        return len(self.items) < MAX_ITEMS and self.total_bytes() + size <= MAX_TOTAL_BYTES

    def active_for(self, sender_id: int) -> int:
        self.sweep()
        return sum(1 for i in self.items.values() if i.sender_id == sender_id)

    def put(
        self,
        ciphertext: bytes,
        salt: bytes,
        iv: bytes,
        verifier: bytes,
        to: str = "",
        sender: str = "",
        sender_id: int = 0,
    ) -> str:
        item_id = secrets.token_urlsafe(16)
        item = Item(ciphertext, salt, iv, hash_verifier(verifier), self.clock(), to, sender, sender_id)
        self.items[item_id] = item
        return item_id

    def peek(self, item_id: str) -> Item | None:
        self.sweep()
        return self.items.get(item_id)

    def open(self, item_id: str, verifier: bytes) -> Opened:
        """Отдаёт и сразу удаляет при верном верификаторе; после MAX_ATTEMPTS ошибок удаляет."""
        item = self.peek(item_id)
        if item is None:
            return Opened(OpenResult.GONE)
        if hmac.compare_digest(hash_verifier(verifier), item.verifier_hash):
            del self.items[item_id]
            return Opened(OpenResult.OK, item)
        item.attempts_left -= 1
        if item.attempts_left <= 0:
            del self.items[item_id]
            return Opened(OpenResult.GONE, burned=True)
        return Opened(OpenResult.WRONG, attempts_left=item.attempts_left)


INDEX = "items.json"
ITEM_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
BYTES_FIELDS = ("salt", "iv", "verifier_hash")


def item_to_json(item: Item) -> dict[str, object]:
    fields = asdict(item)
    del fields["ciphertext"]
    return {**fields, **{k: base64.b64encode(fields[k]).decode() for k in BYTES_FIELDS}}


def item_from_json(fields: dict, ciphertext: bytes) -> Item:
    raw = {k: base64.b64decode(fields[k]) for k in BYTES_FIELDS}
    return Item(**{**fields, **raw, "ciphertext": ciphertext})


def save_items(items: dict[str, Item], directory: Path) -> None:
    """Пишет записи в каталог: шифротекст — файлом на запись, остальное — одним items.json.

    items.json пишется последним и атомарно: без него каталог считается пустым.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for item_id, item in items.items():
        (directory / f"{item_id}.bin").write_bytes(item.ciphertext)
    index = {item_id: item_to_json(item) for item_id, item in items.items()}
    tmp = directory / f"{INDEX}.tmp"
    tmp.write_text(json.dumps(index), encoding="utf-8")
    os.replace(tmp, directory / INDEX)


def load_items(directory: Path) -> dict[str, Item]:
    """Читает то, что записал save_items, и сразу стирает файлы.

    Стирание обязательно: иначе запись, открытая после загрузки, воскресла бы при следующем старте.
    """
    if not directory.is_dir():
        return {}
    index_path = directory / INDEX
    index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else {}
    items = {}
    for item_id, fields in index.items():
        blob = directory / f"{item_id}.bin"
        if ITEM_ID.fullmatch(item_id) and blob.exists():
            items[item_id] = item_from_json(fields, blob.read_bytes())
    for leftover in directory.iterdir():
        if leftover.is_file():
            leftover.unlink()
    return items
