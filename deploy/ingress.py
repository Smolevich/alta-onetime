"""Вставляет в /etc/cloudflared/config.yml правило /check/ перед общим правилом alta.smolevich.com.

Печатает changed/unchanged. Правило по пути стоит выше правила по хосту:
cloudflared берёт первое совпадение.
"""

import sys
from pathlib import Path

CONFIG = Path(sys.argv[1] if len(sys.argv) > 1 else "/etc/cloudflared/config.yml")
ANCHOR = "  - hostname: alta.smolevich.com\n"
RULE = (
    "  # Временная одноразовая проверка документов (локальный репо alta-onetime, alta-onetime.service).\n"
    "  - hostname: alta.smolevich.com\n"
    "    path: ^/check(/|$)\n"
    "    service: http://127.0.0.1:8103\n"
)


def with_rule(text: str) -> str | None:
    if RULE in text:
        return None
    if text.count(ANCHOR) != 1:
        raise SystemExit("anchor not found exactly once")
    return text.replace(ANCHOR, RULE + ANCHOR)


def without_rule(text: str) -> str | None:
    return text.replace(RULE, "") if RULE in text else None


if __name__ == "__main__":
    remove = len(sys.argv) > 2 and sys.argv[2] == "remove"
    text = CONFIG.read_text()
    new = without_rule(text) if remove else with_rule(text)
    if new is None:
        print("unchanged")
    else:
        CONFIG.write_text(new)
        print("changed")
