"""Вставляет в /etc/cloudflared/config.yml правило /check/ перед общим правилом alta.smolevich.com.

Печатает changed/unchanged. Правило по пути стоит выше правила по хосту:
cloudflared берёт первое совпадение.
"""

import sys
from pathlib import Path

CONFIG = Path(sys.argv[1] if len(sys.argv) > 1 else "/etc/cloudflared/config.yml")
ANCHOR = "  - hostname: alta.smolevich.com\n"
ROUTE = (
    "  - hostname: alta.smolevich.com\n"
    "    path: ^/check(/|$)\n"
    "    service: http://127.0.0.1:8103\n"
)
RULE = "  # Одноразовая проверка документов (alta-onetime.service).\n" + ROUTE


def with_rule(text: str) -> str | None:
    # Правило могли перенести в общий конфиг туннеля со своим комментарием: сверяем только маршрут.
    if ROUTE in text:
        return None
    if text.count(ANCHOR) != 1:
        raise SystemExit("anchor not found exactly once")
    return text.replace(ANCHOR, RULE + ANCHOR)


def without_rule(text: str) -> str | None:
    for rule in (RULE, ROUTE):
        if rule in text:
            return text.replace(rule, "")
    return None


if __name__ == "__main__":
    remove = len(sys.argv) > 2 and sys.argv[2] == "remove"
    text = CONFIG.read_text()
    new = without_rule(text) if remove else with_rule(text)
    if new is None:
        print("unchanged")
    else:
        CONFIG.write_text(new)
        print("changed")
