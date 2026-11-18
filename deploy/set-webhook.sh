#!/usr/bin/env bash
# Регистрирует вебхук бота входа: Telegram шлёт апдейты на /check/api/tg-bot/<секрет> с тем же секретом
# в заголовке X-Telegram-Bot-Api-Secret-Token. Токен и секрет берутся из Keychain и в вывод не попадают.
#   deploy/set-webhook.sh          зарегистрировать
#   deploy/set-webhook.sh info     показать состояние вебхука (без URL: в нём секрет)
set -euo pipefail
BASE=https://alta.smolevich.com/check/api/tg-bot
token=$(security find-generic-password -s alta-login-bot-token -w)
secret=$(security find-generic-password -s alta-login-webhook-secret -w)

if [ "${1:-}" = info ]; then
  curl -fsS "https://api.telegram.org/bot$token/getWebhookInfo" \
    | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; r.pop("url",None); print(json.dumps(r,ensure_ascii=False))'
  exit 0
fi

curl -fsS "https://api.telegram.org/bot$token/setWebhook" \
  --data-urlencode "url=$BASE/$secret" \
  --data-urlencode "secret_token=$secret" \
  --data-urlencode 'allowed_updates=["message"]' \
  --data-urlencode "drop_pending_updates=true" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r.get("ok"), r.get("description",""))'
