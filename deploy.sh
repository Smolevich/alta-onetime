#!/usr/bin/env bash
# Деплой на сервер: код → /opt/alta-onetime, systemd-юнит, правило /check/ в туннеле cloudflared.
#   ./deploy.sh           выкатить
#   ./deploy.sh log [N]   последние N событий (по умолчанию 50): создана / открыта / неверный пароль
#   ./deploy.sh remove    остановить сервис, снять правило туннеля, удалить код
# SSH-хост сервера: переменная HOST или первая строка файла .deploy-host (он в .gitignore —
# имя внутреннего сервера в публичный репозиторий не попадает).
set -euo pipefail
cd "$(dirname "$0")"
HOST=${HOST:-$(head -n1 .deploy-host 2>/dev/null || true)}
: "${HOST:?задайте HOST=<ssh-хост> или положите его в .deploy-host}"
DIR=/opt/alta-onetime

check_public() {
  for p in / /account/stats "$@"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "https://alta.smolevich.com$p")
    echo "$p -> $code"
    [ "$code" = 200 ] || return 1
  done
}

# Правка конфига туннеля с проверкой и откатом; рестарт только если правило поменялось.
apply_ingress() {
  ssh "$HOST" "set -e
    cp /etc/cloudflared/config.yml /etc/cloudflared/config.yml.bak-onetime
    res=\$(python3 $2 /etc/cloudflared/config.yml $1)
    echo ingress: \$res
    if [ \"\$res\" = changed ]; then
      if ! cloudflared tunnel --config /etc/cloudflared/config.yml ingress validate; then
        cp /etc/cloudflared/config.yml.bak-onetime /etc/cloudflared/config.yml; exit 1
      fi
      systemctl restart cloudflared
      sleep 5
    fi
    cloudflared tunnel --config /etc/cloudflared/config.yml ingress rule https://alta.smolevich.com/check/"
}

if [ "${1:-}" = log ]; then
  ssh "$HOST" "tail -n ${2:-50} /var/log/alta-onetime/events.jsonl"
  exit 0
fi

if [ "${1:-}" = remove ]; then
  scp -q deploy/ingress.py "$HOST:/tmp/onetime-ingress.py"
  apply_ingress remove /tmp/onetime-ingress.py
  ssh "$HOST" "systemctl disable --now alta-onetime.service || true
    rm -f /etc/systemd/system/alta-onetime.service /etc/logrotate.d/alta-onetime; systemctl daemon-reload; rm -rf $DIR /tmp/onetime-ingress.py /var/log/alta-onetime"
  check_public
  exit 0
fi

uv run pytest -q
node --test tests/js/*.test.mjs >/dev/null
echo "before:"; check_public

rsync -az --delete --exclude .venv --exclude .python --exclude __pycache__ --exclude .env \
  pyproject.toml uv.lock src deploy "$HOST:$DIR/"
# Токен бота виджета — только для проверки подписи входа; из Keychain по stdin, в вывод не попадает.
# Бот входа по deep link (LOGIN_*) необязателен: пока его записей в Keychain нет, сервис работает с виджетом.
keychain() { security find-generic-password -s "$1" -w 2>/dev/null || true; }
widget_token=$(security find-generic-password -s telegram-bot-token -w)
{
  printf 'TG_BOT_TOKEN=%s\n' "$widget_token"
  login_token=$(keychain alta-login-bot-token)
  login_name=$(keychain alta-login-bot-username)
  login_secret=$(keychain alta-login-webhook-secret)
  if [ -n "$login_token" ] && [ -n "$login_name" ] && [ -n "$login_secret" ]; then
    printf 'LOGIN_BOT_TOKEN=%s\nLOGIN_BOT_USERNAME=%s\nLOGIN_WEBHOOK_SECRET=%s\n' "$login_token" "$login_name" "$login_secret"
  fi
} | ssh "$HOST" "set -e; umask 077; cat > $DIR/.env.tmp; mv $DIR/.env.tmp $DIR/.env"
echo "login bot: $(ssh "$HOST" "grep -q '^LOGIN_BOT_TOKEN=' $DIR/.env && echo on || echo off")"
# Интерпретатор лежит в $DIR/.python: пользователь сервиса не читает /root, где uv держит его по умолчанию.
ssh "$HOST" "set -e; cd $DIR
  # macOS-rsync не знает --chown: владельца ставим уже на сервере.
  chown -R root:root pyproject.toml uv.lock src deploy
  chmod 755 $DIR
  export UV_PYTHON_INSTALL_DIR=$DIR/.python
  case \$(readlink -f .venv/bin/python 2>/dev/null) in $DIR/*) ;; *) rm -rf .venv ;; esac
  uv sync --frozen --no-dev -q
  chmod -R go+rX $DIR/.python $DIR/.venv
  install -m 644 deploy/alta-onetime.service /etc/systemd/system/alta-onetime.service
  install -m 644 deploy/alta-onetime.logrotate /etc/logrotate.d/alta-onetime
  systemctl daemon-reload
  systemctl enable -q alta-onetime.service
  systemctl restart alta-onetime.service
  # Файл мог остаться от прежнего запуска с правами 644.
  chmod 640 /var/log/alta-onetime/events.jsonl 2>/dev/null || true
  for i in 1 2 3 4 5 6 7 8 9 10; do curl -fs -o /dev/null http://127.0.0.1:8103/check/ && break; sleep 1; done
  curl -fs -o /dev/null http://127.0.0.1:8103/check/ && echo local ok"
apply_ingress add $DIR/deploy/ingress.py
echo "after:"; check_public /check/ /check/static/view.js
