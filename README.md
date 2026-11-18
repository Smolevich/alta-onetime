# alta-onetime — одноразовый показ документа

Код страницы https://alta.smolevich.com/check/. Вкладчик ALTA показывает проверяющему выписку или
справку (что у него в банке больше 50 000 €) так, чтобы документ открылся **один раз**, только
**нужному человеку** и **не остался** ни на сервере, ни у проверяющего файлом.

English summary — [below](#english).

## Как это работает

1. Отправитель входит через Telegram, выбирает до 5 файлов (PDF, JPG, PNG или письмо банка `.eml`)
   и пишет ник проверяющего.
2. **Браузер отправителя** генерирует случайный 256-битный ключ и шифрует файлы (AES-256-GCM).
   Ключ и проверочное значение для сервера выводятся из случайного ключа через HKDF-SHA-256;
   в HKDF входит ник получателя, поэтому с другим ником ключ не подходит
   ([`crypto.js`](src/alta_onetime/static/crypto.js)).
3. На сервер уходит только шифротекст, соль, IV и проверочное значение. Ключ остаётся в ссылке
   после `#` (`/check/v/<id>#<ключ>`) — эту часть ссылки браузер на сервер не отправляет.
4. Проверяющий открывает ссылку и входит через Telegram. Сервер отдаёт шифротекст, только если
   ник вошедшего совпадает с ником получателя и проверочное значение верное, — и **сразу удаляет**
   его у себя.
5. Расшифровка идёт в браузере проверяющего. Документ рисуется в `<canvas>` с водяным знаком
   «от @отправитель · для @получатель · время» на каждой странице, виден 90 секунд (или 60) и
   исчезает. Кнопки «скачать» нет.

## Что знает и хранит сервер

Хранит **только в памяти процесса**, на диск не пишет
([`store.py`](src/alta_onetime/store.py)); в systemd-юните запрещён своп (`MemorySwapMax=0`):

- шифротекст, соль, IV;
- SHA-256 от проверочного значения (не сам ключ и не проверочное значение);
- ник получателя, ник и Telegram-id отправителя — чтобы пустить только получателя, поставить
  отправителя в водяной знак и ограничить число ссылок;
- время создания и счётчик неверных попыток.

Запись удаляется:

- сразу после первого успешного открытия;
- после 5 неверных проверочных значений;
- через 24 часа, если ссылку не открыли;
- при любом перезапуске сервиса (всё в памяти).

Сервер **не видит** содержимого файлов, их типов и ключа. Он знает число файлов и общий размер
шифротекста.

Журнал событий ([`main.py`](src/alta_onetime/main.py), `EventLog`) — только тип события, время,
id ссылки и числа (сколько файлов, сколько байт, сколько попыток осталось). Ников, Telegram-id,
IP и содержимого в нём нет; журнал доступа uvicorn выключен (`--no-access-log`).

Ограничения: до 5 файлов, файл до 30 МБ, вместе до 60 МБ; у одного отправителя не больше 3
активных ссылок и 10 загрузок в час.

## Письмо банка `.eml`

Вместо скана можно загрузить письмо «Izveštaj o stanju na računu» от `altabanka@24x7.rs`.
Браузер проверяющего сам проверяет подпись DKIM банка и показывает только имя владельца счёта,
дату, остаток и ответ «больше 50 000 € или нет» ([`dkim.js`](src/alta_onetime/static/dkim.js)).
Изменённое письмо проверку не пройдёт.

## Чему всё-таки приходится доверять

- **Коду страницы.** JavaScript отдаёт тот же сервер. Злонамеренный владелец мог бы подменить
  скрипт и увести ключ. Поэтому ниже — как сверить то, что отдаёт прод, с этим репозиторием.
- **Проверяющему.** Скриншот или фото экрана не запретить. Водяной знак с обоими никами и
  временем показывает, откуда утёк снимок.
- **Telegram** — для входа. Пока ссылка жива, сервер знает, кто кому отправил документ.
- Перед сервером стоит Cloudflare (TLS заканчивается там). Он видит адрес без части после `#`
  и шифротекст.

Старые ссылки с паролем (PBKDF2-SHA-256, 600 000 итераций, затем тот же HKDF) ещё открываются,
но новые страница загрузки создаёт только с ключом в ссылке.

## Как проверить самому

1. Сверить скрипты на проде с репозиторием (пустой вывод — совпадают):

   ```sh
   for f in crypto.js upload.js view.js tglogin.js mark.js dkim.js progress.js; do
     curl -s "https://alta.smolevich.com/check/static/$f" | diff -q - "src/alta_onetime/static/$f" >/dev/null \
       || echo "differs: $f"
   done
   ```

2. В DevTools → Network при загрузке: тело `POST /check/api/upload` — двоичный шифротекст
   (`application/octet-stream`), в заголовках только соль, IV, проверочное значение, ник
   получателя и число файлов. При открытии ссылки в запросах нет части после `#`.
3. Тесты:

   ```sh
   uv run pytest
   node --test tests/js/*.test.mjs
   ```

## Запуск и деплой

Python 3.13, [uv](https://docs.astral.sh/uv/). Локально:

```sh
uv sync
TG_BOT_TOKEN=... TG_BOT_USERNAME=my_login_bot uv run uvicorn --factory alta_onetime.main:create_app --port 8103
# страница: http://127.0.0.1:8103/check/
```

Переменные окружения:

| Переменная | Зачем |
|---|---|
| `TG_BOT_TOKEN` | проверка подписи Telegram Login Widget; без неё вход выключен |
| `TG_BOT_USERNAME` | username того же бота (например `my_login_bot`) — его показывает виджет; у бота в @BotFather `/setdomain` должен указывать на ваш домен |
| `LOGIN_BOT_TOKEN`, `LOGIN_BOT_USERNAME`, `LOGIN_WEBHOOK_SECRET` | необязательный вход через бота по deep link |
| `EVENTS_LOG` | путь к журналу событий (JSONL); без него журнал не пишется |
| `ALLOWED_RECIPIENTS` | необязательный список ников получателей через запятую |

`deploy.sh` выкатывает код на сервер по SSH (хост — в `HOST` или в файле `.deploy-host`, он не в
репозитории), ставит systemd-юнит из `deploy/` и правило `/check/` в туннель cloudflared.
Токены берутся из macOS Keychain и передаются на сервер через stdin, в репозитории их нет.

---

## English

Source of https://alta.smolevich.com/check/ — a one-time viewer for bank documents.

- Files are encrypted **in the sender's browser** with AES-256-GCM. A random 256-bit key is
  generated there; HKDF-SHA-256 (with the recipient's Telegram username in `info`) derives the
  encryption key and a verifier. The key travels only in the link fragment (`#…`), which browsers
  never send to the server.
- The server keeps **in memory only** (no disk, swap disabled in the unit): ciphertext, salt, IV,
  the SHA-256 of the verifier, the recipient's username and the sender's username/id.
- A record is deleted right after the first successful open, after 5 wrong verifiers, after 24 h,
  or on any restart. Only the logged-in Telegram user whose username matches the recipient can
  fetch it.
- Decryption and rendering happen in the viewer's browser: canvas with a watermark naming sender,
  recipient and time, shown for 60–90 s, no download button.
- The event log holds event type, time, link id and counts — no usernames, ids, IPs or content.
- You still trust the JavaScript served by the site: compare it with this repo (see
  “Как проверить самому” above), and screenshots cannot be prevented, only traced by the watermark.

Run tests: `uv run pytest && node --test tests/js/*.test.mjs`.
