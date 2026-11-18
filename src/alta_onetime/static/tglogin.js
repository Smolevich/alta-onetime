// Вход через Telegram: основной путь — бот по deep link (человек жмёт Start в своём Telegram, страница
// опрашивает сервер), запасной — Login Widget, который перенаправляет на /check/api/tg-login.

const REASONS = {
  no_username: "В вашем Telegram не задан username. Задайте его в настройках Telegram (Настройки → Имя пользователя) и войдите снова.",
  expired: "Вход устарел, войдите ещё раз.",
  bad_signature: "Не получилось проверить вход через Telegram, попробуйте ещё раз.",
  off: "Вход через Telegram сейчас недоступен.",
  gone: "Вход устарел, нажмите кнопку ещё раз.",
};
const POLL_MS = 1500;

export async function currentUser() {
  const res = await fetch("/check/api/me", { cache: "no-store" });
  return res.ok ? (await res.json()).username : null;
}

export function loginProblem() {
  const m = location.hash.match(/login=([a-z_]+)/);
  if (!m) return "";
  history.replaceState(null, "", location.pathname);
  return REASONS[m[1]] || REASONS.bad_signature;
}

// Имя бота виджета приходит с сервера (TG_BOT_USERNAME): токен для проверки подписи — тоже там.
export function mountWidget(container, bot) {
  if (!bot) return;
  const s = document.createElement("script");
  s.async = true;
  s.src = "https://telegram.org/js/telegram-widget.js?22";
  s.dataset.telegramLogin = bot;
  s.dataset.size = "large";
  s.dataset.authUrl = `/check/api/tg-login?next=${encodeURIComponent(location.pathname)}`;
  container.append(s);
}

export function bindLogout(button) {
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await fetch("/check/api/logout", { method: "POST" });
    } finally {
      location.reload();
    }
  });
}

// { bot: бот входа по deep link или null, widget: бот Login Widget или null }
export async function loginConfig() {
  const res = await fetch("/check/api/login-config", { cache: "no-store" });
  return res.ok ? await res.json() : { bot: null, widget: null };
}

// Кнопка входа через бота. Окно Telegram открываем синхронно в клике, иначе браузер заблокирует всплывающее.
export function mountBotLogin(button, link, message, onDone) {
  let timer = null;
  let poll = null;
  const stop = () => {
    clearInterval(timer);
    timer = null;
    poll = null;
  };
  const fail = (text) => {
    stop();
    message.textContent = text;
    button.disabled = false;
  };
  button.hidden = false;
  button.addEventListener("click", async () => {
    button.disabled = true;
    message.textContent = "";
    const tab = window.open("about:blank", "_blank");
    try {
      const res = await fetch("/check/api/bot-login", { method: "POST" });
      if (res.status === 429) throw new Error("Слишком много попыток входа. Подождите несколько минут.");
      if (!res.ok) throw new Error(REASONS.off);
      const { nonce, url } = await res.json();
      if (tab) {
        tab.opener = null;
        tab.location.href = url;
      }
      link.href = url;
      link.parentElement.hidden = false;
      poll = async () => {
        if (document.hidden || !timer) return;
        const r = await fetch(`/check/api/bot-login/status?n=${encodeURIComponent(nonce)}`, { cache: "no-store" });
        // Параллельный опрос мог уже завершить вход: поздний ответ «nonce погашен» игнорируем.
        if (r.status === 202 || !timer) return;
        if (r.ok) {
          stop();
          link.parentElement.hidden = true;
          return onDone();
        }
        const why = r.status === 403 ? REASONS.no_username : REASONS.gone;
        fail(why);
      };
      clearInterval(timer);
      timer = setInterval(() => poll && poll().catch(() => {}), POLL_MS);
    } catch (e) {
      if (tab) tab.close();
      fail(e.message || REASONS.off);
    }
  });
  document.addEventListener("visibilitychange", () => {
    // Вернулись из Telegram — проверяем сразу, не дожидаясь следующего тика.
    if (!document.hidden && poll) poll().catch(() => {});
  });
}
