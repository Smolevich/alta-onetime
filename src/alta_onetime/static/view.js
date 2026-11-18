import {
  b64url,
  decryptBundle,
  decryptBundleWithKey,
  fromB64url,
  linkVerifierFor,
  normalizePassword,
  verifierFor,
} from "./crypto.js?v=20261118b";
import { checkStatement, maskAccount, verdictText } from "./dkim.js";
import { stamp, watermarkText } from "./mark.js";
import { bindLogout, currentUser, loginConfig, loginProblem, mountBotLogin, mountWidget } from "./tglogin.js?v=20261118b";
import { bindIndicator, nextPaint } from "./progress.js?v=20261118b";
import { adoptLinkKey, dropLinkKey, keySlot } from "./linkkey.js?v=20261118b";
import * as pdfjs from "./vendor/pdf.min.mjs";

pdfjs.GlobalWorkerOptions.workerSrc = "/check/static/vendor/pdf.worker.min.mjs";
const MAX_RATIO = 1.5;
const $ = (id) => document.getElementById(id);
const itemId = location.pathname.split("/").filter(Boolean).pop();
let salt = null;
let me = "";
let progress = null;
const keySlotName = keySlot(itemId);
// Доступ к sessionStorage сам бросает исключение, если хранилище запрещено: тогда ключ живёт только в памяти.
const tabStorage = (() => {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
})();
let linkKey = adoptLinkKey(keySlotName, { location, history, storage: tabStorage });

function forgetLinkKey() {
  dropLinkKey(keySlotName, tabStorage);
  if (linkKey) linkKey.fill(0);
  linkKey = null;
}

function only(id) {
  for (const s of ["loading", "login", "ask", "show", "gone"]) $(s).hidden = s !== id;
}

function gone(why) {
  if (why) $("gone-why").textContent = why;
  only("gone");
}

async function init() {
  const res = await fetch(`/check/api/meta/${encodeURIComponent(itemId)}`, { cache: "no-store" });
  if (!res.ok) {
    forgetLinkKey();
    return gone();
  }
  salt = fromB64url((await res.json()).salt);
  const problem = loginProblem();
  me = (await currentUser().catch(() => null)) || "";
  if (!me) {
    $("login-msg").textContent = problem;
    only("login");
    const config = botMounted && widgetMounted ? {} : await loginConfig().catch(() => ({}));
    if (!botMounted && config.bot) {
      botMounted = true;
      mountBotLogin($("bot-login"), $("bot-link"), $("login-msg"), () => init());
    }
    if (!widgetMounted) {
      widgetMounted = true;
      mountWidget($("widget"), config.widget);
    }
    return;
  }
  bindLogout($("logout"));
  $("whoami").textContent = `Вы вошли как @${me}.`;
  only("ask");
  $("pw-block").hidden = Boolean(linkKey);
  (linkKey ? $("open") : $("pw")).focus();
}

let botMounted = false;
let widgetMounted = false;

const ratio = () => Math.min(window.devicePixelRatio || 1, MAX_RATIO);

function newCanvas(label) {
  const canvas = document.createElement("canvas");
  canvas.className = "page";
  canvas.dataset.page = label;
  $("doc").append(canvas);
  return canvas;
}

function sizeFor(canvas, w, h) {
  const width = Math.floor(($("doc").clientWidth || 640) * ratio());
  canvas.width = width;
  canvas.height = Math.floor((h / w) * width);
}

// Карточка письма рисуется в canvas вместе со знаком: в DOM нет текста, который можно «очистить».
function statementLines(r) {
  const amount = r.amount.toLocaleString("ru-RU", { minimumFractionDigits: 2 });
  return [
    ["Подпись банка проверена в вашем браузере: письмо от altabanka@24x7.rs не изменено.", 14, false],
    [verdictText(r.verdict, r.amount), 20, true],
    [`Владелец счёта: ${r.owner}`, 16, false],
    [`Счёт: ${maskAccount(r.account)}`, 16, false],
    [`Остаток «Novo stanje» на ${r.date}: ${amount}${r.currency ? " " + r.currency : ""}`, 16, false],
    [`Письмо подписано ${new Date(r.signedAt * 1000).toLocaleDateString("ru-RU")}.`, 14, false],
  ];
}

function wrap(ctx, text, maxWidth) {
  const out = [];
  let line = "";
  for (const word of text.split(" ")) {
    const next = line ? `${line} ${word}` : word;
    if (ctx.measureText(next).width > maxWidth && line) {
      out.push(line);
      line = word;
    } else line = next;
  }
  return [...out, line];
}

function drawCard(canvas, lines, tone) {
  const k = ratio();
  const width = Math.floor(($("doc").clientWidth || 640) * k);
  const pad = 18 * k;
  const ctx = canvas.getContext("2d");
  const font = (size, bold) => `${bold ? "bold " : ""}${size * k}px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`;
  const laid = lines.flatMap(([text, size, bold]) => {
    ctx.font = font(size, bold);
    return wrap(ctx, text, width - 2 * pad).map((t) => [t, size, bold]);
  });
  canvas.width = width;
  canvas.height = Math.ceil(pad * 2 + laid.reduce((h, [, size]) => h + size * 1.6 * k, 0));
  ctx.fillStyle = { ok: "#f1faf3", warn: "#fdf3f2", none: "#f4f5f8" }[tone];
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#1d1d1f";
  ctx.textBaseline = "top";
  let y = pad;
  for (const [text, size, bold] of laid) {
    ctx.font = font(size, bold);
    ctx.fillText(text, pad, y);
    y += size * 1.6 * k;
  }
}

// Готовим всё из расшифрованных байтов, после чего байты сразу обнуляются.
async function prepare(file, session) {
  if (file.type === "application/pdf") {
    const doc = await pdfjs.getDocument({ data: file.data.slice(), isEvalSupported: false }).promise;
    session.docs.push(doc);
    return { kind: "pdf", doc };
  }
  if (file.type === "message/rfc822") {
    try {
      const r = await checkStatement(file.data);
      return { kind: "card", lines: statementLines(r), tone: r.verdict.sure ? (r.verdict.yes ? "ok" : "warn") : "none" };
    } catch (e) {
      return { kind: "card", lines: [["Письмо не прошло проверку", 20, true], [e.message || "Ошибка проверки.", 16, false]], tone: "warn" };
    }
  }
  return { kind: "image", bitmap: await createImageBitmap(new Blob([file.data], { type: file.type })) };
}

async function render(item, index, text, session) {
  const k = ratio();
  if (item.kind === "image") {
    const canvas = newCanvas(`${index}`);
    sizeFor(canvas, item.bitmap.width, item.bitmap.height);
    canvas.getContext("2d").drawImage(item.bitmap, 0, 0, canvas.width, canvas.height);
    item.bitmap.close();
    stamp(canvas, text, k);
    return;
  }
  if (item.kind === "card") {
    const canvas = newCanvas(`${index}`);
    drawCard(canvas, item.lines, item.tone);
    stamp(canvas, text, k);
    return;
  }
  for (let n = 1; n <= item.doc.numPages && !session.over; n++) {
    const page = await item.doc.getPage(n);
    const base = page.getViewport({ scale: 1 });
    const canvas = newCanvas(`${index}:${n}/${item.doc.numPages}`);
    sizeFor(canvas, base.width, base.height);
    const viewport = page.getViewport({ scale: canvas.width / base.width });
    await page.render({ canvasContext: canvas.getContext("2d"), viewport }).promise;
    page.cleanup();
    if (session.over) return;
    stamp(canvas, text, k);
  }
}

async function show(bundle, nick, sender) {
  const session = { over: false, docs: [] };
  const items = [];
  try {
    for (const file of bundle.files) {
      items.push(await prepare(file, session).catch(() => ({ kind: "card", lines: [["Не получилось показать этот файл.", 16, true]], tone: "warn" })));
    }
  } finally {
    bundle.buffer.fill(0);
  }
  const text = watermarkText(sender, nick, new Date());
  only("show");
  // Отсчёт по часам, а не по числу тиков: в фоновой вкладке браузер замедляет setInterval.
  const deadline = Date.now() + bundle.seconds * 1000;
  const secondsLeft = () => Math.ceil((deadline - Date.now()) / 1000);
  const tick = () => ($("timer").textContent = `Документы исчезнут через ${secondsLeft()} с`);
  const step = () => {
    if (secondsLeft() > 0) return tick();
    clearInterval(timer);
    session.over = true;
    document.removeEventListener("visibilitychange", step);
    for (const doc of session.docs) doc.destroy();
    for (const c of $("doc").querySelectorAll("canvas")) {
      c.getContext("2d").clearRect(0, 0, c.width, c.height);
      c.width = c.height = 0;
    }
    $("doc").replaceChildren();
    gone("Время просмотра вышло, документы стёрты с экрана, на сервере их уже нет.");
  };
  tick();
  const timer = setInterval(step, 250);
  document.addEventListener("visibilitychange", step);
  for (let i = 0; i < items.length && !session.over; i++) {
    await render(items[i], i + 1, text, session).catch(() => {});
  }
}

function fail(text) {
  progress("idle");
  $("msg").className = "error";
  $("msg").textContent = text;
  $("open").disabled = false;
}

async function openDoc() {
  if ($("open").disabled) return;
  const nick = me;
  const password = linkKey ? "" : normalizePassword($("pw").value);
  if (!linkKey && !password) return fail("Введите пароль.");
  $("open").disabled = true;
  $("msg").textContent = "";
  // У беспарольной ссылки проверять нечего: PBKDF2 нет, верификатор считается мгновенно.
  progress(linkKey ? "decrypt" : "verify");
  await nextPaint();
  try {
    const verifier = linkKey ? await linkVerifierFor(linkKey, nick, salt) : await verifierFor(password, nick, salt);
    const res = await fetch(`/check/api/open/${encodeURIComponent(itemId)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ v: b64url(verifier) }),
    });
    if (res.status === 404) {
      forgetLinkKey();
      return gone();
    }
    if (res.status === 401) return location.reload();
    if (res.status === 429) return fail("Слишком много запросов. Подождите минуту и попробуйте ещё раз.");
    if (res.status === 403 && (await res.clone().json()).error === "other") {
      return fail("Эта ссылка для другого человека. Попытка не потрачена.");
    }
    if (res.status === 403 && linkKey) {
      return fail("Ссылка неполная или повреждена. Попросите отправителя прислать её целиком.");
    }
    if (res.status === 403) {
      const { left } = await res.json();
      return fail(`Неверный пароль. Осталось попыток: ${left}. После последней документ удалится.`);
    }
    if (!res.ok) throw new Error();
    progress("decrypt");
    await nextPaint();
    const iv = fromB64url(res.headers.get("X-IV"));
    const sender = res.headers.get("X-From") || "";
    const data = await res.arrayBuffer();
    const bundle = linkKey
      ? await decryptBundleWithKey(data, iv, salt, linkKey, nick)
      : await decryptBundle(data, iv, salt, password, nick);
    forgetLinkKey();
    $("pw").value = "";
    progress("idle");
    await show(bundle, nick, sender);
  } catch {
    fail("Не получилось открыть документ. Обновите страницу и попробуйте ещё раз.");
  }
}

progress = bindIndicator($("progress"));
$("open").addEventListener("click", openDoc);
for (const id of ["pw"]) $(id).addEventListener("keydown", (e) => e.key === "Enter" && openDoc());
$("doc").addEventListener("contextmenu", (e) => e.preventDefault());
$("doc").addEventListener("dragstart", (e) => e.preventDefault());
init().catch(() => gone("Не получилось связаться с сервером. Обновите страницу."));
