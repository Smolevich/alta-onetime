import { b64url, EML, encryptBundleWithKey, generateLinkKey, isValidNick, normalizeNick, sniffType } from "./crypto.js?v=20261119a";
import { bindIndicator, nextPaint } from "./progress.js?v=20261119a";
import { checkStatement, describe } from "./dkim.js";
import { bindLogout, currentUser, loginConfig, loginProblem, mountBotLogin, mountWidget } from "./tglogin.js?v=20261119a";

const MAX_FILES = 5;
const MAX_TOTAL = 60 * 1024 * 1024;
const MAX_FILE = 30 * 1024 * 1024;
const $ = (id) => document.getElementById(id);
let sender = "";
const progress = bindIndicator($("progress"));

// fetch не отдаёт прогресс отправки, поэтому XHR: процент здесь настоящий (отправлено байт / всего).
function postBytes(url, headers, body, onPercent) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    xhr.upload.onprogress = (e) => e.lengthComputable && onPercent((e.loaded / e.total) * 100);
    xhr.onload = () => resolve({ status: xhr.status, ok: xhr.status >= 200 && xhr.status < 300, text: xhr.responseText });
    xhr.onerror = () => reject(new Error("Не получилось загрузить, попробуйте ещё раз."));
    xhr.send(body);
  });
}

function setStatus(text, isError = false) {
  $("status").textContent = text;
  $("status").className = isError ? "error" : "muted";
}

const mb = (n) => (n / 1024 / 1024).toFixed(1).replace(".", ",");

function selectionProblem(files) {
  if (!files.length) return "";
  if (files.length > MAX_FILES) return `Не больше ${MAX_FILES} файлов.`;
  const total = files.reduce((n, f) => n + f.size, 0);
  const big = files.find((f) => f.size > MAX_FILE);
  if (big) return `«${big.name}» — ${mb(big.size)} МБ, один файл может быть до 30 МБ.`;
  if (total > MAX_TOTAL) return `Вместе ${mb(total)} МБ — это больше 60 МБ.`;
  return "";
}

$("file").addEventListener("change", () => {
  const files = [...$("file").files];
  $("files").replaceChildren(
    ...files.map((f) => {
      const li = document.createElement("li");
      li.textContent = `${f.name} — ${f.size < 1024 * 1024 ? Math.ceil(f.size / 1024) + " КБ" : mb(f.size) + " МБ"}`;
      return li;
    }),
  );
  const problem = selectionProblem(files);
  setStatus(problem, Boolean(problem));
  $("send").disabled = !files.length || Boolean(problem);
});


async function readFile(f) {
  const bytes = await f.arrayBuffer();
  const isEml = /\.eml$/i.test(f.name);
  const type = isEml ? EML : sniffType(bytes);
  if (!type) throw new Error(`«${f.name}»: подходят только PDF, JPG, PNG и письмо .eml.`);
  let preview = null;
  if (isEml) {
    setStatus(`Проверяем подпись письма «${f.name}»…`);
    try {
      preview = describe(await checkStatement(bytes)).join(" · ");
    } catch (e) {
      throw new Error(`«${f.name}»: ${e.message}`);
    }
  }
  return { type, bytes, preview };
}

$("send").addEventListener("click", async () => {
  const picked = [...$("file").files];
  const nick = normalizeNick($("nick").value);
  const problem = selectionProblem(picked);
  if (problem) return setStatus(problem, true);
  if (!isValidNick(nick)) return setStatus("Укажите ник проверяющего в Telegram, например @nickname.", true);
  $("send").disabled = true;
  try {
    const files = [];
    for (const f of picked) files.push(await readFile(f));
    setStatus("");
    progress("encrypt");
    await nextPaint();
    const linkKey = generateLinkKey();
    const seconds = Number($("seconds").value);
    const { salt, iv, verifier, ciphertext } = await encryptBundleWithKey(files, seconds, linkKey, nick);
    progress("upload", 0);
    const res = await postBytes(
      "/check/api/upload",
      {
        "Content-Type": "application/octet-stream",
        "X-Salt": b64url(salt),
        "X-IV": b64url(iv),
        "X-Verifier": b64url(verifier),
        "X-To": nick,
        "X-Files": String(files.length),
      },
      ciphertext,
      (pct) => progress("upload", pct),
    );
    if (res.status === 401) throw new Error("Вход через Telegram истёк — обновите страницу и войдите снова.");
    if (res.status === 413) throw new Error("Файлы слишком большие.");
    if (res.status === 429) throw new Error("Слишком много ссылок или загрузок сразу: одновременно можно держать не больше трёх активных ссылок, а загрузок — десять в час. Подождите, пока ссылки откроют или они истекут.");
    if (res.status === 403) throw new Error("Этому получателю отправлять нельзя.");
    if (res.status === 503) throw new Error("Сервис сейчас переполнен, попробуйте через час.");
    if (!res.ok) throw new Error("Не получилось загрузить, попробуйте ещё раз.");
    const { id } = JSON.parse(res.text);
    progress("idle");
    $("link").textContent = `${location.origin}/check/v/${id}#${b64url(linkKey)}`;
    linkKey.fill(0);
    $("nick-out").textContent = `@${nick}`;
    $("preview").replaceChildren(
      ...files
        .filter((f) => f.preview)
        .map((f) => {
          const li = document.createElement("li");
          li.textContent = `Проверяющий увидит: ${f.preview}`;
          return li;
        }),
    );
    $("file").value = "";
    $("pick").hidden = true;
    $("done").hidden = false;
    setStatus("");
  } catch (e) {
    progress("idle");
    setStatus(e.message || "Ошибка", true);
    $("send").disabled = false;
  }
});

for (const btn of document.querySelectorAll("[data-copy]")) {
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($(btn.dataset.copy).textContent);
      const old = btn.textContent;
      btn.textContent = "Скопировано";
      setTimeout(() => (btn.textContent = old), 1500);
    } catch {
      getSelection().selectAllChildren($(btn.dataset.copy));
    }
  });
}

$("again").addEventListener("click", () => location.reload());

(async () => {
  const problem = loginProblem();
  sender = (await currentUser().catch(() => null)) || "";
  if (sender) {
    bindLogout($("logout"));
    $("whoami").textContent = `Вы вошли как @${sender}.`;
    $("pick").hidden = false;
    return;
  }
  $("login-msg").textContent = problem;
  $("login").hidden = false;
  const config = await loginConfig().catch(() => ({}));
  if (config.bot) mountBotLogin($("bot-login"), $("bot-link"), $("login-msg"), () => location.reload());
  mountWidget($("widget"), config.widget);
})();
