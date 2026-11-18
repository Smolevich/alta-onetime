// Проверка письма ALTA «Izveštaj o stanju na računu» от altabanka@24x7.rs: подпись DKIM и разбор остатка.
// Всё в браузере проверяющего; ключ закреплён здесь, потому что DNS из браузера не прочитать,
// а при ликвидации банка запись может исчезнуть.

const KEY_SPKI =
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDF1Vgeomt5dEHKquNnTz+N2bJHanavv5FW68wid5i5fzP1i1Hm+DV+dsoSaKgEN+pWs6zAF+ODCpbs1/j6I7FO9fvMOngh2NCV7mYgh+0n3XnGMThgAzGupXNvLubccJhXisdZKtxZFO2/Sgm5PTYAj9Pmfhn2DUZ4Zh6f0q3ggQIDAQAB";
const DOMAIN = "24x7.rs";
const SELECTOR = "selector3";
const SENDER = "altabanka@24x7.rs";
export const THRESHOLD_EUR = 50000;
// Средний курс НБС, порядок величины стабилен годами; нужен только для динарного счёта.
export const RSD_PER_EUR = 117.2;

export class MailError extends Error {}

const latin1 = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return s;
};
const toBytes = (str) => Uint8Array.from(str, (c) => c.charCodeAt(0) & 0xff);
const b64 = (text) => Uint8Array.from(atob(text.replace(/\s+/g, "")), (c) => c.charCodeAt(0));

async function sha256b64(str) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", toBytes(str)));
  return btoa(String.fromCharCode(...d));
}

export function splitMessage(raw) {
  const text = raw.includes("\r\n") ? raw : raw.replace(/\n/g, "\r\n");
  const at = text.indexOf("\r\n\r\n");
  if (at < 0) throw new MailError("Это не похоже на письмо .eml.");
  const headerBlock = text.slice(0, at + 2);
  const headers = [];
  for (const line of headerBlock.split(/(?<=\r\n)/)) {
    if (/^[ \t]/.test(line) && headers.length) headers[headers.length - 1].raw += line;
    else if (line.trim()) headers.push({ name: line.slice(0, line.indexOf(":")).trim().toLowerCase(), raw: line });
  }
  return { headers, body: text.slice(at + 4) };
}

export function parseTags(value) {
  const tags = {};
  for (const part of value.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0) tags[part.slice(0, eq).trim()] = part.slice(eq + 1).replace(/\s+/g, "");
  }
  return tags;
}

function headerValue(h) {
  return h.raw.slice(h.raw.indexOf(":") + 1);
}

export function canonicalBodySimple(body) {
  const trimmed = body.replace(/(\r\n)*$/, "");
  return trimmed + "\r\n";
}

// h= берёт экземпляры заголовков снизу вверх (RFC 6376, 5.4.2).
function signedHeaders(headers, names) {
  const used = new Set();
  let out = "";
  for (const name of names) {
    for (let i = headers.length - 1; i >= 0; i--) {
      if (headers[i].name === name && !used.has(i)) {
        used.add(i);
        out += headers[i].raw;
        break;
      }
    }
  }
  return out;
}

function stripSignature(raw) {
  return raw.replace(/([;\s]b=)[^;]*/, "$1").replace(/\r\n$/, "");
}

export async function verifyDkim(raw, key = KEY_SPKI) {
  const { headers, body } = splitMessage(raw);
  const sigHeader = headers.find((h) => {
    if (h.name !== "dkim-signature") return false;
    const t = parseTags(headerValue(h));
    return t.d === DOMAIN && t.s === SELECTOR;
  });
  if (!sigHeader) throw new MailError("В письме нет подписи 24x7.rs — это не письмо ALTA или его переслали.");
  const tags = parseTags(headerValue(sigHeader));
  if (tags.a !== "rsa-sha256" || (tags.c || "simple/simple") !== "simple/simple" || tags.l) {
    throw new MailError("Подпись письма в неожиданном формате.");
  }
  const names = tags.h.toLowerCase().split(":");
  if (!names.includes("from")) throw new MailError("Подпись не покрывает отправителя.");
  const froms = headers.filter((h) => h.name === "from");
  if (froms.length !== 1) throw new MailError("В письме несколько отправителей.");
  if (!headerValue(froms[0]).toLowerCase().includes(`<${SENDER}>`)) {
    throw new MailError(`Письмо не от ${SENDER}.`);
  }
  const bodyHash = await sha256b64(canonicalBodySimple(body));
  if (bodyHash !== tags.bh) throw new MailError("Текст письма изменён: подпись не сходится.");
  const signed = signedHeaders(headers, names) + stripSignature(sigHeader.raw);
  const pub = await crypto.subtle.importKey("spki", b64(key), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, [
    "verify",
  ]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", pub, b64(tags.b), toBytes(signed));
  if (!ok) throw new MailError("Подпись письма не сходится.");
  const signedAt = Number(tags.t);
  const expires = tags.x ? Number(tags.x) : null;
  if (expires !== null && expires < signedAt) throw new MailError("Подпись письма испорчена (срок раньше даты).");
  return { body, headers, signedAt, expires };
}

function decodeQuotedPrintable(text) {
  const bytes = toBytes(text.replace(/=\r\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))));
  return new TextDecoder("utf-8").decode(bytes);
}

export function plainTextPart(body) {
  const m = body.match(/Content-Type:\s*text\/plain[^\r]*\r\n((?:[ \t]?[^\r]*\r\n)*?)\r\n([\s\S]*?)(\r\n--|$)/i);
  if (!m) throw new MailError("В письме нет текстовой части.");
  const qp = /Content-Transfer-Encoding:\s*quoted-printable/i.test(m[1]);
  return (qp ? decodeQuotedPrintable(m[2]) : m[2]).replace(/^﻿/, "");
}

export function parseAmount(text) {
  const m = text.match(/^(\d{1,3}(?:[.,\s]\d{3})*|\d+)([.,]\d{2})?$/);
  if (!m) return null;
  return Number(m[1].replace(/[.,\s]/g, "") + (m[2] ? "." + m[2].slice(1) : ""));
}

const lineBefore = (lines, marker) => {
  const i = lines.findIndex((l) => marker.test(l));
  return i > 0 ? lines[i - 1].trim() : "";
};

export function parseStatement(text) {
  const lines = text.split(/\r?\n/).map((l) => l.replace(/\s+$/, ""));
  const owner = lineBefore(lines, /\(Naziv vlasnika ra[cč]una\)/i);
  const account = lineBefore(lines, /\(Broj ra[cč]una\)/i);
  const at = lines.findIndex((l) => /Nov[oi]\s+(stanje|saldo)/i.test(l));
  if (!owner || at < 0) throw new MailError("Это не отчёт об остатке (Izveštaj o stanju na računu).");
  const row = lines.slice(at + 1, at + 4).join(" ");
  const date = (row.match(/\d{2}\.\d{2}\.\d{4}/) || [])[0];
  const numbers = row.replace(/\d{2}\.\d{2}\.\d{4}|\d{2}:\d{2}:\d{2}/g, " ").match(/\d[\d.,]*\d/g) || [];
  const amount = date && numbers.length ? parseAmount(numbers[numbers.length - 1]) : null;
  if (amount === null) throw new MailError("Не нашли сумму «Novo stanje» в письме.");
  const currency = (text.match(/\b(EUR|RSD)\b/) || [])[1] || null;
  return { owner, account, date, amount, currency };
}

export function verdict(amount, currency) {
  const asEur = amount >= THRESHOLD_EUR;
  const asRsd = amount / RSD_PER_EUR >= THRESHOLD_EUR;
  if (currency === "EUR") return { yes: asEur, sure: true };
  if (currency === "RSD") return { yes: asRsd, sure: true };
  return asEur === asRsd ? { yes: asEur, sure: true } : { yes: null, sure: false, asEur, asRsd };
}

export function maskAccount(account) {
  const digits = account.replace(/\D/g, "");
  return digits.length > 4 ? `…${digits.slice(-6, -2)}-${digits.slice(-2)}` : account;
}

export async function checkStatement(bytes) {
  const raw = latin1(new Uint8Array(bytes));
  const { body, signedAt, expires } = await verifyDkim(raw);
  const statement = parseStatement(plainTextPart(body));
  return { ...statement, signedAt, expires, verdict: verdict(statement.amount, statement.currency) };
}

const money = (n) => n.toLocaleString("ru-RU", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

export function verdictText(v, amount) {
  if (v.sure) return v.yes ? "Да, больше 50 000 €" : "Нет, меньше 50 000 €";
  const eur = Math.round(amount / RSD_PER_EUR).toLocaleString("ru-RU");
  return `Валюта в письме не указана: если счёт в евро — да, больше 50 000 €; если в динарах — это ≈ ${eur} €, меньше 50 000 €`;
}

/** Строки, которые увидит проверяющий: без номера счёта целиком и без остального письма. */
export function describe(r) {
  return [
    `владелец: ${r.owner}`,
    `счёт ${maskAccount(r.account)}`,
    `остаток на ${r.date}: ${money(r.amount)}${r.currency ? " " + r.currency : ""}`,
    verdictText(r.verdict, r.amount),
  ];
}
