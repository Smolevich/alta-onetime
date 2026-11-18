// Шифрование в браузере. Пароль может придумать человек, поэтому сначала медленный PBKDF2,
// затем из результата через HKDF — два независимых значения: ключ AES-GCM и верификатор для сервера.
// Ник получателя входит в ключ: с чужим ником пароль просто не подходит.
// Новые ссылки обходятся без пароля: случайный 256-битный ключ едет во фрагменте ссылки (#…), который
// браузер на сервер не отправляет. PBKDF2 ему не нужен, ник остаётся в HKDF info.

const ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const PASSWORD_LEN = 16;
export const MIN_PASSWORD = 10;
export const KDF_ITERATIONS = 600_000;
const ENC_INFO = "alta-check/enc/v2";
const VERIFY_INFO = "alta-check/verify/v2";
const LINK_ENC_INFO = "alta-check/enc/v3";
const LINK_VERIFY_INFO = "alta-check/verify/v3";
export const LINK_KEY_BYTES = 32;

export const TYPES = { 1: "application/pdf", 2: "image/png", 3: "image/jpeg", 4: "message/rfc822" };
export const EML = 4;
export const SHOW_CHOICES = [60, 90];
export const SHOW_DEFAULT = 90;

const enc = new TextEncoder();

export function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(text) {
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

export function generatePassword() {
  const out = [];
  const limit = 256 - (256 % ALPHABET.length);
  while (out.length < PASSWORD_LEN) {
    for (const b of crypto.getRandomValues(new Uint8Array(32))) {
      if (b < limit && out.length < PASSWORD_LEN) out.push(ALPHABET[b % ALPHABET.length]);
    }
  }
  return out.join("");
}

export function normalizePassword(text) {
  return text.trim();
}

export function normalizeNick(text) {
  return text.trim().replace(/^@+/, "").replace(/^(https?:\/\/)?t\.me\//i, "").toLowerCase();
}

export function isValidNick(nick) {
  return /^[a-z0-9_]{5,32}$/.test(nick);
}

export function sniffType(bytes) {
  const b = new Uint8Array(bytes.slice(0, 8));
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return 1;
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 2;
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 3;
  return 0;
}

async function splitKeys(material, hkdfSalt, encInfo, verifyInfo) {
  const base = await crypto.subtle.importKey("raw", material, "HKDF", false, ["deriveKey", "deriveBits"]);
  const hkdf = (info) => ({ name: "HKDF", hash: "SHA-256", salt: hkdfSalt, info: enc.encode(info) });
  const verifier = new Uint8Array(await crypto.subtle.deriveBits(hkdf(verifyInfo), base, 256));
  const key = await crypto.subtle.deriveKey(hkdf(encInfo), base, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  return { key, verifier };
}

async function deriveKeys(password, nick, salt, iterations) {
  const secret = await crypto.subtle.importKey("raw", enc.encode(`${password}\n${nick}`), "PBKDF2", false, [
    "deriveBits",
  ]);
  const master = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, secret, 256);
  return splitKeys(master, new Uint8Array(0), ENC_INFO, VERIFY_INFO);
}

function deriveLinkKeys(linkKey, nick, salt) {
  return splitKeys(linkKey, salt, `${LINK_ENC_INFO}\n${nick}`, `${LINK_VERIFY_INFO}\n${nick}`);
}

export function generateLinkKey() {
  return crypto.getRandomValues(new Uint8Array(LINK_KEY_BYTES));
}

// Ключ из фрагмента ссылки; null, если там не ключ (например, старая ссылка с паролем).
export function linkKeyFrom(fragment) {
  const text = (fragment || "").replace(/^#/, "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(text)) return null;
  const key = fromB64url(text);
  return key.length === LINK_KEY_BYTES ? key : null;
}

export async function linkVerifierFor(linkKey, nick, salt) {
  return (await deriveLinkKeys(linkKey, nick, salt)).verifier;
}

export async function verifierFor(password, nick, salt, iterations = KDF_ITERATIONS) {
  return (await deriveKeys(password, nick, salt, iterations)).verifier;
}

// Контейнер: 4 байта длины заголовка, JSON {s: секунды показа, f: [[тип, размер], …]}, затем файлы подряд.
// Ник отправителя сюда не кладём: его ставит сервер из сессии, клиентскому полю в водяном знаке веры нет.
// Всё это шифруется целиком: сервер не знает ни числа файлов, ни их типов.
export function pack(files, seconds) {
  const meta = { s: seconds, f: files.map((f) => [f.type, f.bytes.byteLength]) };
  const header = enc.encode(JSON.stringify(meta));
  const total = 4 + header.length + files.reduce((n, f) => n + f.bytes.byteLength, 0);
  const out = new Uint8Array(total);
  new DataView(out.buffer).setUint32(0, header.length);
  out.set(header, 4);
  let at = 4 + header.length;
  for (const f of files) {
    out.set(new Uint8Array(f.bytes), at);
    at += f.bytes.byteLength;
  }
  return out;
}

export function unpack(plain) {
  const len = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
  const header = JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + len)));
  let at = 4 + len;
  const files = header.f.map(([type, size]) => {
    const data = plain.subarray(at, at + size);
    at += size;
    return { type: TYPES[type], data };
  });
  const seconds = SHOW_CHOICES.includes(header.s) ? header.s : SHOW_DEFAULT;
  return { seconds, files };
}

export async function encryptBundle(files, seconds, password, nick, iterations = KDF_ITERATIONS) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const { key, verifier } = await deriveKeys(password, nick, salt, iterations);
  const plain = pack(files, seconds);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  plain.fill(0);
  return { salt, iv, verifier, ciphertext };
}

// Беспарольный вариант: тот же контейнер и тот же протокол с сервером (соль, IV, верификатор).
export async function encryptBundleWithKey(files, seconds, linkKey, nick) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const { key, verifier } = await deriveLinkKeys(linkKey, nick, salt);
  const plain = pack(files, seconds);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  plain.fill(0);
  return { salt, iv, verifier, ciphertext };
}

export async function decryptBundleWithKey(ciphertext, iv, salt, linkKey, nick) {
  const { key } = await deriveLinkKeys(linkKey, nick, salt);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
  return { ...unpack(plain), buffer: plain };
}

export async function decryptBundle(ciphertext, iv, salt, password, nick, iterations = KDF_ITERATIONS) {
  const { key } = await deriveKeys(password, nick, salt, iterations);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
  return { ...unpack(plain), buffer: plain };
}
