// Ключ беспарольной ссылки живёт во фрагменте адреса. Виджет Telegram кладёт location.href в return_to
// своего iframe, поэтому фрагмент снимаем при загрузке, раньше любого стороннего скрипта, а ключ держим
// в sessionStorage вкладки: вход через виджет уводит её на /check/api/tg-login и возвращает без фрагмента.
import { b64url, linkKeyFrom } from "./crypto.js?v=20261118b";

export const KEY_TTL_MS = 60 * 60 * 1000;

export const keySlot = (itemId) => `alta-check-key:${itemId}`;

function attempt(fn) {
  try {
    return fn();
  } catch {
    return null;
  }
}

function readSaved(storage, slot, now) {
  const saved = attempt(() => JSON.parse(storage.getItem(slot)));
  if (saved && saved.exp > now) return linkKeyFrom(saved.k);
  attempt(() => storage.removeItem(slot));
  return null;
}

// Фрагмент снимаем любой, кроме #login=… (ответ сервера о неудачном входе): обрезок ключа — тоже ключ.
export function adoptLinkKey(slot, { location, history, storage, now = Date.now() }) {
  const hash = location.hash || "";
  if (!hash || hash.startsWith("#login=")) return readSaved(storage, slot, now);
  history.replaceState(null, "", location.pathname + location.search);
  const key = linkKeyFrom(hash);
  if (!key) return readSaved(storage, slot, now);
  attempt(() => storage.setItem(slot, JSON.stringify({ k: b64url(key), exp: now + KEY_TTL_MS })));
  return key;
}

export function dropLinkKey(slot, storage) {
  attempt(() => storage.removeItem(slot));
}
