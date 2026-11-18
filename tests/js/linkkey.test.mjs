import assert from "node:assert/strict";
import { test } from "node:test";
import { b64url, generateLinkKey } from "../../src/alta_onetime/static/crypto.js?v=20261118b";
import { adoptLinkKey, dropLinkKey, KEY_TTL_MS, keySlot } from "../../src/alta_onetime/static/linkkey.js?v=20261118b";

const SLOT = keySlot("abc");
const NOW = 1_700_000_000_000;

function fakeStorage() {
  const data = new Map();
  return {
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => data.set(k, String(v)),
    removeItem: (k) => data.delete(k),
    get size() {
      return data.size;
    },
  };
}

// Адрес вкладки: replaceState меняет его так же, как браузер, — путь без фрагмента.
function fakeTab(hash) {
  const location = { pathname: "/check/v/abc", search: "", hash };
  const history = {
    replaceState: (_s, _t, url) => {
      const at = url.indexOf("#");
      location.hash = at < 0 ? "" : url.slice(at);
    },
  };
  return { location, history };
}

const href = ({ location }) => `${location.pathname}${location.search}${location.hash}`;

test("on page load the key leaves the address and is kept in tab storage", () => {
  const key = generateLinkKey();
  const tab = fakeTab(`#${b64url(key)}`);
  const storage = fakeStorage();
  const got = adoptLinkKey(SLOT, { ...tab, storage, now: NOW });
  assert.deepEqual(
    { hash: tab.location.hash, href: href(tab), key: got, saved: JSON.parse(storage.getItem(SLOT)).k },
    { hash: "", href: "/check/v/abc", key, saved: b64url(key) },
  );
});

test("after the login redirect returns without a fragment the key comes from storage", () => {
  const key = generateLinkKey();
  const storage = fakeStorage();
  adoptLinkKey(SLOT, { ...fakeTab(`#${b64url(key)}`), storage, now: NOW });
  assert.deepEqual(adoptLinkKey(SLOT, { ...fakeTab(""), storage, now: NOW + 60_000 }), key);
});

test("after decryption the stored key is gone", () => {
  const storage = fakeStorage();
  adoptLinkKey(SLOT, { ...fakeTab(`#${b64url(generateLinkKey())}`), storage, now: NOW });
  dropLinkKey(SLOT, storage);
  assert.deepEqual([storage.size, adoptLinkKey(SLOT, { ...fakeTab(""), storage, now: NOW })], [0, null]);
});

test("a stored key expires", () => {
  const storage = fakeStorage();
  adoptLinkKey(SLOT, { ...fakeTab(`#${b64url(generateLinkKey())}`), storage, now: NOW });
  const got = adoptLinkKey(SLOT, { ...fakeTab(""), storage, now: NOW + KEY_TTL_MS + 1 });
  assert.deepEqual([got, storage.size], [null, 0]);
});

test("a broken or truncated key is also removed from the address", () => {
  const tab = fakeTab(`#${b64url(generateLinkKey()).slice(0, 20)}`);
  const storage = fakeStorage();
  assert.deepEqual([adoptLinkKey(SLOT, { ...tab, storage, now: NOW }), href(tab), storage.size], [null, "/check/v/abc", 0]);
});

test("a login error fragment stays for the login message", () => {
  const tab = fakeTab("#login=expired");
  adoptLinkKey(SLOT, { ...tab, storage: fakeStorage(), now: NOW });
  assert.equal(tab.location.hash, "#login=expired");
});

test("without storage the key still works for this page", () => {
  const key = generateLinkKey();
  const tab = fakeTab(`#${b64url(key)}`);
  assert.deepEqual([adoptLinkKey(SLOT, { ...tab, storage: null, now: NOW }), tab.location.hash], [key, ""]);
});
