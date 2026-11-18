// Сервер получает только то, что отдаёт encryptBundle: проверяем, что открытого текста там нет.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  b64url,
  decryptBundle,
  decryptBundleWithKey,
  encryptBundle,
  encryptBundleWithKey,
  generateLinkKey,
  linkKeyFrom,
  linkVerifierFor,
  generatePassword,
  isValidNick,
  KDF_ITERATIONS,
  normalizeNick,
  pack,
  unpack,
  verifierFor,
} from "../../src/alta_onetime/static/crypto.js";
import { watermarkText } from "../../src/alta_onetime/static/mark.js";

const FAST = 1000;
const MARKER = "PLAINTEXT-MARKER-ALTA-TEST";
const pdf = new TextEncoder().encode(`%PDF-1.4\n${MARKER}\n`.repeat(50));
const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4]);
const files = [
  { type: 1, bytes: pdf },
  { type: 2, bytes: png },
];
const contains = (haystack, needle) => Buffer.from(haystack).includes(Buffer.from(needle));

test("upload payload carries no plaintext or password", async () => {
  const password = "my own password 1";
  const { salt, iv, verifier, ciphertext } = await encryptBundle(files, 120, password, "test_reviewer", FAST);
  const sent = Buffer.concat([
    Buffer.from(ciphertext),
    Buffer.from(`X-Salt: ${b64url(salt)}\nX-IV: ${b64url(iv)}\nX-Verifier: ${b64url(verifier)}`),
  ]);
  assert.deepEqual([contains(sent, MARKER), contains(sent, password)], [false, false]);
});

test("all files and show time come back with the right nick and password", async () => {
  const password = generatePassword();
  const { salt, iv, ciphertext } = await encryptBundle(files, 60, password, "test_reviewer", FAST);
  const out = await decryptBundle(ciphertext, iv, salt, password, "test_reviewer", FAST);
  assert.deepEqual(
    [out.seconds, out.files.map((f) => f.type), Buffer.from(out.files[0].data), Buffer.from(out.files[1].data)],
    [60, ["application/pdf", "image/png"], Buffer.from(pdf), Buffer.from(png)],
  );
});

test("other nick with the right password gives a different verifier", async () => {
  const { salt, verifier } = await encryptBundle(files, 60, "same password 1", "test_reviewer", FAST);
  assert.notDeepEqual(await verifierFor("same password 1", "someone_else", salt, FAST), verifier);
});

test("verifier is reproducible from password, nick and salt", async () => {
  const { salt, verifier } = await encryptBundle(files, 60, "same password 1", "test_reviewer", FAST);
  assert.deepEqual(await verifierFor("same password 1", "test_reviewer", salt, FAST), verifier);
});

test("other nick cannot decrypt", async () => {
  const { salt, iv, ciphertext } = await encryptBundle(files, 60, "same password 1", "test_reviewer", FAST);
  await assert.rejects(decryptBundle(ciphertext, iv, salt, "same password 1", "someone_else", FAST));
});

test("nick is normalized: @, case and t.me link", () => {
  assert.deepEqual(
    ["@Test_Reviewer", " test_reviewer ", "https://t.me/Test_Reviewer"].map(normalizeNick),
    ["test_reviewer", "test_reviewer", "test_reviewer"],
  );
});

test("default KDF is PBKDF2 with at least 600k iterations", () => {
  assert.ok(KDF_ITERATIONS >= 600_000);
});

test("generated password is 16 chars of unambiguous alphabet", () => {
  assert.match(generatePassword(), /^[a-km-zA-HJ-NP-Z2-9]{16}$/);
});

test("bundle header carries no sender field", () => {
  const plain = pack(files, 60);
  const len = new DataView(plain.buffer).getUint32(0);
  assert.equal("from" in JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + len))), false);
});

test("unpacked bundle exposes no sender", () => {
  assert.equal("sender" in unpack(pack(files, 60)), false);
});

test("five-character nick is valid and four-character is not", () => {
  assert.deepEqual(["abcde", "abcd"].map(isValidNick), [true, false]);
});

test("show time above 90 s from a forged bundle falls back to 90", () => {
  assert.equal(unpack(pack(files, 300)).seconds, 90);
});

test("watermark names sender and recipient", () => {
  assert.match(watermarkText("test_sender", "test_reviewer", new Date(2026, 10, 3, 17, 23)), /^от @test_sender · для @test_reviewer · 03\.11\.2026/);
});

test("watermark without sender names only recipient", () => {
  assert.match(watermarkText("", "test_reviewer", new Date(2026, 10, 3, 17, 23)), /^для @test_reviewer · /);
});

test("random link key encrypts and decrypts all files", async () => {
  const key = generateLinkKey();
  const { salt, iv, ciphertext } = await encryptBundleWithKey(files, 60, key, "test_reviewer");
  const out = await decryptBundleWithKey(ciphertext, iv, salt, key, "test_reviewer");
  assert.deepEqual([out.seconds, Buffer.from(out.files[0].data)], [60, Buffer.from(pdf)]);
});

test("link key payload carries no plaintext or key", async () => {
  const key = generateLinkKey();
  const { salt, iv, verifier, ciphertext } = await encryptBundleWithKey(files, 60, key, "test_reviewer");
  const sent = Buffer.concat([Buffer.from(ciphertext), Buffer.from(`${b64url(salt)}${b64url(iv)}${b64url(verifier)}`)]);
  assert.deepEqual([contains(sent, MARKER), contains(sent, key), sent.includes(b64url(key))], [false, false, false]);
});

test("link key with other nick cannot decrypt and gives other verifier", async () => {
  const key = generateLinkKey();
  const { salt, iv, verifier, ciphertext } = await encryptBundleWithKey(files, 60, key, "test_reviewer");
  assert.notDeepEqual(await linkVerifierFor(key, "someone_else", salt), verifier);
  await assert.rejects(decryptBundleWithKey(ciphertext, iv, salt, key, "someone_else"));
});

test("link verifier is reproducible from key, nick and salt", async () => {
  const key = generateLinkKey();
  const { salt, verifier } = await encryptBundleWithKey(files, 60, key, "test_reviewer");
  assert.deepEqual(await linkVerifierFor(key, "test_reviewer", salt), verifier);
});

test("link key survives the URL fragment round trip", () => {
  const key = generateLinkKey();
  assert.deepEqual([linkKeyFrom(`#${b64url(key)}`), linkKeyFrom(""), linkKeyFrom("#login=expired")], [key, null, null]);
});

test("password links still decrypt next to link-key links", async () => {
  const { salt, iv, ciphertext } = await encryptBundle(files, 60, "old password 12", "test_reviewer", FAST);
  const out = await decryptBundle(ciphertext, iv, salt, "old password 12", "test_reviewer", FAST);
  assert.equal(out.files.length, 2);
});
