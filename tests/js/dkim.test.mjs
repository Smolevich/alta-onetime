// Синтетическое письмо, подписанное своим ключом по тем же правилам (simple/simple), что у 24x7.rs.
import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalBodySimple, parseAmount, verdict, verifyDkim, parseStatement, plainTextPart } from "../../src/alta_onetime/static/dkim.js";

const enc = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const b64 = (u8) => Buffer.from(u8).toString("base64");

const BODY = [
  "Content-Type: multipart/alternative; boundary=\"XX\"",
  "",
  "--XX",
  "Content-Type: text/plain; charset=\"utf-8\"",
  "Content-Transfer-Encoding: quoted-printable",
  "",
  "IVAN TESTOV PR BEOGRAD =09",
  "(Naziv vlasnika ra=C4=8Duna)\t=20",
  "190-0000000012345-67 =09",
  "(Broj ra=C4=8Duna)\t=20",
  "\tNovo Stanje\t \t=09",
  "\t31.10.2026 / 09:06:33\t 61,234.50\t =09",
  "--XX--",
  "",
].join("\r\n");

async function signedMail({ from = "\"ALTA Banka a.d. Beograd\" <altabanka@24x7.rs>", body = BODY } = {}) {
  const keys = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const bh = b64(new Uint8Array(await crypto.subtle.digest("SHA-256", enc(canonicalBodySimple(body)))));
  const headers = `From: ${from}\r\nTo: candidate1@example.com\r\nSubject: Izvestaj o stanju\r\n`;
  const sig = `DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple;\r\n  d=24x7.rs; s=selector3; t=1793435154; x=1824971154;\r\n  h=from:to:subject; bh=${bh};\r\n  b=`;
  const b = b64(new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, enc(headers + sig))));
  const spki = b64(new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey)));
  return { raw: `${sig}${b}\r\n${headers}MIME-Version: 1.0\r\n\r\n${body}`, spki };
}

test("genuine signed mail verifies", async () => {
  const { raw, spki } = await signedMail();
  assert.equal((await verifyDkim(raw, spki)).signedAt, 1793435154);
});

test("changed balance breaks the signature", async () => {
  const { raw, spki } = await signedMail();
  await assert.rejects(verifyDkim(raw.replace("61,234.50", "91,234.50"), spki), /изменён/);
});

test("changed signed header breaks the signature", async () => {
  const { raw, spki } = await signedMail();
  await assert.rejects(verifyDkim(raw.replace("candidate1@", "candidate2@"), spki), /не сходится/);
});

test("other sender of the same domain is rejected", async () => {
  const { raw, spki } = await signedMail({ from: "<altabank@24x7.rs>" });
  await assert.rejects(verifyDkim(raw, spki), /не от/);
});

test("second From header is rejected", async () => {
  const { raw, spki } = await signedMail();
  await assert.rejects(verifyDkim(raw.replace("MIME-Version", "From: <x@example.com>\r\nMIME-Version"), spki), /несколько/);
});

test("mail saved with LF line endings still verifies", async () => {
  const { raw, spki } = await signedMail();
  assert.ok(await verifyDkim(raw.replace(/\r\n/g, "\n"), spki));
});

test("statement yields owner, date and balance", () => {
  const s = parseStatement(plainTextPart(BODY));
  assert.deepEqual([s.owner, s.date, s.amount], ["IVAN TESTOV PR BEOGRAD", "31.10.2026", 61234.5]);
});

test("amounts in both separator styles parse", () => {
  assert.deepEqual([parseAmount("13,723.08"), parseAmount("13.723,08"), parseAmount("2835")], [13723.08, 13723.08, 2835]);
});

test("unknown currency is undecided only when EUR and RSD readings disagree", () => {
  assert.deepEqual([verdict(61234.5, null).sure, verdict(10_000_000, null).yes, verdict(1000, null).yes], [false, true, false]);
});
