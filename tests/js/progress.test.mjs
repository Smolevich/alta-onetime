import assert from "node:assert/strict";
import { test } from "node:test";
import { indicatorState } from "../../src/alta_onetime/static/progress.js";

test("verify and decrypt steps show their text without a fake percent", () => {
  assert.deepEqual(indicatorState("verify"), { visible: true, text: "Проверяю пароль…", percent: null });
  assert.match(indicatorState("decrypt").text, /^Расшифровываю файл… \(несколько секунд\)$/);
});

test("upload shows a real percent, clamped and rounded", () => {
  assert.equal(indicatorState("upload", 42.4).text, "Загружаю… 42%");
  assert.equal(indicatorState("upload", 140).percent, 100);
  assert.equal(indicatorState("upload", -3).percent, 0);
});

test("unknown or idle step hides the indicator", () => {
  assert.equal(indicatorState("idle").visible, false);
  assert.equal(indicatorState("encrypt").text, "Шифрую…");
});
