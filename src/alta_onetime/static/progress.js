// Индикатор работы: чистая функция состояния + привязка к DOM.
// Процент показываем только там, где он настоящий (отправка по сети); у PBKDF2 и AES-GCM его нет.

export const STEPS = {
  verify: "Проверяю пароль…",
  decrypt: "Расшифровываю файл… (несколько секунд)",
  encrypt: "Шифрую…",
  upload: "Загружаю…",
};

// percent: число 0..100 — полоса с долей; null — бегущая полоса без числа; step "idle" — индикатор скрыт.
export function indicatorState(step, percent = null) {
  if (!(step in STEPS)) return { visible: false, text: "", percent: null };
  const known = Number.isFinite(percent) ? Math.max(0, Math.min(100, Math.round(percent))) : null;
  return { visible: true, text: known === null ? STEPS[step] : `${STEPS[step]} ${known}%`, percent: known };
}

export function bindIndicator(root) {
  const text = root.querySelector(".progress-text");
  const bar = root.querySelector(".progress-bar");
  return (step, percent = null) => {
    const s = indicatorState(step, percent);
    root.hidden = !s.visible;
    text.textContent = s.text;
    bar.classList.toggle("indeterminate", s.percent === null);
    bar.style.width = s.percent === null ? "" : `${s.percent}%`;
  };
}

// Даём браузеру отрисовать индикатор до синхронной тяжёлой работы.
export const nextPaint = () => new Promise((done) => requestAnimationFrame(() => setTimeout(done, 0)));
