// Текст водяного знака и его отрисовка прямо в пиксели canvas: отдельного слоя, который можно
// удалить из DOM, нет.

export const MARK_COLOR = "rgba(179, 38, 30, 0.34)";

export function watermarkText(sender, nick, when) {
  const stamp = when.toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" });
  return [sender && `от @${sender}`, `для @${nick}`, stamp].filter(Boolean).join(" · ");
}

function tile(text, ratio) {
  const font = `bold ${Math.round(18 * ratio)}px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`;
  const angle = Math.PI / 7;
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  ctx.font = font;
  const width = ctx.measureText(text).width;
  canvas.width = Math.ceil(width * Math.cos(angle) + 40 * ratio);
  canvas.height = Math.ceil(width * Math.sin(angle) + 50 * ratio);
  ctx.font = font;
  ctx.fillStyle = MARK_COLOR;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.translate(canvas.width / 2, canvas.height / 2);
  ctx.rotate(-angle);
  ctx.fillText(text, 0, 0);
  return canvas;
}

export function stamp(canvas, text, ratio) {
  const ctx = canvas.getContext("2d");
  const t = tile(text, ratio);
  ctx.save();
  ctx.fillStyle = ctx.createPattern(t, "repeat");
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  // Второй проход со сдвигом на полплитки по горизонтали: параллельные строки между первыми,
  // обрезать фото мимо надписей труднее. Сдвиг по диагонали лёг бы поверх первых строк.
  ctx.translate(t.width / 2, 0);
  ctx.fillRect(-t.width / 2, 0, canvas.width, canvas.height);
  ctx.restore();
  t.width = t.height = 0;
}
