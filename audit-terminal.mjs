import { safeText } from './audit.mjs';

const codes = { bold: 1, dim: 2, green: 32, amber: 33, red: 31, cyan: 36 };
const segments = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
const cells = (s) =>
  /\p{Extended_Pictographic}|\p{Script=Han}|\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Hangul}/u.test(
    s,
  )
    ? 2
    : 1;
export const textWidth = (text) =>
  [...segments.segment(text)].reduce((n, s) => n + cells(s.segment), 0);

export function terminalOptions({
  color = 'auto',
  width,
  stream = process.stdout,
  env = process.env,
} = {}) {
  return {
    color:
      color === true ||
      color === 'always' ||
      (color === 'auto' &&
        !!stream.isTTY &&
        env.TERM !== 'dumb' &&
        !Object.hasOwn(env, 'NO_COLOR')),
    width: Math.floor(
      Math.max(32, Math.min(140, Number(width ?? stream.columns ?? env.COLUMNS) || 100)),
    ),
  };
}
export function terminalLayout(options) {
  const { color, width } = terminalOptions(options);
  const paint = (text, tone) =>
    color && codes[tone] ? `\x1b[${codes[tone]}m${text}\x1b[0m` : text;
  const wrap = (value, size) => {
    let rest = [...segments.segment(safeText(value, 12000))].map((s) => s.segment);
    if (!rest.length) return [''];
    const result = [];
    while (rest.length) {
      let i = 0,
        used = 0,
        split = 0;
      while (i < rest.length && used + cells(rest[i]) <= size) {
        used += cells(rest[i]);
        if (/\s|\//.test(rest[i])) split = i + 1;
        i++;
      }
      if (i < rest.length && split > i / 2) i = split;
      i = Math.max(1, i);
      result.push(rest.splice(0, i).join('').trimEnd());
      while (rest[0] === ' ') rest.shift();
    }
    return result;
  };
  const lines = [];
  return {
    width,
    paint,
    line(value = '', { indent = 2, tone, prefix = '' } = {}) {
      if (!value && !prefix) {
        lines.push('');
        return;
      }
      const padding = Math.min(prefix.match(/ *$/)?.[0].length ?? 0, 16);
      prefix = safeText(prefix, 400) + ' '.repeat(padding);
      // Stack long transitions at narrow widths instead of squeezing targets.
      if (prefix && width - indent - textWidth(prefix) < 24) {
        this.line(prefix.trimEnd(), { indent, tone });
        this.line(value, { indent: indent + 2, tone });
        return;
      }
      const lead = ' '.repeat(indent) + prefix,
        next = ' '.repeat(textWidth(lead));
      wrap(value, Math.max(2, width - textWidth(lead))).forEach((part, i) =>
        lines.push(paint((i ? next : lead) + part, tone)),
      );
    },
    title(left, right, tone) {
      const cleanLeft = safeText(left),
        cleanRight = safeText(right);
      const gap = width - textWidth(cleanLeft) - textWidth(cleanRight) - 2;
      if (gap >= 2) lines.push(paint(cleanLeft, tone) + ' '.repeat(gap) + paint(cleanRight, 'dim'));
      else {
        this.line(cleanLeft, { indent: 0, tone });
        this.line(cleanRight, { indent: 0, tone: 'dim' });
      }
      lines.push(paint('─'.repeat(width), 'dim'));
    },
    section(title, subtitle) {
      lines.push('');
      this.line(title, { tone: 'bold' });
      if (subtitle) this.line(subtitle, { tone: 'dim' });
    },
    result: () => lines.join('\n'),
  };
}
