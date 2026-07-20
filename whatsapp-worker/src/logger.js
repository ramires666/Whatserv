import { redact } from './helpers.js';

const levels = { debug: 10, info: 20, warn: 30, error: 40 };
export function createLogger(level = 'info') {
  const threshold = levels[level] ?? levels.info;
  return Object.fromEntries(Object.entries(levels).map(([name, value]) => [name, (event, fields = {}) => {
    if (value < threshold) return;
    process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), level: name, event, ...redact(fields) })}\n`);
  }]));
}
