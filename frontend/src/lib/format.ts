/** Display-only projections of raw device values. Never mutate the API payload. */
export function readableEntityValue(value: string): string {
  if (!value.startsWith('{')) return value;
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    const parts = [parsed.name, parsed.host, parsed.ip, parsed.account, parsed.command, parsed.path].filter(v => typeof v === 'string' && v);
    if (typeof parsed.pid === 'number' || typeof parsed.pid === 'string') parts.push(`pid ${parsed.pid}`);
    return parts.length ? parts.join(' · ') : value;
  } catch { return value; }
}

/** One-line projection for observation values (objects become readable key figures). */
export function readableValue(value: unknown, limit = 400): string {
  if (value === null || value === undefined) return '未提供';
  if (typeof value === 'object') {
    const text = readableEntityValue(JSON.stringify(value));
    if (text !== JSON.stringify(value)) return text.slice(0, limit);
    return JSON.stringify(value).slice(0, limit);
  }
  if (typeof value === 'string' && value.startsWith('{')) {
    const text = readableEntityValue(value);
    if (text !== value) return text.slice(0, limit);
  }
  return String(value).slice(0, limit);
}
