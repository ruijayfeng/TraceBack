/** Display helpers for stable IDs. Never rewrite the underlying ID value. */
export const shortId = (value: string) =>
  value.length > 22 ? value.slice(0, 12) + '…' + value.slice(-6) : value;

export const isStableId = (value: string) => /^[a-z]{3}_[a-f0-9]{64}$/.test(value);
