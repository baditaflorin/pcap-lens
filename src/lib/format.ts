export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return '0 B';
  }

  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unit = 0;

  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }

  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

export function formatTimestamp(micros: number): string {
  if (!Number.isFinite(micros) || micros <= 0) {
    return 'unknown';
  }

  return new Date(Math.floor(micros / 1000)).toISOString();
}

export function formatDurationMicros(start: number, end: number): string {
  const deltaMs = Math.max(0, (end - start) / 1000);

  if (deltaMs < 1000) {
    return `${deltaMs.toFixed(1)} ms`;
  }

  return `${(deltaMs / 1000).toFixed(2)} s`;
}

export function bytesToPreview(bytes: Uint8Array, maxLength = 96): string {
  const slice = bytes.slice(0, maxLength);
  let output = '';

  for (const byte of slice) {
    output += byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
  }

  return output;
}

export function bytesToAscii(bytes: Uint8Array): string {
  let output = '';

  for (const byte of bytes) {
    output += byte >= 9 && byte <= 126 ? String.fromCharCode(byte) : '.';
  }

  return output;
}
