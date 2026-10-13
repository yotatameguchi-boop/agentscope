import { redactName } from './secrets.js';

/**
 * JSON ポインタ風の表示用パスを組み立てる（例: mcpServers.github.env.TOKEN, permissions.allow[2]）。
 * キー名は画面に出るため、秘密情報らしいキー名は伏せる。
 */
export function joinPointer(base: string, key: string | number): string {
  if (typeof key === 'number') return `${base}[${key}]`;
  const shown = redactName(key);
  const safe = /^[A-Za-z_$][\w$-]*$/.test(shown) ? shown : JSON.stringify(shown);
  return base ? `${base}.${safe}` : safe;
}
