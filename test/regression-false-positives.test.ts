/**
 * 回帰テスト: 公開データ（node_modules）で見つかった誤検知を直したとき、本物の秘密情報まで残さないこと。
 * 誤検知を減らす条件は広げすぎると、本物の値を見逃す（実際に WORDPRESS_DB_PASSWORD: wordpress を見逃した）。
 */
import { describe, expect, it } from 'vitest';
import { maskSecrets } from '../src/util/protect.js';
import { classifySecret } from '../src/util/secrets.js';

describe('誤検知を減らしても、本物の秘密情報は伏せる', () => {
  it.each([
    // 値がキー名の一部と同じでも、本物のパスワード
    ['WORDPRESS_DB_PASSWORD: wordpress', 'wordpress'],
    ['MARIADB_PASSWORD: mariadb-dev', 'mariadb-dev'],
    // ハイフンでつないだ単語の合言葉
    ['POSTGRES_PASSWORD: myapp-local', 'myapp-local'],
    ['APP_PASSPHRASE=correct-horse-battery-staple', 'correct-horse-battery-staple'],
    ['Bash(OPS_PASSPHRASE=sora-moyou-2026 npm start)', 'sora-moyou-2026'],
    // 「Basic」の後ろが本物の base64
    [`curl -H "Authorization: Basic ${Buffer.from('admin:Zq8wLmT4').toString('base64')}"`, Buffer.from('admin:Zq8wLmT4').toString('base64')],
  ])('%s', (input, secret) => {
    expect(maskSecrets(input)).not.toContain(secret);
  });

  it('キー名による検出（R004 の材料）も同じ規則で判定する', () => {
    expect(classifySecret('WORDPRESS_DB_PASSWORD', 'wordpress-prod')?.kind).toBe('key-name');
    expect(classifySecret('APP_PASSPHRASE', 'correct-horse-battery-staple')?.kind).toBe('key-name');
    expect(classifySecret('privateKey', 'privateKey')).toBeUndefined();
    expect(classifySecret('token', 'SingletonFoo')).toBeUndefined();
    expect(classifySecret('credentials', 'same-origin')).toBeUndefined();
    expect(classifySecret('PWD', '/home/robot')).toBeUndefined();
    expect(classifySecret('token-time', '2145916800')).toBeUndefined();
  });
});
