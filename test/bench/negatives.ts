/**
 * 出力保護の評価用の「伏せてはいけない」文字列。設定ファイルやコマンドによく出てくる、
 * ランダムに見えるが秘密ではない値を中心に集める。値は固定シードの乱数で組み立てる。
 *
 * tier:
 * - keep: 変更してはいけない（変更したら誤検知）
 * - tolerable: 伏せても許容できる（リンクを知っていれば開ける URL の ID など、値そのものが鍵の役割を持ちうるもの）
 */
import { gen, rng } from './corpus.js';

export type Tier = 'keep' | 'tolerable';

export interface Negative {
  /** 集計の単位 */
  group: string;
  kind: string;
  tier: Tier;
  text: string;
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const LOWER_NUM = 'abcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';
const B64 = ALNUM + '+/';
const URLSAFE = ALNUM + '-_';
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function negativeSet(seed: number): Negative[] {
  const r = rng(seed);
  const out: Negative[] = [];
  const add = (group: string, kind: string, text: string, tier: Tier = 'keep') => out.push({ group, kind, tier, text });
  const int = (n: number) => Math.floor(r() * n);
  const pick = <T,>(rand: () => number, xs: T[]) => xs[Math.floor(rand() * xs.length)]!;
  const uuid = () => `${gen(r, HEX, 8)}-${gen(r, HEX, 4)}-4${gen(r, HEX, 3)}-a${gen(r, HEX, 3)}-${gen(r, HEX, 12)}`;

  // ---- ハッシュ・ダイジェスト・チェックサム
  add('hash', 'git-sha', gen(r, HEX, 40));
  add('hash', 'git-short-sha', gen(r, HEX, 7));
  add('hash', 'sha256-hex', gen(r, HEX, 64));
  add('hash', 'md5', gen(r, HEX, 32));
  add('hash', 'docker-digest', `ghcr.io/org/app@sha256:${gen(r, HEX, 64)}`);
  add('hash', 'npm-integrity', `sha512-${gen(r, B64, 86)}==`);
  add('hash', 'sri-sha384', `<script src="https://cdn.example.com/lib.js" integrity="sha384-${gen(r, B64, 64)}" crossorigin="anonymous">`);
  add('hash', 'go-sum', `github.com/stretchr/testify v1.9.0 h1:${gen(r, B64, 43)}=`);
  add('hash', 'go-sum-mod', `golang.org/x/sys v0.25.0/go.mod h1:${gen(r, B64, 43)}=`);
  add('hash', 'pip-hash', `requests==2.32.3 --hash=sha256:${gen(r, HEX, 64)}`);
  add('hash', 'cargo-checksum', `checksum = "${gen(r, HEX, 64)}"`);
  add('hash', 'yarn-checksum', `checksum: ${gen(r, HEX, 128)}`);
  add('hash', 'nix-sri', `hash = "sha256-${gen(r, B64, 43)}=";`);
  add('hash', 'ssh-fingerprint', `SHA256:${gen(r, B64, 43)}`);
  add('hash', 'gpg-fingerprint', `${gen(r, HEX, 40).toUpperCase()}`);
  add('hash', 'etag', `W/"${gen(r, HEX, 8)}-${gen(r, URLSAFE, 27)}"`);
  add('hash', 'actions-pinned', `uses: actions/checkout@${gen(r, HEX, 40)} # v4.2.2`);
  add('hash', 'cache-key', `key: \${{ runner.os }}-node-\${{ hashFiles('**/package-lock.json') }}`);

  // ---- 公開鍵・証明書（秘密ではない）
  add('public-key', 'ssh-ed25519', `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${gen(r, B64, 43)} someone@laptop`);
  add('public-key', 'ssh-rsa', `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ${gen(r, B64, 300)} deploy@ci`);
  add('public-key', 'pem-certificate', `-----BEGIN CERTIFICATE-----\n${gen(r, B64, 64)}\n${gen(r, B64, 64)}\n-----END CERTIFICATE-----`);
  add('public-key', 'pem-public-key', `-----BEGIN PUBLIC KEY-----\n${gen(r, B64, 64)}\n-----END PUBLIC KEY-----`);
  add('public-key', 'age-recipient', `age1${gen(r, 'qpzry9x8gf2tvdw0s3jn54khce6mua7l', 58)}`);
  add('public-key', 'jwks-n', `"n": "${gen(r, URLSAFE, 342)}"`);

  // ---- 公開してよいキー・クライアント ID
  add('public-id', 'stripe-publishable', `pk_live_${gen(r, ALNUM, 24)}`);
  add('public-id', 'stripe-publishable-test', `NEXT_PUBLIC_STRIPE_KEY=pk_test_${gen(r, ALNUM, 24)}`);
  add('public-id', 'google-oauth-client-id', `${gen(r, '0123456789', 12)}-${gen(r, LOWER_NUM, 32)}.apps.googleusercontent.com`);
  add('public-id', 'firebase-app-id', `1:${gen(r, '0123456789', 12)}:web:${gen(r, HEX, 22)}`);
  add('public-id', 'ga4-measurement-id', `G-${gen(r, CROCKFORD, 10)}`);
  add('public-id', 'gtm-id', `GTM-${gen(r, CROCKFORD, 7)}`);
  add('public-id', 'algolia-app-id', `NEXT_PUBLIC_ALGOLIA_APP_ID=${gen(r, CROCKFORD, 10)}`);
  add('public-id', 'sentry-dsn-host', `https://o${gen(r, '0123456789', 6)}.ingest.sentry.io/${gen(r, '0123456789', 7)}`);
  add('public-id', 'mapbox-style', `mapbox://styles/${gen(r, LOWER_NUM, 8)}/${gen(r, LOWER_NUM, 25)}`);
  add('public-id', 'recaptcha-site-key', `data-sitekey="6L${gen(r, URLSAFE, 38)}"`, 'tolerable');

  // ---- クラウドのリソース ID
  add('cloud-id', 'aws-account', `123456789012`);
  add('cloud-id', 'aws-arn-role', `arn:aws:iam::${gen(r, '0123456789', 12)}:role/GitHubActionsDeployRole2024`);
  add('cloud-id', 'aws-arn-lambda', `arn:aws:lambda:ap-northeast-1:${gen(r, '0123456789', 12)}:function:ImageResizer-Prod`);
  add('cloud-id', 'aws-ami', `ami-0${gen(r, HEX, 16)}`);
  add('cloud-id', 'aws-instance', `i-0${gen(r, HEX, 16)}`);
  add('cloud-id', 'aws-subnet', `subnet-0${gen(r, HEX, 16)}`);
  add('cloud-id', 'aws-sg', `sg-0${gen(r, HEX, 16)}`);
  add('cloud-id', 'aws-cloudfront', `E${gen(r, CROCKFORD, 13)}`);
  add('cloud-id', 'aws-access-key-id-example', `AKIAIOSFODNN7EXAMPLE`, 'tolerable');
  add('cloud-id', 's3-url', `https://my-bucket-2024.s3.ap-northeast-1.amazonaws.com/releases/v1.2.3/app.zip`);
  add('cloud-id', 'azure-subscription', `/subscriptions/${uuid()}/resourceGroups/rg-prod/providers/Microsoft.Web/sites/app-prod`);
  add('cloud-id', 'azure-tenant', `AZURE_TENANT_ID=${uuid()}`);
  add('cloud-id', 'gcp-project', `projects/my-project-${gen(r, LOWER_NUM, 6)}/locations/asia-northeast1/services/api`);
  add('cloud-id', 'gcp-sa-email', `deployer@my-project-${gen(r, LOWER_NUM, 6)}.iam.gserviceaccount.com`);
  add('cloud-id', 'k8s-pod', `web-${gen(r, 'abcdef0123456789', 9)}-${gen(r, LOWER_NUM, 5)}`);
  add('cloud-id', 'k8s-image', `registry.k8s.io/ingress-nginx/controller:v1.11.2@sha256:${gen(r, HEX, 64)}`);
  add('cloud-id', 'vercel-project-id', `prj_${gen(r, ALNUM, 28)}`, 'tolerable');
  add('cloud-id', 'cloudflare-account-id', `account_id = "${gen(r, HEX, 32)}"`);
  add('cloud-id', 'cloudflare-zone-id', `CF_ZONE_ID=${gen(r, HEX, 32)}`);

  // ---- アプリの ID（秘密ではない）
  add('app-id', 'uuid', uuid());
  add('app-id', 'ulid', `01${gen(r, CROCKFORD, 24)}`);
  add('app-id', 'ksuid', gen(r, ALNUM, 27), 'tolerable');
  add('app-id', 'nanoid', gen(r, URLSAFE, 21), 'tolerable');
  add('app-id', 'mongo-objectid', gen(r, HEX, 24));
  add('app-id', 'snowflake', gen(r, '0123456789', 19));
  add('app-id', 'stripe-customer', `cus_${gen(r, ALNUM, 14)}`);
  add('app-id', 'stripe-price', `STRIPE_PRICE_ID=price_1${gen(r, ALNUM, 23)}`);
  add('app-id', 'stripe-product', `prod_${gen(r, ALNUM, 14)}`);
  add('app-id', 'stripe-payment-intent', `pi_3${gen(r, ALNUM, 23)}`);
  add('app-id', 'notion-page-id', `https://www.notion.so/myteam/Roadmap-${gen(r, HEX, 32)}`, 'tolerable');
  add('app-id', 'slack-channel', `C0${gen(r, CROCKFORD, 9)}`);
  add('app-id', 'slack-user', `U0${gen(r, CROCKFORD, 9)}`);
  add('app-id', 'discord-channel', gen(r, '0123456789', 18));
  add('app-id', 'youtube', `https://www.youtube.com/watch?v=${gen(r, URLSAFE, 11)}`);
  add('app-id', 'spotify-track', `https://open.spotify.com/track/${gen(r, ALNUM, 22)}`, 'tolerable');
  add('app-id', 'figma-file', `https://www.figma.com/design/${gen(r, ALNUM, 22)}/Design-System`, 'tolerable');
  add('app-id', 'google-doc', `https://docs.google.com/document/d/${gen(r, URLSAFE, 44)}/edit`, 'tolerable');
  add('app-id', 'claude-artifact', `https://claude.ai/artifact/${uuid()}`, 'tolerable');
  add('app-id', 'jira-key', 'feature/PROJ-1234-add-login-form');
  add('app-id', 'github-run', `https://github.com/org/repo/actions/runs/${gen(r, '0123456789', 11)}/job/${gen(r, '0123456789', 11)}`);

  // ---- パッケージ・依存関係
  add('package', 'package-spec', '@modelcontextprotocol/server-github@2025.4.8');
  add('package', 'npx-claude', 'npx -y @anthropic-ai/claude-code@2.1.300');
  add('package', 'npm-tarball', `https://registry.npmjs.org/zod/-/zod-4.6.7.tgz`);
  add('package', 'pnpm-path', `node_modules/.pnpm/@types+node@26.6.5_${gen(r, HEX, 10)}/node_modules/@types/node/index.d.ts`);
  add('package', 'python-wheel', `torch-2.5.1+cu124-cp312-cp312-manylinux_2_28_x86_64.whl`);
  add('package', 'maven', `org.springframework.boot:spring-boot-starter-web:3.4.0`);
  add('package', 'go-module', `github.com/aws/aws-sdk-go-v2/service/s3 v1.67.0`);
  add('package', 'docker-tag', `node:24.18.1-bookworm-slim`);
  add('package', 'semver-range', '>=22.12.0 <25');
  add('package', 'build-metadata', 'v2.1.300-rc.1+build.20261014');
  add('package', 'vite-asset', `dist/assets/index-${gen(r, URLSAFE, 8)}.js`);
  add('package', 'webpack-chunk', `static/js/main.${gen(r, HEX, 8)}.chunk.js`);
  add('package', 'nextjs-build', `.next/static/${gen(r, URLSAFE, 21)}/_buildManifest.js`, 'tolerable');

  // ---- パス
  add('path', 'unix-path', '/Users/someone/Projects/AgentScope2/src/index.ts');
  add('path', 'windows-path', 'C:\\Users\\Someone\\AppData\\Roaming\\Code\\User\\settings.json');
  add('path', 'macos-tmp', `/private/var/folders/${gen(r, LOWER_NUM + '_', 2)}/${gen(r, LOWER_NUM + '_', 28)}/T/agentscope-test-${gen(r, ALNUM, 6)}/com.anthropic.claudecode.plist`);
  add('path', 'linux-tmp', `/tmp/tmp.${gen(r, ALNUM, 10)}/work/${gen(r, ALNUM, 8)}/settings.json`);
  add('path', 'windows-tmp', `C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\agentscope-test-${gen(r, ALNUM, 6)}\\.claude\\settings.json`);
  add('path', 'nix-store', `/nix/store/${gen(r, 'abcdfghijklmnpqrsvwxyz0123456789', 32)}-nodejs-24.18.1/bin/node`);
  add('path', 'go-cache', `/home/runner/go/pkg/mod/github.com/aws/aws-sdk-go-v2@v1.32.${int(9)}/config/doc.go`);
  add('path', 'vscode-ext', `~/.vscode/extensions/anthropic.claude-code-2.1.300-darwin-arm64/resources/${gen(r, ALNUM, 6)}/icon.svg`);
  add('path', 'claude-worktree', `.claude/worktrees/${gen(r, LOWER_NUM, 8)}-fix-auth-bug/src/app.ts`);
  add('path', 'glob', 'Read(./src/**/*.{ts,tsx})');
  add('path', 'registry-path', 'HKLM\\SOFTWARE\\Policies\\ClaudeCode\\Settings');

  // ---- URL
  add('url', 'utm', `https://example.com/landing?utm_source=newsletter&utm_medium=email&utm_campaign=launch_2024`);
  add('url', 'google-fonts', 'https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;700&display=swap');
  add('url', 'cdn-versioned', `https://cdn.jsdelivr.net/npm/chart.js@4.4.6/dist/chart.umd.min.js`);
  add('url', 'github-blob', `https://github.com/yotatameguchi-boop/agentscope/blob/${gen(r, HEX, 40)}/src/scan.ts`);
  add('url', 'wikimedia', 'https://upload.wikimedia.org/wikipedia/commons/6/61/Miejscu-pracy-koparka-budowlanych-3741.webm');
  add('url', 'oauth-redirect', `http://localhost:5173/auth/callback?code_challenge_method=S256&state=${gen(r, HEX, 16)}`);
  add('url', 'mcp-endpoint', 'https://mcp.example.com/v1/sse?transport=streamable-http');
  add('url', 'localhost', 'http://127.0.0.1:5174/api/state');
  add('url', 'ws', 'wss://realtime.example.com/socket/websocket?vsn=2.0.0');

  // ---- コマンド・権限ルール
  add('command', 'bash-rule', 'Bash(npm run test:integration -- --runInBand)');
  add('command', 'git-log', 'Bash(git log --oneline --since=2024-01-01 --author=yota)');
  add('command', 'docker-run', 'docker run --rm -p 127.0.0.1:5439:5432 -e POSTGRES_DB=app postgres:17');
  add('command', 'curl-json', `curl -s -X POST -H 'Content-Type: application/json' -d '{"name":"test"}' http://localhost:3000/api/items`);
  add('command', 'kubectl', 'kubectl rollout status deployment/web-frontend -n production --timeout=300s');
  add('command', 'terraform', 'terraform plan -var-file=env/prod.tfvars -out=tfplan');
  add('command', 'aws-cli', 'aws s3 sync ./dist s3://my-bucket-2024/releases/ --delete --cache-control max-age=31536000');
  add('command', 'gh-cli', 'gh pr create --base main --head feature/login --title "Add login"');
  add('command', 'secret-id-flag', 'aws secretsmanager get-secret-value --secret-id prod/app/database');
  add('command', 'token-file-flag', 'vault login -method=github token_file=/run/secrets/gh');
  add('command', 'mcp-tool', 'mcp__github__create_pull_request_review_comment');
  add('command', 'cursor-allow', 'Shell(npm run lint)');
  add('command', 'cron', '0 */6 * * 1-5');
  add('command', 'regex', '^(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*)@example\\.com$');
  add('command', 'sql', 'SELECT id, email FROM users WHERE created_at > now() - interval \'7 days\' ORDER BY id DESC LIMIT 50;');

  // ---- 参照・仮の値
  add('reference', 'env-ref', 'API_KEY=${API_KEY}');
  add('reference', 'env-default-ref', 'TOKEN=${TOKEN:-${FALLBACK_TOKEN}}');
  add('reference', 'env-required', 'SESSION_SECRET: ${SESSION_SECRET:?SESSION_SECRET is required}');
  add('reference', 'gha-secret', 'ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}');
  add('reference', 'gha-vars', 'API_URL: ${{ vars.API_URL }}');
  add('reference', 'cursor-env-ref', '"Authorization": "Bearer ${env:GITHUB_TOKEN}"');
  add('reference', 'placeholder-angle', 'ANTHROPIC_API_KEY=<your-api-key>');
  add('reference', 'placeholder-words', 'JWT_SECRET=tobemodified');
  add('reference', 'placeholder-japanese', 'password = あなたのパスワード');
  add('reference', 'placeholder-xxx', 'OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx');
  add('reference', 'op-reference', 'DB_PASSWORD=op://Private/Database/password');
  add('reference', 'k8s-secret-ref', 'valueFrom: { secretKeyRef: { name: app-secrets, key: api-token } }');

  // ---- 名前・識別子
  add('name', 'camel', 'MyVeryLongServerName2024Production');
  add('name', 'java-class', 'org.springframework.boot.autoconfigure.SpringBootApplication');
  add('name', 'test-name', 'PlaywrightTestRunnerConfiguration');
  add('name', 'kebab', 'claude-code-security-review-github-action-workflow-v2');
  add('name', 'model-id', 'claude-opus-5-5');
  add('name', 'model-id-dated', 'gpt-4o-2024-08-06');
  add('name', 'bedrock-model', 'anthropic.claude-sonnet-5-20261001-v1:0');
  add('name', 'env-var-name', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC');
  add('name', 'css-class', 'flex items-center justify-between gap-4 rounded-lg bg-slate-900/80 px-4 py-2');
  add('name', 'branch', 'dependabot/npm_and_yarn/vitest-5.0.4');
  add('name', 'email', 'yota.example+agentscope@example.co.jp');
  add('name', 'ldap-dn', 'CN=Deploy Bot,OU=Service Accounts,DC=corp,DC=example,DC=com');

  // ---- 文章・データ
  add('text', 'japanese', '本番環境ではトークンを環境変数から読み込みます');
  add('text', 'japanese-long', 'このリポジトリでは、APIキーやトークンを .env に書かず、1Password から読み込む運用にしています。');
  add('text', 'english', 'Never commit the API key; load it from the secret manager at runtime.');
  add('text', 'emoji', '🚀 Deploy finished in 42s ✅');
  add('text', 'markdown-table', '| 項目 | 値 |\n| --- | --- |\n| リージョン | ap-northeast-1 |');
  add('text', 'ipv4-cidr', '10.0.0.0/16, 192.168.1.10/32');
  add('text', 'ipv6', 'fe80::1ff:fe23:4567:890a');
  add('text', 'mac', '3c:22:fb:9a:01:7e');
  add('text', 'date-time', '2026-10-14T07:18:56.123+09:00');
  add('text', 'color', '#1a2b3c, rgb(26 43 60 / 80%)');
  add('text', 'json-small', '{"enabled":true,"retries":3,"timeoutMs":120000}');
  add('text', 'data-uri-small', 'data:image/png;base64,iVBORw0KGgo=');
  add('text', 'data-uri-svg', `data:image/svg+xml;base64,${Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5z"/></svg>').toString('base64')}`, 'tolerable');
  add('text', 'base64-json', `eyJuYW1lIjoiYWdlbnRzY29wZSIsInZlcnNpb24iOiIwLjEuMCJ9`, 'tolerable');
  add('text', 'version-list', '22.12.0, 24.18.1, 26.0.0-nightly20261001');

  // ---- 公開データ（node_modules）で見つかった誤検知の型
  add('code', 'crypto-class-new', `kem: new Dhkem${pick(r, ['P256', 'P384', 'X25519', 'X448'])}HkdfSha${pick(r, ['256', '384', '512'])}(),`);
  add('code', 'crypto-class-import', `import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";`);
  add('code', 'method-call', 'The `isIPv4MappedAddress()` method returns true for IPv4-mapped addresses.');
  add('code', 'identifier-list', '  Aes256GcmEncryptor,');
  add('code', 'basic-word', '- **Smoke Tests** - Basic import/require tests for CommonJS and ESM');
  add('code', 'basic-auth-doc', '| auth | string | Basic authentication (`user:password`) for the Authorization header |');
  add('code', 'same-name', '  privateKey: privateKey,');
  add('code', 'di-token', `  token: "${pick(r, ['SingletonFoo', 'ContainerScopedFoo', 'theirClass', 'LoggerService'])}",`);
  add('code', 'fetch-credentials', `fetch(url, { credentials: '${pick(r, ['same-origin', 'include', 'omit'])}' })`);
  add('code', 'shell-pwd', `parse('beep --boop="$PWD"', { PWD: '/home/robot' })`);
  add('code', 'objc-cast', 'didUpdatePushCredentials:(PKPushCredentials *)credentials forType:(PKPushType)type');
  add('code', 'objc-arg', 'didUpdatePushCredentials:credentials forType:type');
  add('public-key', 'gpg-key-id', `https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=0x${gen(r, HEX, 16).toUpperCase()}`);
  add('public-key', 'travis-secure', `  - secure: ${gen(r, B64, 80)}=`);
  add('public-key', 'vapid-pubkey', `web-push send-notification --vapid-pubkey=B${gen(r, URLSAFE, 86)}`);
  add('public-key', 'webpush-p256dh', `"p256dh": "B${gen(r, URLSAFE, 86)}"`);
  add('url', 'github-advisory', `https://github.com/advisories/GHSA-${gen(r, LOWER_NUM, 4)}-${gen(r, LOWER_NUM, 4)}-${gen(r, LOWER_NUM, 4)}`);
  add('url', 'youtube-channel', `https://www.youtube.com/channel/UC${gen(r, URLSAFE, 22)}`);
  add('url', 'signed-url-time', `https://cdn.example.com/a.png?token-time=${gen(r, '0123456789', 10)}`);

  return out;
}
