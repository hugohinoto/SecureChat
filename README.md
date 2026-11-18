# SecureChat

プライバシーを重視したブラウザー向けチャットアプリの開発プロジェクトです。現在は認証付きの開発用プロトタイプです。

> [!WARNING]
> **セキュリティ検証前の試作版です。** 個別チャットはブラウザー内でECDH P-256 + HKDF + AES-GCMを使う試作暗号化を行いますが、公開鍵のSHA-256指紋を画面に表示しますが、相手と別経路で照合する必要があります。自動的な本人確認・署名済みPreKey・前方秘匿性は未実装です。OTPによる相互連絡先確認は追加されていますが、これは暗号鍵の真正性を保証しません。機密情報・個人情報の送信には使用しないでください。

## Cloudflare構成（新しいデプロイ先）

- **Cloudflare Workers**：HTTP APIと静的フロントエンドの配信
- **Cloudflare Durable Objects（SQLite）**：WebSocketの共通ルーム中継
- **Cloudflare D1**：ユーザーとセッションの保存
- **GitHub**：ソースコード管理とデプロイ連携

Render/PostgreSQLの代わりにCloudflare内で完結する構成です。CloudflareへのデプロイにはCloudflareアカウントでの初回リソース作成・Git連携が必要です。

## 現在実装済み

- Liquid Glass風のレスポンシブUI
- Cloudflare Workers API
- D1によるユーザー・セッション管理
- 既存ユーザーが発行する招待コード制の新規登録（24時間有効・1回限り・コード本体は保存せずSHA-256ハッシュのみ保存）
- 招待コードはユーザーごとに有効なものを最大5件まで発行可能
- 5分ごとに期限切れセッション・招待・暗号化メッセージを自動削除
- PBKDF2-HMAC-SHA-256によるパスワードハッシュ化（100,000反復、ユーザーごとのランダムソルト）
- セッショントークンは暗号学的乱数で発行し、D1にはSHA-256ハッシュのみ保存
- HttpOnly / SameSite=Strict Cookie（HTTPSではSecure・__Host- prefix）
- Durable Objects WebSocket Hibernation APIによる共通ルーム
- ログアウト時に該当セッションのWebSocketを切断
- Originチェック、D1共有ストレージによる永続・原子的なIP単位レート制限（15分窓）、基本的なセキュリティヘッダー
- レート制限キーはIPアドレスのSHA-256ダイジェストで保存し、生IPはD1へ保存しない（期限切れカウンターは定期削除）
- D1マイグレーション
- 8桁OTPを使った相互連絡先確認（各コード5分有効・1回限り・最大5回試行）
- OTPはサーバー側のHMAC秘密鍵でハッシュ化し、D1にはコードそのものを保存しない
- HTTPSへのリダイレクトとHSTS

## 未実装

- 検証済みライブラリを使った本番品質のE2EE（現在は試作暗号方式）
- Turnstile等の対話型チャレンジ（現在のボット対策はD1共有レート制限と招待制）
- Signal Protocol / PQXDH / Double Ratchet
- 公開鍵の本人確認、署名済みPreKey Bundleの検証、前方秘匿性
- 端末追加・鍵ローテーション・安全な鍵バックアップ
- 暗号化ファイル送信
- アカウント復旧・パスワードリセット
- 専門家によるセキュリティレビュー

## Cloudflareへの初回セットアップ

### 1. 必要なもの

- Cloudflareアカウント
- Node.js 22.12以降
- このGitHubリポジトリへのアクセス

### 2. D1データベースを作成

ローカルPCでリポジトリを取得し、プロジェクトのルートで実行します。

```bash
npm install
npx wrangler login
npx wrangler d1 create securechat-db
```

コマンド結果に表示された `database_id` をコピーし、ルートの `wrangler.jsonc` の `database_id` にある `REPLACE_WITH_D1_DATABASE_ID` を置き換えてください。database_idは秘密情報ではありません。パスワードやAPIトークンはGitHubに保存しないでください。

### 3. データベースを初期化

```bash
npx wrangler d1 migrations apply securechat-db --remote
```

### 3.1 招待制登録のデータベース移行

招待制登録を有効にするため、D1へ新しいテーブルを追加します。

```bash
npx wrangler d1 migrations apply securechat-db --remote
```

GitHub連携だけでデプロイしている場合も、Workerを更新する前にこのD1マイグレーションを適用してください。Cloudflare DashboardのD1 Consoleを使う場合は、`database/d1-migrations/0004_registration_invites.sql` の内容を実行します。

ログイン後、サイドバーの「アカウント招待」からコードを発行し、新規登録する人へ共有します。登録画面でコードを入力しないとアカウントを作成できません。既存アカウントには影響しません。

### 3.2 永続レート制限のデータベース移行

認証・登録・招待発行のレート制限をWorkerメモリではなくD1で共有するため、`database/d1-migrations/0005_persistent_rate_limits.sql` を適用してください。Wranglerを使う場合は次を実行します。

```bash
npx wrangler d1 migrations apply securechat-db --remote
```

Cloudflare DashboardのD1 Consoleを使う場合は、同ファイルのSQLを一度だけ実行します。これを適用する前に新しいWorkerが動くと、レート制限テーブルがないためAPIがエラーになります。

### 3.3 相互OTP連絡先認証の設定

新しい連絡先認証には、Worker Secret `CONTACT_OTP_PEPPER` が必要です。32バイト以上のランダムな値をCloudflare DashboardのWorker「Settings → Variables and Secrets → Add → Secret」に登録してください。値をGitHubやコードに書かないでください。

Node.jsがあるPCでは、次のコマンドで秘密値を生成してWranglerへ登録できます。

```powershell
node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))" | npx wrangler secret put CONTACT_OTP_PEPPER
```

D1の新しいスキーマを適用します。

```bash
npx wrangler d1 migrations apply securechat-db --remote
```

手動でD1 Consoleを操作している場合は、`database/d1-migrations/0003_mutual_otp_contacts.sql` の内容を一度だけ実行してください。既存の連絡先はOTP確認済みとは見なされず、新しい招待手順が必要です。既存の会話はOTP確認が終わるまで表示・利用できず、確認完了時にその相手との古い会話は削除されます。

### 4. ローカルで確認

```bash
npm run cf:dev
```

表示されたlocalhostのURLを開き、新規登録・ログイン・別ブラウザー間のWebSocketチャットを確認します。

### 5. Cloudflareにデプロイ

```bash
npm run cf:deploy
```

初回デプロイ時にDurable ObjectsのSQLite migration（v1）が適用されます。Workers & PagesのGit連携を設定すると、GitHubの指定ブランチへの更新を自動デプロイにできます。WranglerのGit連携設定を使う場合も、D1のdatabase_idとリモートマイグレーションが先に設定されていることを確認してください。

## GitHub連携デプロイ

Cloudflare DashboardでWorkers & Pagesから既存WorkerをGitHubリポジトリに接続し、次の値を指定します。

- Repository: `hugohinoto/SecureChat`
- Production branch: `main`
- Build command: `npm install`
- Deploy command: `npx wrangler deploy`
- Root directory: リポジトリのルート

`wrangler.jsonc` にD1 bindingとDurable Object bindingが定義されています。初回は必ずD1の `database_id` を実際のIDに置き換え、D1 migrationをremoteに適用してください。

## ローカルの旧Node.js / Render構成

`server/` と `render.yaml` は旧Render構成との比較・移行用に残しています。Cloudflareデプロイでは `worker/index.js` と `wrangler.jsonc` が使用されます。旧Render側のWeb ServiceはCloudflare移行確認が済むまで削除しないでください。

## ヘルスチェック

`GET /api/health` はWorkerとD1の接続状態を返します。正常時は `status: "ok"`、`database: "connected"` になります。

## 無料枠と制限

Cloudflare Workers Freeには日次リクエスト数・CPU時間の制限があり、D1 Freeにはデータベース容量と日次読み書き上限があります。Durable Objects Freeにも日次リクエスト・実行時間の上限があります。利用量が上限に達すると、その日の処理が失敗することがあります。パスワードハッシュは600,000反復のPBKDF2を使うため、FreeプランのCPU制限に達する場合はWorkers Paidへの切り替えが必要です。上限・料金は変わるためCloudflare公式料金ページで確認してください。

## 通信の保護

WorkerはHTTPアクセスをHTTPSへリダイレクトし、HTTPS応答にHSTSを付けます。TLSのバージョン選択はWorkerコードではなくCloudflareのエッジ設定で行われます。Cloudflare Dashboardの「SSL/TLS → Edge Certificates」で、Minimum TLS VersionをTLS 1.2にし、TLS 1.3をOnにしてください。TLS 1.3の設定値は「on」（0-RTTを有効にしない）を選び、「zrt」は選ばないでください。TLS 1.3の有効化とMinimum TLS Versionの設定はCloudflareのエッジ側で適用されます。

## セキュリティ方針

- 独自の暗号アルゴリズムや鍵交換プロトコルを作りません。
- E2EEはSignalが公開する実装や、互換性・保守性を確認した検証済みライブラリを評価して採用します。
- クライアント側の秘密鍵をサーバーへ送らない設計を目指します。
- 鍵のバックアップ、端末追加、本人確認、失効、XSSと配信経路の保護も設計対象です。
- 認証機能が動くことと、メッセージがE2EEで保護されることは別です。
- 専門的なセキュリティレビューを完了するまでは、本番用途の安全性を保証しません。
