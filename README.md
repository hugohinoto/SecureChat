# SecureChat

プライバシーを重視したブラウザー向けチャットアプリの開発プロジェクトです。現在は認証付きの開発用プロトタイプです。

> [!WARNING]
> **まだ安全なプライベートチャットではありません。** アカウント認証とHTTPS/WSSの基盤はありますが、チャット本文はサーバーで読める平文として全ログインユーザーに中継されます。E2EE、個別チャット、公開鍵登録は未実装です。パスワード以外の機密情報や個人情報は送信しないでください。

## 現在実装済み

- Liquid Glass風のレスポンシブUI
- Node.js / Express / WebSocket
- PostgreSQLのユーザー・セッション管理
- ユーザーIDの新規登録とログイン
- Node.js標準の scrypt によるパスワードハッシュ化（ユーザーごとにランダムソルト）
- セッショントークンは暗号学的乱数で発行し、DBにはSHA-256ハッシュのみ保存
- HttpOnly / SameSite=Strict Cookie（本番ではSecure属性付き）
- 認証済みユーザーだけがWebSocketに接続可能
- Originチェック、ログイン・登録の試行回数制限、基本的なセキュリティヘッダー
- ログアウト時のセッション削除と、そのセッションで開いているWebSocketの切断
- 起動時のDBマイグレーション

## 未実装

- エンドツーエンド暗号化（E2EE）
- Signal Protocol / PQXDH / Double Ratchet
- 端末ID・公開鍵・PreKey Bundleの登録と検証
- 1対1のプライベートチャット
- 暗号化ファイル送信
- アカウント復旧・パスワードリセット
- 専門家によるセキュリティレビュー

現在の共通テストルームは、ログインユーザー全員にメッセージを中継します。サーバー運営者が本文を読めるため、秘密の会話には使わないでください。

## 必要環境

- Node.js 24.22.1
- npm
- PostgreSQL 18（または互換性のあるサポート対象バージョン）

## ローカル起動

1. PostgreSQLに securechat データベースと接続ユーザーを作成します。
2. DATABASE_URL をローカルDBの接続文字列に設定します。
3. 依存パッケージをインストールし、DBマイグレーションを実行します。

```bash
npm install
npm run db:migrate
npm run dev
```

PowerShellでの接続文字列設定例：

```powershell
$env:DATABASE_URL = "postgresql://securechat_app:YOUR_PASSWORD@localhost:5432/securechat"
npm install
npm run db:migrate
npm run dev
```

ブラウザーで http://localhost:3000 を開き、「新規登録」からアカウントを作成します。パスワードは12〜128文字です。

## Renderへのデプロイ

リポジトリの render.yaml はRender Blueprintです。Render DashboardでNew → BlueprintからこのGitHubリポジトリを選択し、内容を確認して適用します。Web ServiceとPostgreSQLはSingaporeリージョンに作成され、DATABASE_URL はRenderから自動的に設定されます。起動時に未適用のDBマイグレーションが実行されます。

**料金・保存期間に注意:** このBlueprintは初期テスト用にPostgres Freeプランを指定しています。RenderのFree Postgresは作成から30日で期限切れになり、猶予期間終了後にデータが削除されます。継続利用する場合は期限前に有料プランへアップグレードするか、別のPostgreSQLサービスへ移行してください。

## ヘルスチェック

GET /api/health はアプリとPostgreSQLへの接続状態を返します。

## セキュリティ方針

- 独自の暗号アルゴリズムや鍵交換プロトコルを作りません。
- E2EEはSignalが公開する実装や、互換性・保守性を確認した検証済みライブラリを評価して採用します。
- クライアント側の秘密鍵をサーバーへ送らない設計を目指します。
- 鍵のバックアップ、端末追加、本人確認、失効、XSSと配信経路の保護も設計対象です。
- 認証機能が動くことと、メッセージがE2EEで保護されることは別です。
- 専門的なセキュリティレビューを完了するまでは、本番用途の安全性を保証しません。
