# SecureChat deployment sequence

## Production Worker and D1 migrations

The D1 binding is named `DB` in `wrangler.jsonc`. Production schema migrations must run before the new Worker code is published, because the multi-device and unread-message routes require migration 0011.

The repository's deployment script now runs:

```sh
npm run cf:d1:migrate:remote
wrangler deploy
```

For Cloudflare Workers Builds, set **Settings → Builds → Deploy command** to:

```sh
npm run deploy
```

Do not leave the Deploy command as a bare `wrangler deploy` for releases that change D1 schema. The script uses Wrangler's migration history to apply only pending files and stops the deploy if migrations fail.

Before the first production rollout of migration 0011, verify that the existing migrations 0001–0010 are recorded in the D1 `d1_migrations` table. If the database schema was applied manually through the dashboard rather than with Wrangler, first reconcile the migration history; do not let Wrangler replay the existing ALTER TABLE migrations blindly.

Migration 0011 is additive:
- Adds a signed key-transition chain and password-encrypted identity backup envelope to `user_keys`.
- Creates `conversation_reads` and its lookup index for per-user unread cursors.
- Does not rewrite or delete existing chat messages or identity keys.

## Independent scanner status in the admin console

To display the latest Semgrep, SQLFluff, and OWASP ZAP job results, add a Cloudflare Worker Secret called `SECURITY_SCAN_GITHUB_TOKEN` with a fine-grained GitHub token scoped to `hugohinoto/SecureChat` and **Actions: Read-only** permission. Do not grant write permissions. Without this secret, scanner linkage remains explicitly unverified.

## Notification limits

Unread counts are persisted per conversation and shown in the chat list. Browser notifications work while SecureChat is open in a browser tab and the user has granted notification permission. This release does not implement Web Push or delivery after the browser has fully closed.


## Application data-encryption key rotation

This rotation applies only to application-stored sensitive fields (announcement content, admin audit details, and bug-report payloads). It does **not** rotate chat identity keys and does not provide chat forward secrecy.

1. Keep the existing `APP_DATA_ENCRYPTION_KEY` (generation v1) unchanged and store a protected offline backup. Never paste key material into GitHub, chat, or logs.
2. Generate a new random secret with at least 32 bytes of entropy and add it as the Worker Secret `APP_DATA_ENCRYPTION_KEY_V2`.
3. Keep the non-secret Worker variable `APP_DATA_ENCRYPTION_ACTIVE_VERSION=2` in the top-level `vars` section of `wrangler.jsonc` (this project deploys the default Production environment). Do not rely only on a dashboard variable: Wrangler treats its config as the source of truth and can overwrite dashboard variables on the next deploy. Do not remove v1.
4. Deploy the Worker. Wrangler deployments preserve Secrets that are not explicitly deleted, so keep both v1 and v2 Secret names configured. The existing five-minute Cron migration re-encrypts up to 10 announcements, 20 audit records, and 20 bug reports per run.
5. Re-run the admin security diagnostic. `key-rotation` remains warning while older encrypted rows remain, becomes critical if an old key required by stored ciphertext is missing, and passes only after no ciphertext from an older generation remains. The separate `sensitive-data-migration` check must also pass.
6. Keep v1 available through a recovery period and retain a protected backup. Do not delete v1 merely because v2 is active; only consider retirement after the diagnostics show zero old-generation records, backups are verified, and recovery has been tested.

The Worker cannot create or change Cloudflare Secrets on your behalf. Add `APP_DATA_ENCRYPTION_KEY_V2` as a Production Secret in **Workers & Pages → securechat → Settings → Variables and Secrets**. The non-secret active-version variable is maintained in `wrangler.jsonc` and deployed from the repository. Do not share secret values.

## Cloudflare Invocation Logs and application logs

`wrangler.jsonc` keeps application log collection enabled but explicitly sets `observability.logs.invocation_logs=false` to disable automatically generated invocation logs. Worker source logging is restricted by a regression test to fixed literal labels; do not add request objects, headers, cookies, user IDs, message bodies, key material, or raw exception objects to `console.*`.

The application cannot inspect Cloudflare account-level log access permissions, retention settings, or verify which configuration is currently deployed. Check **Workers & Pages → securechat → Observability → Logs** and the Cloudflare account roles separately. The diagnostic intentionally remains `warning / incomplete` rather than claiming those platform controls passed.


## Forward-secrecy v2 rollout status

The device-scoped Olm/Megolm implementation is self-hosted as a browser WASM bundle generated by `npm run build`. The deployment script builds the bundle, applies D1 migrations, and then deploys the Worker.

The checked-in `wrangler.jsonc` currently sets `SECURECHAT_CRYPTO_V2_ENABLED=true`. This configuration alone is not evidence that the production Worker is running that setting or that the security release gates have passed. Verify the deployed Worker configuration and complete the independent review plus multi-device browser E2E tests before claiming production forward secrecy. The Worker now queues a revocation control event for every surviving device in the affected conversations; clients invalidate the active Megolm outbound session when they next sync, then share a fresh key without the revoked device. This is asynchronous (offline devices cannot process the event until they reconnect), and it has not yet passed multi-device browser E2E tests or independent integration review.

Do not enable v2 by changing only a dashboard variable. When the release owner authorizes rollout after the gates pass, the feature flag must be changed and reviewed in Wrangler configuration, and the Worker plus migration 0012 must be deployed together. Existing v1 messages remain readable through the legacy v1 decrypt path; conversation cutover requires approval by both account owners.


For this branch, deploy through the package script rather than invoking Wrangler directly: `npm install` followed by `npm run deploy`. The script builds `public/crypto-v2.bundle.js` and the WASM asset, applies remote D1 migrations, and then deploys. The generated bundle is a build artifact and is not committed. The production crypto v2 feature flag remains false, so this deployment only ships the guarded implementation and does not switch any conversation to v2.
