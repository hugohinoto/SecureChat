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
