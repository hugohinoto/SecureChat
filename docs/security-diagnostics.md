# SecureChat security diagnostics

The management console combines runtime D1 checks with independent scanners in GitHub Actions. It is a layered diagnostic, not a penetration-test certification.

## Runtime checks in the admin console

- D1 query health and SQLite `quick_check`
- SQLite foreign-key integrity and required foreign-key definitions
- Required table/column inventory against the checked-in migration schema
- Required index inventory
- D1 migration history (`d1_migrations`)
- Sensitive-data encryption migration state
- Signed identity-key coverage
- Expired-session cleanup
- One-hour encrypted-message retention invariants
- Canonical conversation-pair uniqueness
- Application encryption and OTP secrets
- Key rotation, forward secrecy, passkey and platform-log limitations

Each check is isolated. A failed query is shown as an error/incomplete check; it is never converted into a passing result. Overall status is calculated from every check, including unavailable checks.

## Independent engines

The `.github/workflows/security-scan.yml` workflow runs:

- **Semgrep**: static application security analysis plus a project-specific taint rule for untrusted values reaching D1 SQL query text.
- **SQLFluff**: SQLite-dialect parsing of every D1 migration and static SQL statement extracted from the Worker source. Dynamic query expressions are excluded from parser extraction and checked by Semgrep instead.
- **OWASP ZAP Baseline**: passive DAST against the public production site on main pushes, scheduled runs and manual runs. It does not run active attack payloads against production. It does not authenticate to the admin API, so it cannot claim protected routes were tested.

The scan artifacts are retained in the GitHub Actions run. Findings and scanner failures must be reviewed; a scan that was skipped, unavailable, or did not complete is not a clean bill of health.

## Connect latest GitHub scan status to the admin console

The Worker needs a read-only GitHub fine-grained personal access token so it can ask the GitHub Actions API for the latest main-branch scanner run.

1. In GitHub, create a fine-grained token for repository `hugohinoto/SecureChat`.
2. Grant **Actions: Read-only**. Do not grant Contents write, Administration, or other write permissions.
3. In Cloudflare, open the `securechat` Worker → Settings → Variables and Secrets.
4. Add a **Secret** named `SECURITY_SCAN_GITHUB_TOKEN` and paste the token.
5. Redeploy the Worker so the runtime can read the secret.

Until this secret is configured and a main-branch scan has completed, the admin console deliberately marks external scanner status as unverified/warning. The token is used only server-side and is never returned to the browser.

## Limitations

- Semgrep Community scanning does not provide all cross-file/dataflow analysis available in paid products.
- SQLFluff parses the repository's migration files and statically extractable D1 statements; it does not prove query authorization or business logic.
- ZAP Baseline is passive and currently tests the public production surface only. Authenticated DAST should run against an isolated test environment with synthetic accounts before active scanning is introduced.
- Platform-level Cloudflare logs, WAF events, DNS controls, email authentication, and account security settings require their own Cloudflare-side checks.
