# Security Policy

Please report vulnerabilities privately via GitHub **Security → Report a vulnerability** — do not open a public issue.

Never commit secrets: `ADMIN_PASSWORD_HASH` lives only in Cloudflare Worker Secrets (`wrangler secret put`), and `.dev.vars` is git-ignored.
If a hash or token was ever committed, rotate it (see "Recovery" in the README) and revoke sessions.
