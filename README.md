# YOURLS Users & API Tokens

Manage YOURLS users and per-integration API tokens from the admin dashboard. Each token is independently **labeled**, **rotatable**, and **revocable** — no more sharing the master signature with every CRM, webhook, and Zap.

## Why this exists

Stock YOURLS stores users in `user/config.php` and derives every user's API signature token from a single shared `YOURLS_COOKIEKEY` constant. Two consequences:

1. **Adding a user** means SSHing in and editing PHP.
2. **Rotating a token** (because one integration's credentials leaked) rotates *everyone's* tokens at once — there's no per-integration revocation.

This plugin fixes both. Users and tokens live in dedicated database tables, each token is independent random bytes (not derived from `COOKIEKEY`), and the entire workflow lives in the admin UI.

## Features

- Create / edit / delete users from the **Users & API Tokens** plugin page
- Two roles: **admin** (full UI access) and **integration** (API-only; self-service token management for their own account)
- **Multiple labeled tokens per user** — e.g. one user named `flowlu` with separate tokens for `Production`, `Staging`, `Webhook receiver`
- **Per-token rotation and revocation** — kill one token without affecting the others
- **Last-used timestamp** per token, so you can see which tokens are actually in use before retiring them
- **Coexists with native YOURLS auth** — your existing `$yourls_user_passwords` entries and `COOKIEKEY`-derived signatures keep working during migration
- **"Show once" UX** — newly generated tokens are displayed exactly once; the admin list shows a masked preview (`a1b2…f9e8`) thereafter
- Cryptographically random tokens (`random_bytes(20)` → 40-char hex)
- Constant-time signature comparison (`hash_equals`)

## Requirements

- YOURLS **1.8 or later** (uses `\YOURLS\Database\YDB`, the modern PDO-backed DB layer)
- PHP 7.2+ (`random_bytes`, `hash_equals`)

## Installation

1. Copy the `YOURLS-Users-and-API-Tokens` folder into your YOURLS `user/plugins/` directory.
2. Sign in to the YOURLS admin, go to **Plugins**, and activate **Users & API Tokens**.
3. On activation the plugin creates two tables (`{prefix}bdm_users`, `{prefix}bdm_user_tokens`) and migrates every entry from `$yourls_user_passwords` into the database as **admin** users. For each migrated user it also captures their current `COOKIEKEY`-derived signature as a **Legacy** token, so existing integrations keep authenticating without interruption.
4. Visit **Manage Plugins → Users & API Tokens** to manage users.

The plugin **does not** modify `user/config.php`. Your existing entries remain there as a fallback during migration.

## Usage

### Create a dedicated user for an integration

> *Recommended pattern: one DB user per external system (Flowlu, Groundhogg, Zapier, …) rather than reusing your admin account.*

1. Go to **Plugins → Users & API Tokens**.
2. Under **Create user**, enter a username, a password (min 8 chars), and choose role **integration** (the integration role can log in to manage its own token, but cannot see other users).
3. Click **Create user** — you land on the new user's detail page.

### Generate an API token

1. From the user's detail page, under **Create new token**, enter a descriptive label (e.g. *"Flowlu Production"*).
2. Click **Generate token**.
3. **The plaintext token is shown exactly once** in a green confirmation banner — copy it immediately into your integration's config. After you navigate away, the admin UI only shows a masked preview.

### Rotate or revoke a token

- **Regenerate** — creates a new token with the same label, immediately invalidates the old value. Use when a token leaks, or on a regular rotation schedule.
- **Revoke** — marks the token revoked. The row is kept for audit; the token stops authenticating immediately.

Both actions are confirmed in the browser before submitting.

## Using API tokens

Tokens work in both YOURLS signature modes — drop the token in place of where you'd use the master signature today.

**Plain (lazy) mode** — pass the token directly:

```
GET /yourls-api.php?signature=YOUR_TOKEN&action=shorturl&url=https://example.com&format=json
```

**Hashed/timestamped mode** (recommended for public-facing integrations):

```
signature = hash('sha256', timestamp . token)
GET /yourls-api.php?signature=HASH&timestamp=TS&action=shorturl&...
```

The plugin checks every active (non-revoked) token in the database and accepts a request as soon as one matches. After a successful match, `last_used_at` is updated and `yourls_set_user()` is called so downstream YOURLS code sees the same state as a native auth success.

> **Replay protection:** plain mode has none — anyone who captures one valid request URL can replay it until the token is rotated. This matches native YOURLS lazy-mode behavior. Prefer timestamped mode for integrations that traverse logs, proxies, or untrusted networks.

## Retiring the Legacy token (important)

When the plugin migrates `$yourls_user_passwords`, it captures each user's current `COOKIEKEY`-derived signature as a token labeled **Legacy (pre-plugin)**. This is the bridge that keeps existing integrations working while you migrate them.

**However**: native YOURLS auth still independently accepts that `COOKIEKEY`-derived signature even after you click *Revoke* on the Legacy row, because YOURLS computes it on the fly from `COOKIEKEY + username`. The plugin can't intercept what it doesn't own.

To fully retire pre-plugin tokens:

1. Generate **new** tokens for each integration via the UI.
2. Migrate each integration (Flowlu, Groundhogg, Zapier, …) to its new token. Watch the *Last used* column to confirm the Legacy token is no longer in use.
3. Once all integrations are off the Legacy token, **rotate `YOURLS_COOKIEKEY`** in `user/config.php` — generate a fresh value from <https://api.yourls.org/services/cookiekey/1.0/> and paste it in.
4. The Legacy token is now permanently invalid via every code path.

The plugin surfaces an inline warning on every active Legacy token row so you don't forget this step.

## Security notes

- Tokens are stored **as plaintext** in the database. YOURLS's timestamped signature mode requires the server to recompute `hash(algo, timestamp . token)` and compare to the request, so a hash-only store wouldn't work. The trust boundary is the same as `user/config.php` (anyone with DB or filesystem access can recover credentials).
- Token comparisons use `hash_equals` (constant-time) on every iteration. This mitigates timing-based token discovery.
- Tokens are generated from `random_bytes(20)` — 160 bits of entropy, hex-encoded to 40 characters.
- All admin mutations are POST-only and protected by YOURLS nonces (`yourls_create_nonce` / `yourls_verify_nonce`).
- The plugin does **not** add new public endpoints. All UI lives behind the existing YOURLS admin login.

## Emergency admin failsafe

If the database becomes unreachable or you somehow lock yourself out of the UI:

- Any user defined **only** in `user/config.php`'s `$yourls_user_passwords` (i.e. *not* also in the `bdm_users` table) continues to log in via native YOURLS auth.
- The plugin grants UI access to such users as **admin** by default (since they have implicit admin via native YOURLS).

> **Recommended setup:** keep a single emergency admin like `emergency_admin` in `config.php` only — never migrate it to the DB. This is your get-out-of-jail card.

## Uninstall

Deactivating the plugin leaves the DB tables intact (so reactivating restores your users). To fully purge the plugin's data:

```sql
DROP TABLE {prefix}bdm_user_tokens;
DROP TABLE {prefix}bdm_users;
DELETE FROM {prefix}options WHERE option_name = 'bdm_uat_db_version';
```

Replace `{prefix}` with your YOURLS DB prefix (default `yourls_`).

## Configuration flags

Add these to `user/config.php` to override defaults:

```php
// Enable verbose error_log output for debugging
define('BDM_UAT_DEBUG', true);
```

## Troubleshooting

**"Token works in the UI but API rejects it"**
Confirm the request is hitting `yourls-api.php` (not the admin endpoints) and that the `signature` parameter is exact-match. Enable `BDM_UAT_DEBUG` to see plugin-side log lines.

**"After activation, an API call still works with the old master signature"**
That's the intended migration behavior — the Legacy token is accepted. See [Retiring the Legacy token](#retiring-the-legacy-token-important).

**"I get 'Cannot demote/delete the last remaining admin'"**
The plugin refuses operations that would leave the system with zero admin-role users in the DB. Promote another user to admin first, or add an `emergency_admin` to `config.php`.

**"Plugin page doesn't load / blank screen"**
Check the PHP error log for `Users & API Tokens ERROR:` entries. The most common cause is a `CREATE TABLE` failure — confirm the database user has DDL privileges on first activation.

## License

MIT — see [LICENSE](LICENSE).

## Author

Built by [Belmont Digital](https://belmontdigitalmarketing.com) for the YOURLS short-link installs powering our CRM proposal-link tracking. Issues and PRs welcome.
