<?php
/**
 * Database schema, installation, and migration for Users & API Tokens.
 *
 * Tables:
 *   {prefix}bdm_users         - user accounts
 *   {prefix}bdm_user_tokens   - per-user API tokens (multiple per user)
 *
 * The install is idempotent: it checks an option for schema version and only
 * runs CREATE TABLE / migration when needed. Safe to call on every load.
 */

if (!defined('YOURLS_ABSPATH')) {
    die();
}

// ============================================================================
// TABLE NAME HELPERS
// ============================================================================

function bdm_uat_users_table() {
    return bdm_uat_table_prefix() . 'bdm_users';
}

function bdm_uat_tokens_table() {
    return bdm_uat_table_prefix() . 'bdm_user_tokens';
}

function bdm_uat_table_prefix() {
    if (defined('YOURLS_DB_PREFIX') && YOURLS_DB_PREFIX) {
        return YOURLS_DB_PREFIX;
    }
    // Derive from the canonical URL table name as a fallback
    if (defined('YOURLS_DB_TABLE_URL')) {
        return str_replace('url', '', YOURLS_DB_TABLE_URL);
    }
    return 'yourls_';
}

// ============================================================================
// INSTALL / MIGRATION
// ============================================================================

/**
 * Run install or migration if schema version is older than current.
 * Idempotent and safe to call on every page load.
 */
function bdm_uat_maybe_install() {
    $current = (int) yourls_get_option('bdm_uat_db_version');
    if ($current >= BDM_UAT_DB_VERSION) {
        return;
    }

    if ($current < 1) {
        if (!bdm_uat_install_v1()) {
            return; // Failure - leave the version untouched so we retry next load
        }
    }

    yourls_update_option('bdm_uat_db_version', BDM_UAT_DB_VERSION);
}

/**
 * Initial install: create tables and migrate $yourls_user_passwords entries.
 * Returns true on success, false on table-creation failure.
 */
function bdm_uat_install_v1() {
    global $ydb;

    $users_table = bdm_uat_users_table();
    $tokens_table = bdm_uat_tokens_table();
    $charset = bdm_uat_charset_collate();

    $users_sql = "CREATE TABLE IF NOT EXISTS `$users_table` (
        `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
        `username` VARCHAR(64) NOT NULL,
        `password_hash` VARCHAR(255) NOT NULL,
        `role` VARCHAR(20) NOT NULL DEFAULT 'integration',
        `created_at` DATETIME NOT NULL,
        `updated_at` DATETIME NOT NULL,
        `last_login_at` DATETIME DEFAULT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `username` (`username`)
    ) $charset;";

    $tokens_sql = "CREATE TABLE IF NOT EXISTS `$tokens_table` (
        `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
        `user_id` INT UNSIGNED NOT NULL,
        `label` VARCHAR(100) NOT NULL,
        `token` VARCHAR(64) NOT NULL,
        `created_at` DATETIME NOT NULL,
        `last_used_at` DATETIME DEFAULT NULL,
        `revoked_at` DATETIME DEFAULT NULL,
        `is_legacy` TINYINT(1) NOT NULL DEFAULT 0,
        PRIMARY KEY (`id`),
        UNIQUE KEY `token` (`token`),
        KEY `user_id` (`user_id`)
    ) $charset;";

    try {
        $ydb->fetchAffected($users_sql);
        $ydb->fetchAffected($tokens_sql);
    } catch (Exception $e) {
        bdm_uat_error_log('Table creation failed: ' . $e->getMessage());
        return false;
    }

    bdm_uat_migrate_config_users();
    return true;
}

/**
 * Walk $yourls_user_passwords and create matching DB users.
 * For each one, capture the COOKIEKEY-derived signature as a Legacy token
 * so existing integrations keep working until the user rotates COOKIEKEY.
 */
function bdm_uat_migrate_config_users() {
    global $yourls_user_passwords, $ydb;

    if (!is_array($yourls_user_passwords) || empty($yourls_user_passwords)) {
        return;
    }

    $users_table = bdm_uat_users_table();
    $tokens_table = bdm_uat_tokens_table();
    $now = gmdate('Y-m-d H:i:s');

    foreach ($yourls_user_passwords as $username => $password_hash) {
        $username = (string) $username;
        if ($username === '' || !is_string($password_hash)) {
            continue;
        }

        // Skip if already in DB (idempotent re-run)
        $existing = $ydb->fetchValue(
            "SELECT id FROM `$users_table` WHERE username = :u",
            array('u' => $username)
        );
        if ($existing) {
            continue;
        }

        try {
            $ydb->fetchAffected(
                "INSERT INTO `$users_table` (username, password_hash, role, created_at, updated_at)
                 VALUES (:u, :p, 'admin', :c, :c)",
                array('u' => $username, 'p' => $password_hash, 'c' => $now)
            );
            $user_id = $ydb->lastInsertId();
        } catch (Exception $e) {
            bdm_uat_error_log("Migrating user '$username' failed: " . $e->getMessage());
            continue;
        }

        // Capture the user's existing COOKIEKEY-derived signature as a Legacy token
        if (function_exists('yourls_auth_signature')) {
            $legacy = yourls_auth_signature($username);
            if ($legacy) {
                try {
                    $ydb->fetchAffected(
                        "INSERT INTO `$tokens_table`
                            (user_id, label, token, created_at, is_legacy)
                         VALUES (:uid, :label, :tok, :c, 1)",
                        array(
                            'uid'   => $user_id,
                            'label' => 'Legacy (pre-plugin)',
                            'tok'   => $legacy,
                            'c'     => $now,
                        )
                    );
                } catch (Exception $e) {
                    // Duplicate token (two users somehow share a signature) - skip silently
                    bdm_uat_debug_log("Legacy token insert for '$username' skipped: " . $e->getMessage());
                }
            }
        }
    }
}

function bdm_uat_charset_collate() {
    $cc = '';
    if (defined('YOURLS_DB_CHARSET') && YOURLS_DB_CHARSET) {
        $cc = "DEFAULT CHARACTER SET " . YOURLS_DB_CHARSET;
    }
    if (defined('YOURLS_DB_COLLATE') && YOURLS_DB_COLLATE) {
        $cc .= " COLLATE " . YOURLS_DB_COLLATE;
    }
    return $cc;
}
