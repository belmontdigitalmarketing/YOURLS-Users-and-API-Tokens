<?php
/**
 * API token CRUD + validation.
 *
 * Tokens are 40-char hex strings (160 bits of entropy) generated via random_bytes.
 * Each user can have multiple labeled tokens. Tokens are revocable individually
 * via revoked_at timestamp; revoked tokens are kept for audit but no longer
 * validate.
 *
 * "Legacy" tokens (is_legacy=1) are the COOKIEKEY-derived signatures captured
 * during migration. They continue to work through both this plugin AND native
 * YOURLS auth until the user rotates COOKIEKEY in config.php.
 */

if (!defined('YOURLS_ABSPATH')) {
    die();
}

// ============================================================================
// QUERIES
// ============================================================================

function bdm_uat_get_token($id) {
    global $ydb;
    $row = $ydb->fetchObject(
        "SELECT * FROM `" . bdm_uat_tokens_table() . "` WHERE id = :id",
        array('id' => (int) $id)
    );
    return $row ?: null;
}

function bdm_uat_get_tokens_for_user($user_id) {
    global $ydb;
    $rows = $ydb->fetchObjects(
        "SELECT * FROM `" . bdm_uat_tokens_table() . "`
         WHERE user_id = :uid
         ORDER BY revoked_at IS NOT NULL, created_at DESC",
        array('uid' => (int) $user_id)
    );
    return $rows ?: array();
}

/**
 * Fetch all active (non-revoked) tokens joined with username.
 * Used by the auth shunt - kept small by skipping revoked rows.
 */
function bdm_uat_get_all_active_tokens() {
    global $ydb;
    $rows = $ydb->fetchObjects(
        "SELECT t.id, t.user_id, t.token, t.is_legacy, u.username
         FROM `" . bdm_uat_tokens_table() . "` t
         INNER JOIN `" . bdm_uat_users_table() . "` u ON u.id = t.user_id
         WHERE t.revoked_at IS NULL"
    );
    return $rows ?: array();
}

// ============================================================================
// MUTATIONS
// ============================================================================

/**
 * Create a new token for a user.
 *
 * @return array{ok: bool, error?: string, token?: string, id?: int}
 *         On success, `token` is the plaintext token returned ONCE for display.
 */
function bdm_uat_create_token($user_id, $label) {
    global $ydb;

    $user_id = (int) $user_id;
    $label = trim((string) $label);

    if (!bdm_uat_get_user($user_id)) {
        return array('ok' => false, 'error' => 'User not found.');
    }
    if ($label === '') {
        return array('ok' => false, 'error' => 'Label is required.');
    }
    if (strlen($label) > 100) {
        return array('ok' => false, 'error' => 'Label must be 100 characters or fewer.');
    }

    $token = bdm_uat_generate_token();
    $now = gmdate('Y-m-d H:i:s');

    try {
        $ydb->fetchAffected(
            "INSERT INTO `" . bdm_uat_tokens_table() . "`
                (user_id, label, token, created_at, is_legacy)
             VALUES (:uid, :label, :tok, :c, 0)",
            array('uid' => $user_id, 'label' => $label, 'tok' => $token, 'c' => $now)
        );
        return array(
            'ok'    => true,
            'token' => $token,
            'id'    => (int) $ydb->lastInsertId(),
        );
    } catch (Exception $e) {
        bdm_uat_error_log('Create token failed: ' . $e->getMessage());
        return array('ok' => false, 'error' => 'Database error creating token.');
    }
}

/**
 * Regenerate: revoke the old token row and create a fresh one with the same label.
 * Returns the new plaintext token (display once).
 *
 * Transactional: if creating the new row fails after revoking the old one,
 * the revoke is rolled back so the user is never left without a working token.
 */
function bdm_uat_regenerate_token($id) {
    global $ydb;

    $token = bdm_uat_get_token($id);
    if (!$token) {
        return array('ok' => false, 'error' => 'Token not found.');
    }

    // YOURLS YDB extends PDO, so standard transaction methods are available.
    $in_transaction = false;
    try {
        $ydb->beginTransaction();
        $in_transaction = true;
    } catch (Exception $e) {
        // Fallback: run sequentially. Caller accepts the trade-off (rare).
        bdm_uat_debug_log('Regenerate: transaction unavailable, running sequentially.');
    }

    $revoke_result = bdm_uat_revoke_token($id);
    if (!$revoke_result['ok']) {
        if ($in_transaction) $ydb->rollBack();
        return $revoke_result;
    }

    $create_result = bdm_uat_create_token($token->user_id, $token->label);
    if (!$create_result['ok']) {
        if ($in_transaction) $ydb->rollBack();
        return $create_result;
    }

    if ($in_transaction) $ydb->commit();
    return $create_result;
}

function bdm_uat_revoke_token($id) {
    global $ydb;
    $id = (int) $id;

    $token = bdm_uat_get_token($id);
    if (!$token) {
        return array('ok' => false, 'error' => 'Token not found.');
    }
    if ($token->revoked_at !== null) {
        return array('ok' => true); // Already revoked - idempotent
    }

    try {
        $ydb->fetchAffected(
            "UPDATE `" . bdm_uat_tokens_table() . "`
             SET revoked_at = :t WHERE id = :id",
            array('t' => gmdate('Y-m-d H:i:s'), 'id' => $id)
        );
        return array('ok' => true);
    } catch (Exception $e) {
        bdm_uat_error_log('Revoke token failed: ' . $e->getMessage());
        return array('ok' => false, 'error' => 'Database error revoking token.');
    }
}

/**
 * Record that a token was successfully used (last_used_at).
 * Called from the auth shunt after a successful match.
 */
function bdm_uat_record_token_use($id) {
    global $ydb;
    try {
        $ydb->fetchAffected(
            "UPDATE `" . bdm_uat_tokens_table() . "`
             SET last_used_at = :t WHERE id = :id",
            array('t' => gmdate('Y-m-d H:i:s'), 'id' => (int) $id)
        );
    } catch (Exception $e) {
        // Non-fatal; logged at debug level
        bdm_uat_debug_log('Record token use failed: ' . $e->getMessage());
    }
}

// ============================================================================
// GENERATION
// ============================================================================

/**
 * Generate a cryptographically random 40-character hex token (160 bits).
 */
function bdm_uat_generate_token() {
    return bin2hex(random_bytes(20));
}

/**
 * Mask a token for display: show first 4 and last 4 chars, mask the middle.
 * E.g. "a1b2...f9e8"
 */
function bdm_uat_mask_token($token) {
    $token = (string) $token;
    $len = strlen($token);
    if ($len <= 8) {
        return str_repeat('*', $len);
    }
    return substr($token, 0, 4) . str_repeat('*', max(4, $len - 8)) . substr($token, -4);
}
