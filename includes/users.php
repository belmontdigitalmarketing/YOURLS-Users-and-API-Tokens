<?php
/**
 * User CRUD operations.
 *
 * Roles:
 *   admin       - full UI access, can manage all users & tokens
 *   integration - can only view their own account page; intended for API-only users
 *
 * Passwords are stored as YOURLS-compatible hashes (phpass) so the existing
 * yourls_check_password_hash() validation logic continues to work.
 */

if (!defined('YOURLS_ABSPATH')) {
    die();
}

const BDM_UAT_ROLES = array('admin', 'integration');

// ============================================================================
// QUERIES
// ============================================================================

function bdm_uat_get_user($id) {
    global $ydb;
    $row = $ydb->fetchObject(
        "SELECT * FROM `" . bdm_uat_users_table() . "` WHERE id = :id",
        array('id' => (int) $id)
    );
    return $row ?: null;
}

function bdm_uat_get_user_by_username($username) {
    global $ydb;
    $row = $ydb->fetchObject(
        "SELECT * FROM `" . bdm_uat_users_table() . "` WHERE username = :u",
        array('u' => (string) $username)
    );
    return $row ?: null;
}

function bdm_uat_get_all_users() {
    global $ydb;
    $rows = $ydb->fetchObjects(
        "SELECT * FROM `" . bdm_uat_users_table() . "` ORDER BY username ASC"
    );
    return $rows ?: array();
}

function bdm_uat_count_admins() {
    global $ydb;
    return (int) $ydb->fetchValue(
        "SELECT COUNT(*) FROM `" . bdm_uat_users_table() . "` WHERE role = 'admin'"
    );
}

// ============================================================================
// MUTATIONS
// ============================================================================

/**
 * Create a new user.
 *
 * @return array{ok: bool, error?: string, id?: int}
 */
function bdm_uat_create_user($username, $password, $role) {
    global $ydb;

    $username = trim((string) $username);
    $password = (string) $password;
    $role = (string) $role;

    if ($username === '') {
        return array('ok' => false, 'error' => 'Username is required.');
    }
    if (!preg_match('/^[a-zA-Z0-9_.\-]{1,64}$/', $username)) {
        return array('ok' => false, 'error' => 'Username must be 1-64 characters: letters, digits, underscore, dot, dash.');
    }
    if (strlen($password) < 8) {
        return array('ok' => false, 'error' => 'Password must be at least 8 characters.');
    }
    if (!in_array($role, BDM_UAT_ROLES, true)) {
        return array('ok' => false, 'error' => 'Invalid role.');
    }

    if (bdm_uat_get_user_by_username($username)) {
        return array('ok' => false, 'error' => 'A user with that username already exists.');
    }

    $now = gmdate('Y-m-d H:i:s');
    $hash = bdm_uat_hash_password($password);

    try {
        $ydb->fetchAffected(
            "INSERT INTO `" . bdm_uat_users_table() . "`
                (username, password_hash, role, created_at, updated_at)
             VALUES (:u, :p, :r, :c, :c)",
            array('u' => $username, 'p' => $hash, 'r' => $role, 'c' => $now)
        );
        return array('ok' => true, 'id' => (int) $ydb->lastInsertId());
    } catch (Exception $e) {
        bdm_uat_error_log('Create user failed: ' . $e->getMessage());
        return array('ok' => false, 'error' => 'Database error creating user.');
    }
}

/**
 * Update role and/or password on an existing user.
 * Pass null for fields that should remain unchanged.
 *
 * @return array{ok: bool, error?: string}
 */
function bdm_uat_update_user($id, $role = null, $password = null) {
    global $ydb;
    $id = (int) $id;

    $user = bdm_uat_get_user($id);
    if (!$user) {
        return array('ok' => false, 'error' => 'User not found.');
    }

    $sets = array();
    $params = array('id' => $id, 'u' => gmdate('Y-m-d H:i:s'));

    if ($role !== null) {
        if (!in_array($role, BDM_UAT_ROLES, true)) {
            return array('ok' => false, 'error' => 'Invalid role.');
        }
        // Guard: prevent demoting the last DB admin. Note this counts DB users
        // only - if you keep an emergency admin in user/config.php (recommended),
        // that one is not tracked here. See README "Emergency admin failsafe".
        if ($user->role === 'admin' && $role !== 'admin' && bdm_uat_count_admins() <= 1) {
            return array('ok' => false, 'error' => 'Cannot demote the last admin in the database. Promote another user to admin first.');
        }
        $sets[] = 'role = :r';
        $params['r'] = $role;
    }

    if ($password !== null) {
        if (strlen((string) $password) < 8) {
            return array('ok' => false, 'error' => 'Password must be at least 8 characters.');
        }
        $sets[] = 'password_hash = :p';
        $params['p'] = bdm_uat_hash_password($password);
    }

    if (empty($sets)) {
        return array('ok' => true); // No-op
    }

    $sets[] = 'updated_at = :u';
    $sql = "UPDATE `" . bdm_uat_users_table() . "` SET " . implode(', ', $sets) . " WHERE id = :id";

    try {
        $ydb->fetchAffected($sql, $params);
        return array('ok' => true);
    } catch (Exception $e) {
        bdm_uat_error_log('Update user failed: ' . $e->getMessage());
        return array('ok' => false, 'error' => 'Database error updating user.');
    }
}

/**
 * Delete a user and all their tokens.
 *
 * @return array{ok: bool, error?: string}
 */
function bdm_uat_delete_user($id) {
    global $ydb;
    $id = (int) $id;

    $user = bdm_uat_get_user($id);
    if (!$user) {
        return array('ok' => false, 'error' => 'User not found.');
    }
    if ($user->role === 'admin' && bdm_uat_count_admins() <= 1) {
        return array('ok' => false, 'error' => 'Cannot delete the last admin in the database. Promote another user to admin first.');
    }

    try {
        $ydb->fetchAffected(
            "DELETE FROM `" . bdm_uat_tokens_table() . "` WHERE user_id = :id",
            array('id' => $id)
        );
        $ydb->fetchAffected(
            "DELETE FROM `" . bdm_uat_users_table() . "` WHERE id = :id",
            array('id' => $id)
        );
        return array('ok' => true);
    } catch (Exception $e) {
        bdm_uat_error_log('Delete user failed: ' . $e->getMessage());
        return array('ok' => false, 'error' => 'Database error deleting user.');
    }
}

function bdm_uat_record_login($id) {
    global $ydb;
    try {
        $ydb->fetchAffected(
            "UPDATE `" . bdm_uat_users_table() . "` SET last_login_at = :t WHERE id = :id",
            array('t' => gmdate('Y-m-d H:i:s'), 'id' => (int) $id)
        );
    } catch (Exception $e) {
        // Non-fatal
        bdm_uat_debug_log('Record login failed: ' . $e->getMessage());
    }
}

// ============================================================================
// PASSWORD HASHING
// ============================================================================

/**
 * Hash a password using YOURLS's phpass implementation so it's
 * accepted by yourls_check_password_hash() on login.
 */
function bdm_uat_hash_password($password) {
    if (function_exists('yourls_phpass_hash')) {
        return yourls_phpass_hash($password);
    }
    // Fallback: PHP's password_hash (bcrypt). YOURLS check_password_hash
    // recognizes phpass-style hashes; for the fallback we'd need to verify
    // separately, but in practice yourls_phpass_hash() exists in 1.8+.
    return password_hash($password, PASSWORD_DEFAULT);
}
