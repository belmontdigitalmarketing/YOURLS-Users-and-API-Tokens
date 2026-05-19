<?php
/**
 * YOURLS authentication hooks.
 *
 * Two integration points:
 *
 *   1. API signature auth   -> shunt yourls_is_valid_user when the request
 *                              is an API call carrying a signature parameter.
 *
 *   2. Admin password auth  -> inject DB users into $yourls_user_passwords
 *                              global on plugins_loaded. YOURLS's native
 *                              yourls_check_password_hash() then validates
 *                              against our hashes transparently.
 *
 * Coexistence: if no DB row matches the incoming signature, we return the
 * original shunt value (false) so YOURLS's native auth runs and any
 * COOKIEKEY-derived signatures still validate. This is intentional during
 * migration - revoke a Legacy token from the UI AND rotate COOKIEKEY to
 * fully retire pre-plugin tokens.
 */

if (!defined('YOURLS_ABSPATH')) {
    die();
}

// ============================================================================
// API SIGNATURE SHUNT
// ============================================================================

/**
 * Filter callback for shunt_is_valid_user.
 *
 * Returning a non-false value short-circuits yourls_is_valid_user(). Returning
 * the original (default-false) value lets YOURLS's native auth run.
 *
 * We only intervene when:
 *   - the request is an API call (yourls_is_API())
 *   - a `signature` parameter is present
 *
 * For timestamped requests we recompute hash(algo, timestamp.token) per token
 * and compare with hash_equals. For plain (lazy) requests we compare the token
 * directly with hash_equals against each stored token.
 */
function bdm_uat_auth_shunt($shunt_result) {
    // Only handle API requests; cookie/password login goes through native auth.
    if (!function_exists('yourls_is_API') || !yourls_is_API()) {
        return $shunt_result;
    }

    $signature = isset($_REQUEST['signature']) ? (string) $_REQUEST['signature'] : '';
    if ($signature === '') {
        return $shunt_result;
    }

    $timestamp = isset($_REQUEST['timestamp']) ? (string) $_REQUEST['timestamp'] : '';

    // For timestamped requests, enforce the time window BEFORE iterating tokens.
    if ($timestamp !== '') {
        $nonce_life = defined('YOURLS_NONCE_LIFE') ? (int) YOURLS_NONCE_LIFE : 43200;
        $nonce_life = (int) yourls_apply_filter('nonce_life', $nonce_life);
        if (abs(time() - (int) $timestamp) > $nonce_life) {
            return $shunt_result;
        }
    }

    $hash_algo = function_exists('yourls_hmac_algo') ? yourls_hmac_algo() : 'sha256';

    $tokens = bdm_uat_get_all_active_tokens();
    foreach ($tokens as $tok) {
        $candidate = ($timestamp !== '')
            ? hash($hash_algo, $timestamp . $tok->token)
            : $tok->token;

        if (hash_equals($candidate, $signature)) {
            bdm_uat_authenticate_via_token($tok);
            return true;
        }
    }

    // No match - fall through to native auth (handles COOKIEKEY signatures).
    return $shunt_result;
}

/**
 * Mark a token as just-used and register the authenticated user with YOURLS
 * so downstream code paths see the same state as a native auth success.
 */
function bdm_uat_authenticate_via_token($tok) {
    bdm_uat_record_token_use($tok->id);

    // Prefer yourls_set_user() - it defines YOURLS_USER, runs auth side effects,
    // and matches what native yourls_is_valid_user() does on success.
    if (function_exists('yourls_set_user')) {
        yourls_set_user($tok->username);
    } elseif (!defined('YOURLS_USER')) {
        define('YOURLS_USER', $tok->username);
    }

    bdm_uat_debug_log("API auth via token '{$tok->username}' (token id {$tok->id})");
}

// ============================================================================
// PASSWORD AUTH (via $yourls_user_passwords injection)
// ============================================================================

/**
 * Add DB users to the global $yourls_user_passwords array so native
 * yourls_check_username_password() validates against our stored hashes.
 *
 * Precedence: DB users overwrite same-named config.php entries. Rationale -
 * password changes made through the plugin UI must take effect immediately.
 * Keep an "emergency_admin" user (or similar) ONLY in config.php as a failsafe
 * for when the DB is unreachable.
 */
function bdm_uat_inject_users_into_globals() {
    global $yourls_user_passwords;

    if (!is_array($yourls_user_passwords)) {
        $yourls_user_passwords = array();
    }

    $users = bdm_uat_get_all_users();
    foreach ($users as $u) {
        $yourls_user_passwords[$u->username] = $u->password_hash;
    }
}

// ============================================================================
// INTEGRATION-ROLE PAGE RESTRICTION
// ============================================================================

/**
 * Integration-role users may only see our plugin page in the admin UI.
 * Any other admin page (tools.php, plugins.php list, index.php shortener,
 * etc.) bounces them back to the plugin page via yourls_redirect().
 *
 * Why: native YOURLS has no role concept. Without this guard an
 * "integration" user can visit /admin/tools.php and read their
 * COOKIEKEY-derived signature - which the plugin cannot revoke,
 * defeating the per-integration token model. They can also activate
 * arbitrary plugins from /admin/plugins.php, which is a clear
 * privilege escalation path.
 *
 * We hook pre_html_head because that's the first action YOURLS fires
 * after authentication has run but before any output - allowing a
 * clean Location: redirect.
 *
 * Allowed contexts can be extended via the BDM_UAT_INTEGRATION_ALLOWED
 * constant (comma-separated context names) in user/config.php. The
 * plugin page is always allowed.
 */
yourls_add_action('pre_html_head', 'bdm_uat_restrict_integration_pages');

function bdm_uat_restrict_integration_pages($args = null) {
    // Emergency bypass: append ?bdm_norestrict=1 to any admin URL to skip this guard.
    if (!empty($_GET['bdm_norestrict'])) {
        return;
    }

    // YOURLS quirk: yourls_do_action('pre_html_head', $context, $title) wraps
    // those args into a single array and passes it as our first parameter.
    // So $args here is ['plugin_page_bdm_users', 'Users & API Tokens'], not
    // separate positional values. Unwrap it.
    if (is_array($args)) {
        $context = isset($args[0]) ? (string) $args[0] : '';
    } else {
        $context = (string) $args;
    }

    // Unauthenticated (login screen, etc.) - nothing to enforce.
    if (!defined('YOURLS_USER') || YOURLS_USER === '' || YOURLS_USER === false) {
        return;
    }

    // Allow any plugin page (ours is plugin_page_bdm_users). Prefix match is
    // intentional: if YOURLS ever changes the convention, we won't break.
    if ($context !== '' && strpos($context, 'plugin_page_') === 0) {
        return;
    }

    // Extra allowlist via config.php constant (comma-separated context names).
    if (defined('BDM_UAT_INTEGRATION_ALLOWED') && BDM_UAT_INTEGRATION_ALLOWED) {
        foreach (explode(',', BDM_UAT_INTEGRATION_ALLOWED) as $extra) {
            if (trim($extra) === $context) {
                return;
            }
        }
    }

    // Only restrict integration-role users. Admins and config-only emergency
    // admins (no DB row) get full access.
    $user = bdm_uat_get_user_by_username(YOURLS_USER);
    if (!$user || $user->role !== 'integration') {
        return;
    }

    $target = yourls_admin_url('plugins.php') . '?page=bdm_users';
    bdm_uat_debug_log("Restricting integration user '" . YOURLS_USER . "' from ctx='$context' -> $target");
    yourls_redirect($target, 302);
    exit;
}
