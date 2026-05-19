<?php
/*
Plugin Name: Users & API Tokens
Plugin URI: https://github.com/Belmont-Digital/YOURLS-Users-and-API-Tokens
Description: Manage YOURLS users and per-integration API tokens from the admin dashboard. Each token is independently labeled, rotatable, and revocable - no more sharing the master signature with every CRM and webhook.
Version: 1.0.0
Author: Belmont Digital
Author URI: https://belmontdigitalmarketing.com
*/

// Prevent direct access
if (!defined('YOURLS_ABSPATH')) {
    die();
}

// ============================================================================
// CONFIGURATION
// ============================================================================

define('BDM_UAT_VERSION', '1.0.0');
define('BDM_UAT_DB_VERSION', 1);
define('BDM_UAT_DIR', __DIR__);

// Debug mode: add define('BDM_UAT_DEBUG', true); to config.php to enable
if (!defined('BDM_UAT_DEBUG')) {
    define('BDM_UAT_DEBUG', false);
}

// ============================================================================
// LOGGING
// ============================================================================

function bdm_uat_debug_log($message) {
    if (BDM_UAT_DEBUG) {
        error_log('Users & API Tokens DEBUG: ' . $message);
    }
}

function bdm_uat_error_log($message) {
    error_log('Users & API Tokens ERROR: ' . $message);
}

// ============================================================================
// INCLUDES
// ============================================================================

require_once BDM_UAT_DIR . '/includes/db.php';
require_once BDM_UAT_DIR . '/includes/users.php';
require_once BDM_UAT_DIR . '/includes/tokens.php';
require_once BDM_UAT_DIR . '/includes/auth.php';
require_once BDM_UAT_DIR . '/includes/admin.php';

// ============================================================================
// BOOTSTRAP
// ============================================================================

yourls_add_action('plugins_loaded', 'bdm_uat_bootstrap');

function bdm_uat_bootstrap() {
    // Ensure schema is up to date (idempotent; runs migration if needed)
    bdm_uat_maybe_install();

    // Inject DB users into the global so native password auth works
    bdm_uat_inject_users_into_globals();

    // Register admin pages
    yourls_register_plugin_page('bdm_users', 'Users & API Tokens', 'bdm_uat_render_page');
}

// API signature auth shunt - registered early, no DB dependency at this point
yourls_add_filter('shunt_is_valid_user', 'bdm_uat_auth_shunt');

// Enqueue our admin CSS on our pages
yourls_add_action('html_head', 'bdm_uat_enqueue_assets');

function bdm_uat_enqueue_assets() {
    if (!isset($_GET['page']) || $_GET['page'] !== 'bdm_users') {
        return;
    }
    $url = yourls_plugin_url(BDM_UAT_DIR) . '/assets/style.css?v=' . BDM_UAT_VERSION;
    echo '<link rel="stylesheet" href="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '">' . "\n";
}
