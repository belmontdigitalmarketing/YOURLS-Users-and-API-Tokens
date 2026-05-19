<?php
/**
 * Uninstall handler.
 *
 * YOURLS calls this when the plugin is removed via the Plugins page. We
 * intentionally do NOT drop the bdm_users / bdm_user_tokens tables here -
 * user data should survive an accidental uninstall and a manual reinstall
 * picks the data back up.
 *
 * To fully purge the plugin's data, drop the tables manually:
 *   DROP TABLE {prefix}bdm_user_tokens;
 *   DROP TABLE {prefix}bdm_users;
 *   DELETE FROM {prefix}options WHERE option_name = 'bdm_uat_db_version';
 *
 * Note: we `return` rather than `die()` per YOURLS plugin best practice -
 * a die() here would abort the rest of the uninstall flow.
 */

if (!defined('YOURLS_ABSPATH')) {
    return;
}

return;
