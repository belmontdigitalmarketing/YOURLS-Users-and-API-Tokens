<?php
/**
 * Admin UI for Users & API Tokens.
 *
 * Single plugin page registered at ?page=bdm_users, with sub-views and POST
 * actions dispatched on `action` and `user` query parameters.
 *
 * Access:
 *   - admin role:       full access to all users and tokens
 *   - integration role: only their own user/tokens page
 *   - config-only user: treated as admin (legacy emergency-admin in config.php)
 *
 * All mutations are POST-only and protected by YOURLS nonces.
 */

if (!defined('YOURLS_ABSPATH')) {
    die();
}

// ============================================================================
// ENTRY POINT
// ============================================================================

function bdm_uat_render_page() {
    $action = isset($_REQUEST['action']) ? (string) $_REQUEST['action'] : '';
    $is_post = ($_SERVER['REQUEST_METHOD'] === 'POST');

    $flash = array('messages' => array(), 'errors' => array(), 'new_token' => null);

    if ($is_post && $action !== '') {
        $flash = bdm_uat_handle_post($action);
        // For actions that need a redirect to the listing, handle_post returns
        // a 'redirect_to' key. We can't header() after YOURLS has emitted html,
        // so we use a meta refresh fallback.
        if (!empty($flash['redirect_to'])) {
            bdm_uat_redirect($flash['redirect_to']);
            return;
        }
    }

    $view = bdm_uat_route_view();
    bdm_uat_render_view($view, $flash);
}

// ============================================================================
// ACCESS CONTROL
// ============================================================================

function bdm_uat_current_username() {
    return defined('YOURLS_USER') ? YOURLS_USER : null;
}

function bdm_uat_current_user_row() {
    $name = bdm_uat_current_username();
    if (!$name) return null;
    return bdm_uat_get_user_by_username($name);
}

/**
 * Logged-in user is an admin if (a) they have a DB row with role=admin,
 * or (b) they don't have a DB row at all (config-only emergency admin).
 */
function bdm_uat_current_is_admin() {
    $u = bdm_uat_current_user_row();
    if (!$u) return bdm_uat_current_username() !== null;
    return $u->role === 'admin';
}

/**
 * Permission checks return bool. Callers are responsible for bailing out
 * (returning an error flash from POST handlers, returning from render fns).
 * We intentionally do NOT exit() here - that would leave the YOURLS admin
 * page chrome half-rendered.
 */
function bdm_uat_check_admin() {
    return bdm_uat_current_is_admin();
}

function bdm_uat_check_admin_or_self($user_id) {
    if (bdm_uat_current_is_admin()) return true;
    $current = bdm_uat_current_user_row();
    return $current && (int) $current->id === (int) $user_id;
}

function bdm_uat_forbidden_flash($message = 'You do not have permission to perform this action.') {
    return array(
        'errors' => array($message),
        'messages' => array(),
        'new_token' => null,
    );
}

// ============================================================================
// POST DISPATCH
// ============================================================================

function bdm_uat_handle_post($action) {
    $nonce = isset($_REQUEST['nonce']) ? (string) $_REQUEST['nonce'] : '';
    // yourls_verify_nonce() die()s on failure when called with 2 args - no
    // need to inspect a return value. A missing or expired nonce terminates
    // the request before any mutation runs.
    yourls_verify_nonce('bdm_uat_' . $action, $nonce);

    switch ($action) {
        case 'create_user':     return bdm_uat_post_create_user();
        case 'update_user':     return bdm_uat_post_update_user();
        case 'delete_user':     return bdm_uat_post_delete_user();
        case 'create_token':    return bdm_uat_post_create_token();
        case 'regenerate_token':return bdm_uat_post_regenerate_token();
        case 'revoke_token':    return bdm_uat_post_revoke_token();
    }
    return array('errors' => array('Unknown action.'), 'messages' => array(), 'new_token' => null);
}

function bdm_uat_post_create_user() {
    if (!bdm_uat_check_admin()) return bdm_uat_forbidden_flash('Admin privileges required.');
    $r = bdm_uat_create_user(
        isset($_POST['username']) ? $_POST['username'] : '',
        isset($_POST['password']) ? $_POST['password'] : '',
        isset($_POST['role']) ? $_POST['role'] : 'integration'
    );
    if (!$r['ok']) {
        return array('errors' => array($r['error']), 'messages' => array(), 'new_token' => null);
    }
    return array(
        'messages' => array('User created.'),
        'errors' => array(),
        'new_token' => null,
        'redirect_to' => bdm_uat_page_url(array('user' => $r['id'])),
    );
}

function bdm_uat_post_update_user() {
    $user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
    if (!bdm_uat_check_admin_or_self($user_id)) return bdm_uat_forbidden_flash('You can only manage your own account.');

    $role = null;
    $password = null;

    // Role changes are admin-only
    if (bdm_uat_current_is_admin() && isset($_POST['role']) && $_POST['role'] !== '') {
        $role = (string) $_POST['role'];
    }
    if (isset($_POST['password']) && $_POST['password'] !== '') {
        $password = (string) $_POST['password'];
    }

    $r = bdm_uat_update_user($user_id, $role, $password);
    if (!$r['ok']) {
        return array('errors' => array($r['error']), 'messages' => array(), 'new_token' => null);
    }
    return array(
        'messages' => array('User updated.'),
        'errors' => array(),
        'new_token' => null,
        'redirect_to' => bdm_uat_page_url(array('user' => $user_id)),
    );
}

function bdm_uat_post_delete_user() {
    if (!bdm_uat_check_admin()) return bdm_uat_forbidden_flash('Admin privileges required.');
    $user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
    $r = bdm_uat_delete_user($user_id);
    if (!$r['ok']) {
        return array('errors' => array($r['error']), 'messages' => array(), 'new_token' => null);
    }
    return array(
        'messages' => array('User deleted.'),
        'errors' => array(),
        'new_token' => null,
        'redirect_to' => bdm_uat_page_url(),
    );
}

function bdm_uat_post_create_token() {
    $user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
    if (!bdm_uat_check_admin_or_self($user_id)) return bdm_uat_forbidden_flash('You can only manage your own account.');

    $r = bdm_uat_create_token($user_id, isset($_POST['label']) ? $_POST['label'] : '');
    if (!$r['ok']) {
        return array('errors' => array($r['error']), 'messages' => array(), 'new_token' => null);
    }
    return array(
        'messages' => array('Token created. Copy it now - it will not be shown again.'),
        'errors' => array(),
        'new_token' => $r['token'],
    );
}

function bdm_uat_post_regenerate_token() {
    $token_id = isset($_POST['token_id']) ? (int) $_POST['token_id'] : 0;
    $token = bdm_uat_get_token($token_id);
    if (!$token) {
        return array('errors' => array('Token not found.'), 'messages' => array(), 'new_token' => null);
    }
    if (!bdm_uat_check_admin_or_self($token->user_id)) return bdm_uat_forbidden_flash('You can only manage your own account.');

    $r = bdm_uat_regenerate_token($token_id);
    if (!$r['ok']) {
        return array('errors' => array($r['error']), 'messages' => array(), 'new_token' => null);
    }
    return array(
        'messages' => array('Token regenerated. Copy the new value now - it will not be shown again.'),
        'errors' => array(),
        'new_token' => $r['token'],
    );
}

function bdm_uat_post_revoke_token() {
    $token_id = isset($_POST['token_id']) ? (int) $_POST['token_id'] : 0;
    $token = bdm_uat_get_token($token_id);
    if (!$token) {
        return array('errors' => array('Token not found.'), 'messages' => array(), 'new_token' => null);
    }
    if (!bdm_uat_check_admin_or_self($token->user_id)) return bdm_uat_forbidden_flash('You can only manage your own account.');

    $r = bdm_uat_revoke_token($token_id);
    if (!$r['ok']) {
        return array('errors' => array($r['error']), 'messages' => array(), 'new_token' => null);
    }
    return array(
        'messages' => array('Token revoked.'),
        'errors' => array(),
        'new_token' => null,
        'redirect_to' => bdm_uat_page_url(array('user' => $token->user_id)),
    );
}

// ============================================================================
// VIEW ROUTING
// ============================================================================

function bdm_uat_route_view() {
    if (isset($_GET['user'])) {
        return array('view' => 'user_detail', 'user_id' => (int) $_GET['user']);
    }
    return array('view' => 'list');
}

function bdm_uat_render_view($route, $flash) {
    if ($route['view'] === 'user_detail') {
        $user_id = $route['user_id'];
        if (!bdm_uat_check_admin_or_self($user_id)) {
            bdm_uat_render_error('You can only manage your own account.');
            return;
        }
        $user = bdm_uat_get_user($user_id);
        if (!$user) {
            bdm_uat_render_error('User not found.');
            return;
        }
        bdm_uat_render_user_detail($user, $flash);
        return;
    }

    // Default: list view (admin only)
    if (!bdm_uat_current_is_admin()) {
        $u = bdm_uat_current_user_row();
        if ($u) {
            // Integration-role users get redirected to their own page
            bdm_uat_redirect(bdm_uat_page_url(array('user' => $u->id)));
            return;
        }
        bdm_uat_render_error('No user context.');
        return;
    }
    bdm_uat_render_list($flash);
}

// ============================================================================
// VIEWS
// ============================================================================

function bdm_uat_render_list($flash) {
    $users = bdm_uat_get_all_users();
    ?>
    <main class="bdm-uat">
        <h2>Users &amp; API Tokens</h2>
        <?php bdm_uat_render_flash($flash); ?>

        <section class="bdm-uat-card">
            <h3>All users</h3>
            <table class="tblSorter">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Tokens</th>
                        <th>Last login</th>
                        <th>Created</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($users as $u): ?>
                    <?php
                    $tokens = bdm_uat_get_tokens_for_user($u->id);
                    $active = 0; $revoked = 0;
                    foreach ($tokens as $t) { $t->revoked_at ? $revoked++ : $active++; }
                    ?>
                    <tr>
                        <td><a href="<?php echo bdm_uat_h(bdm_uat_page_url(array('user' => $u->id))); ?>"><?php echo bdm_uat_h($u->username); ?></a></td>
                        <td><?php echo bdm_uat_h($u->role); ?></td>
                        <td><?php echo (int) $active; ?> active<?php if ($revoked) echo ', ' . (int) $revoked . ' revoked'; ?></td>
                        <td><?php echo bdm_uat_h($u->last_login_at ?: '-'); ?></td>
                        <td><?php echo bdm_uat_h($u->created_at); ?></td>
                        <td><a href="<?php echo bdm_uat_h(bdm_uat_page_url(array('user' => $u->id))); ?>">Manage</a></td>
                    </tr>
                <?php endforeach; ?>
                <?php if (empty($users)): ?>
                    <tr><td colspan="6"><em>No users yet.</em></td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </section>

        <section class="bdm-uat-card">
            <h3>Create user</h3>
            <form method="post" action="<?php echo bdm_uat_h(bdm_uat_page_url()); ?>">
                <input type="hidden" name="action" value="create_user">
                <input type="hidden" name="nonce" value="<?php echo bdm_uat_h(yourls_create_nonce('bdm_uat_create_user')); ?>">
                <p>
                    <label>Username<br>
                        <input type="text" name="username" required pattern="[A-Za-z0-9_.\-]{1,64}" maxlength="64">
                    </label>
                </p>
                <p>
                    <label>Password (min 8 chars)<br>
                        <input type="password" name="password" required minlength="8" autocomplete="new-password">
                    </label>
                </p>
                <p>
                    <label>Role<br>
                        <select name="role">
                            <option value="integration">integration (API only)</option>
                            <option value="admin">admin (full UI access)</option>
                        </select>
                    </label>
                </p>
                <p><button type="submit" class="button primary">Create user</button></p>
            </form>
        </section>
    </main>
    <?php
}

function bdm_uat_render_user_detail($user, $flash) {
    $tokens = bdm_uat_get_tokens_for_user($user->id);
    $is_admin = bdm_uat_current_is_admin();
    ?>
    <main class="bdm-uat">
        <p><a href="<?php echo bdm_uat_h(bdm_uat_page_url()); ?>">&larr; All users</a></p>
        <h2>User: <?php echo bdm_uat_h($user->username); ?></h2>
        <?php bdm_uat_render_flash($flash); ?>

        <section class="bdm-uat-card">
            <h3>Account</h3>
            <p>Role: <strong><?php echo bdm_uat_h($user->role); ?></strong></p>
            <p>Created: <?php echo bdm_uat_h($user->created_at); ?></p>
            <p>Last login: <?php echo bdm_uat_h($user->last_login_at ?: 'never'); ?></p>

            <form method="post" action="<?php echo bdm_uat_h(bdm_uat_page_url()); ?>">
                <input type="hidden" name="action" value="update_user">
                <input type="hidden" name="user_id" value="<?php echo (int) $user->id; ?>">
                <input type="hidden" name="nonce" value="<?php echo bdm_uat_h(yourls_create_nonce('bdm_uat_update_user')); ?>">
                <?php if ($is_admin): ?>
                <p>
                    <label>Role<br>
                        <select name="role">
                            <option value="">(no change)</option>
                            <option value="integration" <?php if ($user->role === 'integration') echo 'selected'; ?>>integration</option>
                            <option value="admin" <?php if ($user->role === 'admin') echo 'selected'; ?>>admin</option>
                        </select>
                    </label>
                </p>
                <?php endif; ?>
                <p>
                    <label>New password (leave blank to keep current)<br>
                        <input type="password" name="password" minlength="8" autocomplete="new-password">
                    </label>
                </p>
                <p><button type="submit" class="button">Save changes</button></p>
            </form>

            <?php if ($is_admin): ?>
            <?php $confirm_msg = 'Delete user ' . $user->username . ' and all their tokens?'; ?>
            <form method="post" action="<?php echo bdm_uat_h(bdm_uat_page_url()); ?>"
                  onsubmit="return confirm(<?php echo bdm_uat_h(json_encode($confirm_msg, JSON_HEX_QUOT | JSON_HEX_APOS | JSON_HEX_TAG | JSON_HEX_AMP)); ?>);"
                  style="margin-top: 1em;">
                <input type="hidden" name="action" value="delete_user">
                <input type="hidden" name="user_id" value="<?php echo (int) $user->id; ?>">
                <input type="hidden" name="nonce" value="<?php echo bdm_uat_h(yourls_create_nonce('bdm_uat_delete_user')); ?>">
                <button type="submit" class="button bdm-uat-danger">Delete user</button>
            </form>
            <?php endif; ?>
        </section>

        <section class="bdm-uat-card">
            <h3>API tokens</h3>

            <?php if ($flash['new_token']): ?>
                <div class="bdm-uat-new-token">
                    <p><strong>New token (copy now - it will not be shown again):</strong></p>
                    <code class="bdm-uat-token-display"><?php echo bdm_uat_h($flash['new_token']); ?></code>
                </div>
            <?php endif; ?>

            <table class="tblSorter">
                <thead>
                    <tr>
                        <th>Label</th>
                        <th>Token</th>
                        <th>Created</th>
                        <th>Last used</th>
                        <th>Status</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($tokens as $t): ?>
                    <tr<?php if ($t->revoked_at) echo ' class="bdm-uat-revoked"'; ?>>
                        <td><?php echo bdm_uat_h($t->label); ?><?php if ($t->is_legacy) echo ' <span class="bdm-uat-badge">legacy</span>'; ?></td>
                        <td><code><?php echo bdm_uat_h(bdm_uat_mask_token($t->token)); ?></code></td>
                        <td><?php echo bdm_uat_h($t->created_at); ?></td>
                        <td><?php echo bdm_uat_h($t->last_used_at ?: 'never'); ?></td>
                        <td>
                            <?php if ($t->revoked_at): ?>
                                Revoked <?php echo bdm_uat_h($t->revoked_at); ?>
                            <?php else: ?>
                                Active
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if (!$t->revoked_at): ?>
                                <form method="post" action="<?php echo bdm_uat_h(bdm_uat_page_url(array('user' => $user->id))); ?>"
                                      style="display:inline"
                                      onsubmit="return confirm('Regenerate this token? The current value will stop working immediately.');">
                                    <input type="hidden" name="action" value="regenerate_token">
                                    <input type="hidden" name="token_id" value="<?php echo (int) $t->id; ?>">
                                    <input type="hidden" name="nonce" value="<?php echo bdm_uat_h(yourls_create_nonce('bdm_uat_regenerate_token')); ?>">
                                    <button type="submit" class="button">Regenerate</button>
                                </form>
                                <form method="post" action="<?php echo bdm_uat_h(bdm_uat_page_url(array('user' => $user->id))); ?>"
                                      style="display:inline"
                                      onsubmit="return confirm('Revoke this token? It will stop working immediately. This cannot be undone.');">
                                    <input type="hidden" name="action" value="revoke_token">
                                    <input type="hidden" name="token_id" value="<?php echo (int) $t->id; ?>">
                                    <input type="hidden" name="nonce" value="<?php echo bdm_uat_h(yourls_create_nonce('bdm_uat_revoke_token')); ?>">
                                    <button type="submit" class="button bdm-uat-danger">Revoke</button>
                                </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php if ($t->is_legacy && !$t->revoked_at): ?>
                    <tr class="bdm-uat-legacy-note">
                        <td colspan="6">
                            <small>This token was captured from your existing YOURLS COOKIEKEY-derived signature. It will continue to be accepted by native YOURLS auth (independent of this plugin) until you rotate <code>YOURLS_COOKIEKEY</code> in <code>config.php</code>. Revoking here only stops the plugin from accepting it.</small>
                        </td>
                    </tr>
                    <?php endif; ?>
                <?php endforeach; ?>
                <?php if (empty($tokens)): ?>
                    <tr><td colspan="6"><em>No tokens yet.</em></td></tr>
                <?php endif; ?>
                </tbody>
            </table>

            <h4>Create new token</h4>
            <form method="post" action="<?php echo bdm_uat_h(bdm_uat_page_url(array('user' => $user->id))); ?>">
                <input type="hidden" name="action" value="create_token">
                <input type="hidden" name="user_id" value="<?php echo (int) $user->id; ?>">
                <input type="hidden" name="nonce" value="<?php echo bdm_uat_h(yourls_create_nonce('bdm_uat_create_token')); ?>">
                <p>
                    <label>Label (e.g. "Flowlu Production", "Zapier", "Groundhogg webhook")<br>
                        <input type="text" name="label" required maxlength="100" size="40">
                    </label>
                </p>
                <p><button type="submit" class="button primary">Generate token</button></p>
            </form>
        </section>
    </main>
    <?php
}

function bdm_uat_render_error($message) {
    echo '<main class="bdm-uat"><div class="bdm-uat-error">' . bdm_uat_h($message) . '</div></main>';
}

function bdm_uat_render_flash($flash) {
    foreach ($flash['errors'] as $e) {
        echo '<div class="bdm-uat-error">' . bdm_uat_h($e) . '</div>';
    }
    foreach ($flash['messages'] as $m) {
        echo '<div class="bdm-uat-message">' . bdm_uat_h($m) . '</div>';
    }
}

// ============================================================================
// HELPERS
// ============================================================================

function bdm_uat_h($s) {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

function bdm_uat_page_url($params = array()) {
    $base = yourls_admin_url('plugins.php') . '?page=bdm_users';
    foreach ($params as $k => $v) {
        $base .= '&' . rawurlencode($k) . '=' . rawurlencode((string) $v);
    }
    return $base;
}

function bdm_uat_redirect($url) {
    // We're inside a YOURLS plugin page render, so headers have already
    // been sent. Use a JS + meta refresh fallback rather than header().
    $safe = bdm_uat_h($url);
    echo '<meta http-equiv="refresh" content="0;url=' . $safe . '">';
    echo '<script>window.location.replace(' . json_encode($url) . ');</script>';
    echo '<p>Redirecting&hellip; <a href="' . $safe . '">Click here if not redirected.</a></p>';
}
