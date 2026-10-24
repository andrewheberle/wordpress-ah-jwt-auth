<?php
/**
 *
 * Removes the plugin data when the plugin is deleted.
 *
 * Provisioned users are site data and are left in place. The cached JWKS
 * transients only hold public keys and expire within a week, so they are left
 * to WordPress's expired transient cleanup rather than depending on the cache
 * key format used by firebase/php-jwt.
 *
 * @file
 * @package AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/includes/class-ahjwtauthsettings.php';

if ( is_multisite() ) {
	$ahjwtauth_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);

	foreach ( $ahjwtauth_site_ids as $ahjwtauth_site_id ) {
		switch_to_blog( $ahjwtauth_site_id );
		array_map( 'delete_option', AhJwtAuthSettings::PLUGIN_DATA );
		restore_current_blog();
	}
} else {
	array_map( 'delete_option', AhJwtAuthSettings::PLUGIN_DATA );
}
