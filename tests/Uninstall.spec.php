<?php
/**
 * Uninstall specs.
 *
 * @package AhJwtAuth
 */

declare(strict_types=1);

use AhJwtAuth\AhJwtAuthSettings;

function uninstall_for_test() {
	if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
		define( 'WP_UNINSTALL_PLUGIN', 'ah-jwt-auth/ah-jwt-auth.php' );
	}

	require __DIR__ . '/../uninstall.php';
}

function deleted_options_for_test( $blog_id ) {
	$names = array();
	foreach ( $GLOBALS['ahjwtauth_test_deleted_options'] as $deleted ) {
		if ( $deleted[0] === $blog_id ) {
			$names[] = $deleted[1];
		}
	}
	sort( $names );

	return $names;
}

function plugin_data_for_test() {
	$names = AhJwtAuthSettings::PLUGIN_DATA;
	sort( $names );

	return $names;
}

describe(
	'uninstall.php',
	function() {
		beforeEach(
			function() {
				$GLOBALS['ahjwtauth_test_blog_id']         = 1;
				$GLOBALS['ahjwtauth_test_blog_stack']      = array();
				$GLOBALS['ahjwtauth_test_sites']           = null;
				$GLOBALS['ahjwtauth_test_get_sites_args']  = null;
				$GLOBALS['ahjwtauth_test_deleted_options'] = array();
				$GLOBALS['ahjwtauth_test_users']           = array();
			}
		);

		it(
			'lists every setting and the upgrade level as plugin data',
			function() {
				$expected = array_merge( array_keys( AhJwtAuthSettings::DEFAULTS ), array( AhJwtAuthSettings::UPGRADE_LEVEL ) );
				sort( $expected );

				expect( plugin_data_for_test() )->toBe( $expected );
			}
		);

		it(
			'deletes the plugin data on a single site',
			function() {
				uninstall_for_test();

				expect( deleted_options_for_test( 1 ) )->toBe( plugin_data_for_test() );
			}
		);

		it(
			'deletes the plugin data on every site of a multisite network',
			function() {
				$GLOBALS['ahjwtauth_test_sites'] = array( 1, 2, 5 );

				uninstall_for_test();

				expect( deleted_options_for_test( 1 ) )->toBe( plugin_data_for_test() );
				expect( deleted_options_for_test( 2 ) )->toBe( plugin_data_for_test() );
				expect( deleted_options_for_test( 5 ) )->toBe( plugin_data_for_test() );
				expect( $GLOBALS['ahjwtauth_test_blog_id'] )->toBe( 1 );
			}
		);

		it(
			'asks for every site rather than the first page of sites',
			function() {
				$GLOBALS['ahjwtauth_test_sites'] = array( 1 );

				uninstall_for_test();

				expect( $GLOBALS['ahjwtauth_test_get_sites_args'] )->toBe(
					array(
						'fields' => 'ids',
						'number' => 0,
					)
				);
			}
		);

		it(
			'leaves provisioned users in place',
			function() {
				wp_create_user( 'user@example.com', 'password', 'user@example.com' );

				uninstall_for_test();

				expect( get_user_by( 'email', 'user@example.com' ) )->not->toBe( false );
			}
		);
	}
);
