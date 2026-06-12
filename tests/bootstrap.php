<?php
/**
 * Test bootstrap for WordPress function stubs.
 *
 * @package AhJwtAuth
 */

declare(strict_types=1);

error_reporting( E_ALL & ~E_DEPRECATED );
ini_set( 'log_errors', '1' );
ini_set( 'error_log', sys_get_temp_dir() . '/ahjwtauth-test-error.log' );

$GLOBALS['ahjwtauth_test_options'] = array();

if ( ! function_exists( 'get_option' ) ) {
	function get_option( $option_name, $default = false ) {
		return array_key_exists( $option_name, $GLOBALS['ahjwtauth_test_options'] )
			? $GLOBALS['ahjwtauth_test_options'][ $option_name ]
			: $default;
	}
}

if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) {
		return $text;
	}
}

$composer_vendor_dir = getenv( 'COMPOSER_VENDOR_DIR' );
$autoload = false !== $composer_vendor_dir
	? $composer_vendor_dir . '/autoload.php'
	: __DIR__ . '/../vendor/autoload.php';

if ( file_exists( $autoload ) ) {
	require_once $autoload;
}

require_once __DIR__ . '/../includes/class-ahjwtauthadmin.php';
require_once __DIR__ . '/../includes/class-ahjwtauthsignin.php';
