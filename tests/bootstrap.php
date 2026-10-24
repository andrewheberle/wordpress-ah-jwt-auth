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

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'WEEK_IN_SECONDS' ) ) {
	define( 'WEEK_IN_SECONDS', 7 * 24 * 60 * 60 );
}

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

if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( $key ) {
		return false;
	}
}

if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( $key, $value, $expiration = 0 ) {
		return true;
	}
}

if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( $key ) {
		return true;
	}
}

// In-memory stand-in for the WordPress user store.
$GLOBALS['ahjwtauth_test_users'] = array();

if ( ! class_exists( 'WP_User' ) ) {
	class WP_User {
		public $ID;
		public $user_login;
		public $user_email;
		public $roles = array();

		public function set_role( $role ) {
			$this->roles = array( $role );
		}
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		private $message;

		public function __construct( $code = '', $message = '' ) {
			$this->message = $message;
		}

		public function get_error_message() {
			return $this->message;
		}
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'get_user_by' ) ) {
	function get_user_by( $field, $value ) {
		foreach ( $GLOBALS['ahjwtauth_test_users'] as $user ) {
			if ( ( 'email' === $field && $user->user_email === $value ) || ( 'id' === $field && $user->ID === $value ) ) {
				return $user;
			}
		}

		return false;
	}
}

if ( ! function_exists( 'wp_create_user' ) ) {
	function wp_create_user( $username, $password, $email ) {
		foreach ( $GLOBALS['ahjwtauth_test_users'] as $user ) {
			if ( $user->user_login === $username ) {
				return new WP_Error( 'existing_user_login', 'Sorry, that username already exists!' );
			}
		}

		$user             = new WP_User();
		$user->ID         = count( $GLOBALS['ahjwtauth_test_users'] ) + 1;
		$user->user_login = $username;
		$user->user_email = $email;
		$user->set_role( get_option( 'default_role', 'subscriber' ) );

		$GLOBALS['ahjwtauth_test_users'][] = $user;

		return $user->ID;
	}
}

if ( ! function_exists( 'wp_generate_password' ) ) {
	function wp_generate_password( $length = 12, $special_chars = true ) {
		return str_repeat( 'x', $length );
	}
}

if ( ! function_exists( 'wp_roles' ) ) {
	function wp_roles() {
		return new class() {
			public function get_names() {
				return array(
					'administrator' => 'Administrator',
					'editor'        => 'Editor',
					'author'        => 'Author',
					'contributor'   => 'Contributor',
					'subscriber'    => 'Subscriber',
				);
			}
		};
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $value ) {
		return stripslashes( $value );
	}
}

$autoload = __DIR__ . '/../vendor/autoload.php';

if ( file_exists( $autoload ) ) {
	require_once $autoload;
}

require_once __DIR__ . '/../includes/class-ahjwtauthadmin.php';
require_once __DIR__ . '/../includes/interface-ahjwtauthkeysource.php';
require_once __DIR__ . '/../includes/class-ahjwtauthstatickeysource.php';
require_once __DIR__ . '/../includes/class-ahjwtauthjwkskeysource.php';
require_once __DIR__ . '/../includes/class-ahjwtauthverificationfailure.php';
require_once __DIR__ . '/../includes/class-ahjwtauthtokenverifier.php';
require_once __DIR__ . '/../includes/class-ahjwtauthsettings.php';
require_once __DIR__ . '/../includes/class-ahjwtauthsigninfailure.php';
require_once __DIR__ . '/../includes/class-ahjwtauthauthenticator.php';
require_once __DIR__ . '/../includes/class-ahjwtauthsignin.php';
