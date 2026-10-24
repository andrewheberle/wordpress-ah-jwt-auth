<?php
/**
 *
 * AhJwtAuthSignIn is the main class that handles sign-in.
 *
 * @file
 * @category AhJwtAuthSignIn
 * @package  AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 *
 * This class handles all the sign-in logic that extracts and verifies the JWT
 * in the request and subsequently signs the user into WordPress.
 *
 * @category Class
 * @package  AhJwtAuth
 */
class AhJwtAuthSignIn {
	/**
	 * Plugin settings.
	 *
	 * @var AhJwtAuthSettings
	 */
	private $settings;

	/**
	 * Resolves the user for the request's JWT.
	 *
	 * @var AhJwtAuthAuthenticator
	 */
	private $authenticator;

	/**
	 * Error message to display in admin notices.
	 *
	 * @var string
	 */
	private $error;

	/**
	 * Warning message to display in admin notices.
	 *
	 * @var string
	 */
	private $warning;

	/**
	 * Sets up the class ready for use
	 *
	 * @param AhJwtAuthSettings $settings the plugin settings.
	 * @return void
	 */
	public function __construct( AhJwtAuthSettings $settings ) {
		$this->settings      = $settings;
		$this->authenticator = new AhJwtAuthAuthenticator( $settings );

		add_action( 'admin_notices', array( $this, 'ahjwtauth_admin_notice' ) );
		add_action( 'init', array( $this, 'ahjwtauth_log_user_in' ) );
	}

	/**
	 * Logs user in based on JWT
	 *
	 * If a valid JWT is present in the HTTP request it is verified and parsed so
	 * the user contained in the token can be signed in
	 *
	 * @return void
	 */
	public function ahjwtauth_log_user_in() {
		// if user is already logged in just return immediately.
		if ( is_user_logged_in() ) {
			return;
		}

		// Allow background tasks (WP-Cron, WP-CLI) to bypass JWT checks.
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		$user = $this->authenticator->authenticate( getallheaders() );
		if ( $user instanceof AhJwtAuthSignInFailure ) {
			$this->handle_failure( $user );
			return;
		}

		wp_clear_auth_cookie();
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID );
		do_action( 'wp_login', $user->user_login, $user );

		// redirect after login.
		$redirect_to = current_user_can( 'manage_options' ) ? admin_url() : home_url();
		if (
			isset( $_GET['redirect_to'], $_GET['redirect_to_nonce'] )
			&& wp_verify_nonce( sanitize_key( $_GET['redirect_to_nonce'] ), 'ahjwtauth_log_user_in' )
		) {
			$redirect_to = esc_url_raw( wp_unslash( $_GET['redirect_to'] ) );
		}

		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Prints any admin notices
	 *
	 * If any warning or error values have been set, they are printed using this function
	 *
	 * @return void
	 */
	public function ahjwtauth_admin_notice() {
		// Only print admin notices to administrative users.
		if ( current_user_can( 'manage_options' ) ) {
			if ( isset( $this->error ) ) {
				$class   = 'notice notice-error';
				$message = $this->error;
				printf( '<div class="%1$s"><p>%2$s</p></div>', esc_attr( $class ), esc_html( $message ) );
			}

			if ( isset( $this->warning ) ) {
				$class   = 'notice notice-warning is-dismissible';
				$message = $this->warning;
				printf( '<div class="%1$s"><p>%2$s</p></div>', esc_attr( $class ), esc_html( $message ) );
			}
		}
	}

	/**
	 * Reports a failed sign-in
	 *
	 * The failure is logged and shown in an admin notice. If Fail-Closed is
	 * enabled the request is also blocked.
	 *
	 * @param AhJwtAuthSignInFailure $failure why sign-in failed.
	 * @return void
	 */
	private function handle_failure( AhJwtAuthSignInFailure $failure ) {
		$level  = $failure->is_warning() ? 'WARNING' : 'ERROR';
		$detail = '' === $failure->get_detail() ? '' : ': ' . $failure->get_detail();
		$this->log( 'AH JWT Auth: ' . $level . ': ' . $failure->get_message() . $detail );

		if ( $failure->is_warning() ) {
			$this->warning = 'AH JWT Auth: ' . $failure->get_message();
		} else {
			$this->error = 'AH JWT Auth: ' . $failure->get_message();
		}

		if ( $this->settings->fail_closed() ) {
			wp_die(
				esc_html( $failure->get_visitor_message() ),
				esc_html( $failure->get_visitor_title() ),
				array( 'response' => 401 )
			);
		}
	}

	/**
	 * Logs a message using error_log if WP_DEBUG is enabled
	 *
	 * @param string $message the message to log.
	 * @return void
	 */
	private function log( $message ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG === true ) {
			// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( $message );
			// phpcs:enable
		}
	}
}
