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

use Art4\Requests\Psr\HttpClient;

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
	 * Admin handler.
	 *
	 * @var AhJwtAuthAdmin
	 */
	private $ah_jwt_auth_admin;

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
	 * @return void
	 */
	public function __construct() {
		// Set up admin class.
		$this->ah_jwt_auth_admin = new AhJwtAuthAdmin();

		add_action( 'admin_notices', array( $this, 'ahjwtauth_admin_notice' ) );
		add_action( 'init', array( $this, 'ahjwtauth_log_user_in' ) );

		// Remove legacy cron job if it exists from a previous version.
		$timestamp = wp_next_scheduled( 'ahjwtauth_fetch_jwks' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'ahjwtauth_fetch_jwks' );
		}
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

		$fail_closed = '1' === get_option( 'ahjwtauth-fail-closed', '0' );

		// get jwt.
		$jwt = $this->get_token();
		if ( false === $jwt ) {
			// If Fail-Closed is enabled, enforce the token requirement strictly.
			if ( $fail_closed ) {
				wp_die(
					esc_html__( 'Access Denied: This site requires a valid JWT.', 'ah-jwt-auth' ),
					esc_html__( 'JWT Authentication Required', 'ah-jwt-auth' ),
					array( 'response' => 401 )
				);
			}

			return;
		}

		// verify JWT and grab payload.
		$payload = $this->verify_token( $jwt );
		if ( false === $payload ) {
			// Check if the administrator explicitly enabled Fail-Closed enforcement.
			if ( $fail_closed ) {
				wp_die(
					esc_html__( 'Authentication failed: The provided JWT is invalid or expired.', 'ah-jwt-auth' ),
					esc_html__( 'JWT Authentication Error', 'ah-jwt-auth' ),
					array( 'response' => 401 )
				);
			}

			return;
		}

		// If we cannot extract the user's email from header this is an error.
		if ( ! isset( $payload->email ) ) {
			// Check if the administrator explicitly enabled Fail-Closed enforcement.
			if ( $fail_closed ) {
				wp_die(
					esc_html__( 'Authentication failed: The provided JWT did not include an email claim.', 'ah-jwt-auth' ),
					esc_html__( 'JWT Authentication Error', 'ah-jwt-auth' ),
					array( 'response' => 401 )
				);
			}

			$this->error = __( 'AH JWT Auth expects email attribute to identify user, but it does not exist in the JWT. Please check your reverse proxy configuration', 'ah-jwt-auth' );
			return;
		}
		$email = $payload->email;

		$user = get_user_by( 'email', $email );

		if ( ! $user ) {
			if ( '1' === get_option( 'ahjwtauth-disable-user-creation', '0' ) ) {
				// Check if the administrator explicitly enabled Fail-Closed enforcement.
				if ( $fail_closed ) {
					wp_die(
						esc_html__( 'Authentication failed: No account exists for this JWT.', 'ah-jwt-auth' ),
						esc_html__( 'JWT Authentication Error', 'ah-jwt-auth' ),
						array( 'response' => 401 )
					);
				}

				$this->error = __( 'AH JWT Auth found a valid JWT, but the user does not exist and automatic user creation is disabled.', 'ah-jwt-auth' );
				$this->log( 'AH JWT Auth: ERROR: valid JWT found, but user does not exist and automatic user creation is disabled.' );
				return;
			}

			$random_password = wp_generate_password( 64, false );
			$user_id         = wp_create_user( $email, $random_password, $email );
			$user            = get_user_by( 'id', $user_id );

			// set role on creation to configured default if not included in jwt.
			if ( ! isset( $payload->role ) ) {
				$user->set_role( get_option( 'ahjwtauth-user-role', 'subscriber' ) );
			}
		}

		// If we can extract the user's role from the JWT and it is valid then set the role, otherwise leave as-is.
		if ( isset( $payload->role ) ) {
			$role = strtolower( $payload->role );
			if ( array_key_exists( $role, wp_roles()->get_names() ) ) {
				$user->set_role( $role );
			}
		}

		wp_clear_auth_cookie();
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID );
		do_action( 'wp_login', $user->login, $user );

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
	 * Retrieves the JWT
	 *
	 * The JWT is retrieved from the configured HTTP request header
	 *
	 * A value of false is returned on error
	 *
	 * @return string the payload from the JWT
	 */
	private function get_token() {
		$request_headers    = getallheaders();
		$normalized_headers = array_change_key_case( $request_headers, CASE_LOWER );
		$target_header      = strtolower( get_option( 'ahjwtauth-jwt-header', 'Authorization' ) );

		if ( ! isset( $normalized_headers[ $target_header ] ) ) {
			$this->warning = __( 'AH JWT Auth: The expected JWT was not found. Please double check your reverse proxy configuration.', 'ah-jwt-auth' );
			$this->log( 'AH JWT Auth: WARNING: The expected JWT was not found.' );
			return false;
		}

		$raw_header_value = wp_unslash( $normalized_headers[ $target_header ] );
		$array            = explode( ' ', $raw_header_value );
		if ( 'Bearer' === $array[0] ) {
			array_shift( $array );
		}

		return implode( ' ', $array );
	}

	/**
	 * Verifies the JWT
	 *
	 * The provided JWT is verified using the configured key source and its
	 * claims are checked against the configured audience and issuer
	 *
	 * A value of false is returned on error
	 *
	 * @param string $jwt the JWT to verify.
	 * @return object|false the payload from the JWT
	 */
	private function verify_token( $jwt ) {
		$verifier = new AhJwtAuthTokenVerifier(
			$this->key_source(),
			get_option( 'ahjwtauth-audience', '' ),
			get_option( 'ahjwtauth-issuer', '' )
		);

		$result = $verifier->verify( $jwt );
		if ( $result instanceof AhJwtAuthVerificationFailure ) {
			$this->error = 'AH JWT Auth: ' . $result->get_message();
			$detail      = '' === $result->get_detail() ? '' : ': ' . $result->get_detail();
			$this->log( 'AH JWT Auth: ERROR: ' . $result->get_message() . $detail );
			return false;
		}

		return $result;
	}

	/**
	 * Returns the configured source of the key used to verify the JWT
	 *
	 * @return AhJwtAuthKeySource the configured key source
	 */
	private function key_source() {
		$jwks_url = get_option( 'ahjwtauth-jwks-url', '' );
		if ( '' !== $jwks_url ) {
			return new AhJwtAuthJwksKeySource( $jwks_url, new HttpClient() );
		}

		return new AhJwtAuthStaticKeySource( get_option( 'ahjwtauth-private-secret' ) );
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
