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

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;

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
	 * Sets up the class ready for use
	 *
	 * @return void
	 */
	public function __construct() {
		// Set up admin class.
		$this->ah_jwt_auth_admin = new AhJwtAuthAdmin();

		add_action( 'admin_notices', array( $this, 'ahjwtauth_admin_notice' ) );
		add_action( 'login_head', array( $this, 'ahjwtauth_log_user_in' ) );
		add_action( 'login_head', array( $this, 'ahjwtauth_schedule_refresh_jwks' ) );
		add_action( 'ahjwtauth_refresh_jwks', array( $this, 'ahjwtauth_refresh_jwks' ) );
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

		// get jwt.
		$jwt = $this->get_token();
		if ( false === $jwt ) {
			return;
		}

		// verify JWT and grab payload.
		$payload = $this->verify_token( $jwt );
		if ( false === $payload ) {
			return;
		}

		// If we cannot extract the user's email from header this is an error.
		if ( ! isset( $payload->email ) ) {
			$this->error = __( 'AH JWT Auth expects email attribute to identify user, but it does not exist in the JWT. Please check your reverse proxy configuration', 'ah-jwt-auth' );
			return;
		}
		$email = $payload->email;

		$user = get_user_by( 'email', $email );

		if ( ! $user ) {
			$random_password = wp_generate_password( 64, false );
			$user_id = wp_create_user( $email, $random_password, $email );
			$user = get_user_by( 'id', $user_id );

			// set role on creation to configured default if not included in jwt.
			if ( ! isset( $payload->role ) ) {
				$user->set_role( get_option( 'ahjwtauth-user-role', 'subscriber' ) );
			}
		}

		// If we can extract the user's role from the JWT, then set the role, otherwise leave as-is.
		if ( isset( $payload->role ) ) {
			$user->set_role( strtolower( $payload->role ) );
		}

		wp_clear_auth_cookie();
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID );
		do_action( 'wp_login', $user->login, $user );

		// redirect after login.
		$redirect_url = home_url();
		if ( current_user_can( 'manage_options' ) ) {
			$redirect_url = admin_url();
		}
		wp_safe_redirect( isset( $_GET['redirect_to'] ) ? wp_unslash( $_GET['redirect_to'] ) : $redirect_url );
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
		if ( isset( $this->error ) ) {
			$class = 'notice notice-error';
			$message = $this->error;
			printf( '<div class="%1$s"><p>%2$s</p></div>', esc_attr( $class ), esc_html( $message ) );
		}

		if ( isset( $this->warning ) ) {
			$class = 'notice notice-warning is-dismissible';
			$message = $this->warning;
			printf( '<div class="%1$s"><p>%2$s</p></div>', esc_attr( $class ), esc_html( $message ) );
		}
	}

	/**
	 * Schedules the refresh of the JWKS via WP Cron
	 *
	 * @return void
	 */
	public function ahjwtauth_schedule_refresh_jwks() {
		if (!wp_next_scheduled( 'ahjwtauth_refresh_jwks' )) {
			wp_schedule_event( time(), 'daily', 'ahjwtauth_refresh_jwks' );
		}
	}

	/**
	 * Retrieves the JWKS from the configured URL and saves it as a transient
	 *
	 * A value of false is returned on error
	 *
	 * @return array an associative array containing the key set
	 */
	private function ahjwtauth_refresh_jwks() {
		$jwks_url = get_option( 'ahjwtauth-jwks-url' );
		if ( '' === $jwks_url ) {
			return true;
		}

		// retrieve json from JWKS URL with caching.
		$keys = get_transient( 'ahjwtauth_jwks' );

		// transient existed
		if ( false !== $keys ) {
			return $keys;
		}

		// if transient did not exist, attempt to get url.
		$jwks_url = get_option( 'ahjwtauth-jwks-url' );
		$response = wp_remote_get( $jwks_url );
		if ( is_wp_error( $response ) ) {
			$this->error = __( 'AH JWT Auth: error retrieving the JWKS URL', 'ah-jwt-auth' );
			error_log( 'AH JWT Auth: ERROR: error retrieving the JWKS URL' );
			return false;
		}

		// grab response body.
		$json = wp_remote_retrieve_body( $response );

		// check that response was not empty.
		if ( '' === $json ) {
				$this->error = __( 'AH JWT Auth could not retrieve the specified JWKS URL', 'ah-jwt-auth' );
			error_log( 'AH JWT Auth: ERROR: could not retrieve the specified JWKS URL' );
			return false;
		}

		// try to decode json.
		$jwks = @json_decode( $json, true );
		if ( null === $jwks ) {
			$this->error = __( 'AH JWT Auth cannot decode the JSON retrieved from the JWKS URL', 'ah-jwt-auth' );
			error_log( 'AH JWT Auth: ERROR: cannot decode the JSON retrieved from the JWKS URL' );
			return false;
		}

		// parse the JWKS response.
		try {
			$keys = JWK::parseKeySet( array( 'keys' => $jwks['keys'] ) );
		} catch ( Exception $e ) {
			$this->error = $e->getMessage();
			error_log( 'AH JWT Auth: ERROR: Problem parsing key-set: ' . $e->getMessage() );
			error_log( $json );
			return false;
		}

		// cache JWKS for future.
		set_transient( 'ahjwtauth_jwks', $keys, WEEK_IN_SECONDS );

		// return key set.
		return $keys;
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
		$jwt_header = $this->get_header();
		if ( ! isset( $_SERVER[ $jwt_header ] ) ) {
			$msg = 'the expected JWT was not found. Please double check your reverse proxy configuration.';
			$this->warning = __( 'AH JWT Auth ' . $msg, 'ah-jwt-auth' );
			error_log( 'AH JWT Auth: WARNING: ' . $msg );
			return false;
		}

		// Handle "Header: Bearer <JWT>" form by stipping the "Bearer " prefix.
		$array = explode( ' ', sanitize_text_field( wp_unslash( $_SERVER[ $jwt_header ] ) ) );
		if ( 'Bearer' == $array[0] ) {
			array_shift( $array );
		}

		return implode( ' ', $array );
	}

	/**
	 * Decodes the JWT
	 *
	 * The provided JWT is verified using the configured key and decoded
	 *
	 * A value of false is returned on error
	 *
	 * @param string $jwt the JWT to decode.
	 * @return object the payload from the JWT
	 */
	private function verify_token( $jwt ) {
		$key = $this->get_key();
		if ( false === $key ) {
			return false;
		}
		try {
			$payload = JWT::decode( $jwt, $key );
		} catch ( SignatureInvalidException $e ) {
			$msg = 'Cannot verify the JWT. Please double check that your private secret or JWKS URL is configured correctly';
			$this->error = __( 'AH JWT Auth: ' . $msg, 'ah-jwt-auth' );
			error_log( 'AH JWT Auth: ERROR: ' . $msg );
			return false;
		} catch ( Exception $e ) {
			return false;
		}
		return $payload;
	}

	/**
	 * Returns the key to verify the JWT
	 *
	 * Depending on the configuration of the plugin, this function will return
	 * the static key used to verify the JWT or will retrieve a JSON Web Key Set (JWKS)
	 * from the configured URL
	 *
	 * A value of false is returned on error
	 *
	 * @return Key the key used for verifying the signature of the JWT
	 */
	private function get_key() {
		$jwks_url = get_option( 'ahjwtauth-jwks-url' );
		if ( '' !== $jwks_url ) {
			return $this->ahjwtauth_refresh_jwks();
		}
		
		// otherwise use shared secret.
		return new Key( get_option( 'ahjwtauth-private-secret' ), $this->get_alg() );
	}

	/**
	 * Returns a header in "HTTP" form into a form usable with $_SERVER['HEADER']
	 *
	 * The returned string is done by converting the configured settingto uppercase,
	 * replacing "-" with "_" and adding the prefix of "HTTP_".
	 *
	 * @return string the header name usable with _$SERVER
	 */
	private function get_header() {
		return 'HTTP_' . str_replace( '-', '_', strtoupper( get_option( 'ahjwtauth-jwt-header' ) ) );
	}

	/**
	 * Returns the key algorithm as RS256 if a public key or JWKS is used or HS256
	 * if a secret is used.
	 *
	 * @return string key algorithm
	 */
	private function get_alg() {
		$jwks_url = get_option( 'ahjwtauth-jwks-url' );
		if ( '' === $jwks_url ) {
			return 'RS256';
		}

		return 'HS256';
	}
}
