<?php
/**
 *
 * AhJwtAuthAuthenticator resolves the WordPress user for a request's JWT.
 *
 * @file
 * @category AhJwtAuthAuthenticator
 * @package  AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 *
 * Extracts the JWT from the request headers, verifies it, and finds or
 * creates the WordPress user it identifies.
 *
 * @category Class
 * @package  AhJwtAuth
 */
class AhJwtAuthAuthenticator {
	/**
	 * Plugin settings.
	 *
	 * @var AhJwtAuthSettings
	 */
	private $settings;

	/**
	 * Sets up the authenticator
	 *
	 * @param AhJwtAuthSettings $settings the plugin settings.
	 * @return void
	 */
	public function __construct( AhJwtAuthSettings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * Resolves the user for the JWT in the request headers
	 *
	 * The user is created when they do not exist, unless automatic user
	 * creation is disabled. A valid role claim sets the user's role.
	 *
	 * @param array $headers the request headers.
	 * @return \WP_User|AhJwtAuthSignInFailure the user, or why sign-in failed
	 */
	public function authenticate( array $headers ) {
		$jwt = $this->get_token( $headers );
		if ( false === $jwt ) {
			return new AhJwtAuthSignInFailure( AhJwtAuthSignInFailure::NO_TOKEN );
		}

		$verifier = new AhJwtAuthTokenVerifier(
			$this->settings->key_source(),
			$this->settings->audience(),
			$this->settings->issuer()
		);

		$payload = $verifier->verify( $jwt );
		if ( $payload instanceof AhJwtAuthVerificationFailure ) {
			return AhJwtAuthSignInFailure::invalid_token( $payload );
		}

		if ( ! isset( $payload->email ) || ! is_string( $payload->email ) || '' === $payload->email ) {
			return new AhJwtAuthSignInFailure( AhJwtAuthSignInFailure::MISSING_EMAIL );
		}

		$role = $this->get_role( $payload );
		$user = get_user_by( 'email', $payload->email );
		if ( ! $user ) {
			return $this->create_user( $payload->email, $role );
		}

		if ( null !== $role ) {
			$user->set_role( $role );
		}

		return $user;
	}

	/**
	 * Retrieves the JWT from the configured HTTP request header
	 *
	 * @param array $headers the request headers.
	 * @return string|false the JWT, or false if the header is missing
	 */
	private function get_token( array $headers ) {
		$normalized_headers = array_change_key_case( $headers, CASE_LOWER );
		$target_header      = strtolower( $this->settings->jwt_header() );

		if ( ! isset( $normalized_headers[ $target_header ] ) ) {
			return false;
		}

		$array = explode( ' ', wp_unslash( $normalized_headers[ $target_header ] ) );
		if ( 'Bearer' === $array[0] ) {
			array_shift( $array );
		}

		return implode( ' ', $array );
	}

	/**
	 * Returns the role claim if it names a valid role
	 *
	 * @param object $payload the payload from the JWT.
	 * @return string|null the role, or null if the claim is missing or unknown
	 */
	private function get_role( $payload ) {
		if ( ! isset( $payload->role ) || ! is_string( $payload->role ) ) {
			return null;
		}

		$role = strtolower( $payload->role );

		return array_key_exists( $role, wp_roles()->get_names() ) ? $role : null;
	}

	/**
	 * Creates a user for the email address
	 *
	 * @param string      $email the user's email address, also used as their username.
	 * @param string|null $role the role from the JWT, or null to use the configured default role.
	 * @return \WP_User|AhJwtAuthSignInFailure the new user, or why it could not be created
	 */
	private function create_user( $email, $role ) {
		if ( $this->settings->user_creation_disabled() ) {
			return new AhJwtAuthSignInFailure( AhJwtAuthSignInFailure::NO_ACCOUNT );
		}

		$user_id = wp_create_user( $email, wp_generate_password( 64, false ), $email );
		if ( is_wp_error( $user_id ) ) {
			return new AhJwtAuthSignInFailure( AhJwtAuthSignInFailure::USER_CREATION_FAILED, $user_id->get_error_message() );
		}

		$user = get_user_by( 'id', $user_id );
		$user->set_role( null === $role ? $this->settings->default_user_role() : $role );

		return $user;
	}
}
