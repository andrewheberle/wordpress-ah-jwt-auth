<?php
/**
 *
 * AhJwtAuthSettings reads the plugin's configuration.
 *
 * @file
 * @category AhJwtAuthSettings
 * @package  AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Art4\Requests\Psr\HttpClient;

/**
 *
 * Holds the name and default of every plugin option, and reads the stored
 * values. Defaults registered with register_setting only apply in the admin
 * area, so every read passes its default to get_option.
 *
 * @category Class
 * @package  AhJwtAuth
 */
class AhJwtAuthSettings {
	const PRIVATE_SECRET        = 'ahjwtauth-private-secret';
	const JWKS_URL              = 'ahjwtauth-jwks-url';
	const JWT_HEADER            = 'ahjwtauth-jwt-header';
	const AUDIENCE              = 'ahjwtauth-audience';
	const ISSUER                = 'ahjwtauth-issuer';
	const USER_ROLE             = 'ahjwtauth-user-role';
	const DISABLE_USER_CREATION = 'ahjwtauth-disable-user-creation';
	const FAIL_CLOSED           = 'ahjwtauth-fail-closed';

	const DEFAULTS = array(
		self::PRIVATE_SECRET        => '',
		self::JWKS_URL              => '',
		self::JWT_HEADER            => 'Authorization',
		self::AUDIENCE              => '',
		self::ISSUER                => '',
		self::USER_ROLE             => 'subscriber',
		self::DISABLE_USER_CREATION => '0',
		self::FAIL_CLOSED           => '0',
	);

	/**
	 * Returns the shared secret or PEM public key used to verify the JWT
	 *
	 * @return string the key material, or an empty string
	 */
	public function private_secret() {
		return $this->get( self::PRIVATE_SECRET );
	}

	/**
	 * Returns the JWKS URL used to verify the JWT
	 *
	 * @return string the JWKS URL, or an empty string
	 */
	public function jwks_url() {
		return $this->get( self::JWKS_URL );
	}

	/**
	 * Returns the HTTP header that contains the JWT
	 *
	 * A blank stored value falls back to the Authorization header
	 *
	 * @return string the header name
	 */
	public function jwt_header() {
		$header = trim( $this->get( self::JWT_HEADER ) );

		return '' === $header ? self::DEFAULTS[ self::JWT_HEADER ] : $header;
	}

	/**
	 * Returns the expected aud claim
	 *
	 * @return string the audience, or an empty string to skip the check
	 */
	public function audience() {
		return $this->get( self::AUDIENCE );
	}

	/**
	 * Returns the expected iss claim
	 *
	 * @return string the issuer, or an empty string to skip the check
	 */
	public function issuer() {
		return $this->get( self::ISSUER );
	}

	/**
	 * Returns the role for an auto-created user when the JWT has no role claim
	 *
	 * @return string the role name
	 */
	public function default_user_role() {
		return $this->get( self::USER_ROLE );
	}

	/**
	 * Returns whether automatic user creation is disabled
	 *
	 * @return bool true if users must be provisioned before they can sign in
	 */
	public function user_creation_disabled() {
		return '1' === $this->get( self::DISABLE_USER_CREATION );
	}

	/**
	 * Returns whether Fail-Closed enforcement is enabled
	 *
	 * @return bool true if requests without a valid JWT are blocked
	 */
	public function fail_closed() {
		return '1' === $this->get( self::FAIL_CLOSED );
	}

	/**
	 * Returns the configured source of the key used to verify the JWT
	 *
	 * A configured JWKS URL takes precedence over the private secret
	 *
	 * @return AhJwtAuthKeySource the configured key source
	 */
	public function key_source() {
		if ( '' !== $this->jwks_url() ) {
			return new AhJwtAuthJwksKeySource( $this->jwks_url(), new HttpClient() );
		}

		return new AhJwtAuthStaticKeySource( $this->private_secret() );
	}

	/**
	 * Reads a stored option, falling back to its default
	 *
	 * @param string $name the option name, one of the class constants.
	 * @return string the stored value, or the default
	 */
	private function get( $name ) {
		return (string) get_option( $name, self::DEFAULTS[ $name ] );
	}
}
