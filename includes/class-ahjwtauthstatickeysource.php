<?php
/**
 *
 * AhJwtAuthStaticKeySource provides a key from configured key material.
 *
 * @file
 * @category AhJwtAuthStaticKeySource
 * @package  AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Firebase\JWT\Key;

/**
 *
 * Provides a single key from a configured shared secret (HS256) or
 * PEM public key (RS256).
 *
 * @category Class
 * @package  AhJwtAuth
 */
class AhJwtAuthStaticKeySource implements AhJwtAuthKeySource {
	/**
	 * The configured shared secret or PEM public key.
	 *
	 * @var string|false
	 */
	private $key_material;

	/**
	 * Sets up the key source
	 *
	 * @param string|false $key_material the configured shared secret or PEM public key.
	 * @return void
	 */
	public function __construct( $key_material ) {
		$this->key_material = $key_material;
	}

	/**
	 * Returns the key to verify the JWT
	 *
	 * A value of false is returned when no key material is configured
	 *
	 * @return Key|false the key used for verifying the signature of the JWT
	 */
	public function get_key() {
		if ( ! is_string( $this->key_material ) || '' === trim( $this->key_material ) ) {
			return false;
		}

		return new Key( $this->key_material, $this->is_public_key() ? 'RS256' : 'HS256' );
	}

	/**
	 * Determines whether the configured key material is a public key.
	 *
	 * @return bool true if the key material is a public key
	 */
	private function is_public_key() {
		if ( function_exists( 'openssl_pkey_get_public' ) ) {
			return false !== openssl_pkey_get_public( $this->key_material );
		}

		return 1 === preg_match( '/-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE)-----/', $this->key_material );
	}
}
