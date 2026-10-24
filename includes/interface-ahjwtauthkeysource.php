<?php
/**
 *
 * AhJwtAuthKeySource is the seam for the keys that verify JWT signatures.
 *
 * @file
 * @category AhJwtAuthKeySource
 * @package  AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 *
 * A source of the key(s) used to verify the signature of a JWT.
 *
 * @category Interface
 * @package  AhJwtAuth
 */
interface AhJwtAuthKeySource {
	/**
	 * Returns the key(s) to pass to JWT::decode
	 *
	 * A value of false is returned when no key is configured
	 *
	 * @return \Firebase\JWT\Key|\ArrayAccess|false the key or key set
	 */
	public function get_key();
}
