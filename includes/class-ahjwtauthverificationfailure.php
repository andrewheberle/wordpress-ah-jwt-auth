<?php
/**
 *
 * AhJwtAuthVerificationFailure describes why a JWT failed verification.
 *
 * @file
 * @category AhJwtAuthVerificationFailure
 * @package  AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 *
 * The result of a failed JWT verification: a reason code, the admin-facing
 * message for that reason, and the underlying error detail for logs.
 *
 * @category Class
 * @package  AhJwtAuth
 */
class AhJwtAuthVerificationFailure {
	const NO_KEY            = 'no_key';
	const MALFORMED_KEY     = 'malformed_key';
	const MALFORMED_TOKEN   = 'malformed_token';
	const INVALID_TOKEN     = 'invalid_token';
	const INVALID_SIGNATURE = 'invalid_signature';
	const NOT_YET_VALID     = 'not_yet_valid';
	const EXPIRED           = 'expired';
	const UNEXPECTED        = 'unexpected';
	const MISSING_AUDIENCE  = 'missing_audience';
	const AUDIENCE_MISMATCH = 'audience_mismatch';
	const MISSING_ISSUER    = 'missing_issuer';
	const ISSUER_MISMATCH   = 'issuer_mismatch';

	/**
	 * The reason code, one of the class constants.
	 *
	 * @var string
	 */
	private $code;

	/**
	 * The underlying error detail.
	 *
	 * @var string
	 */
	private $detail;

	/**
	 * Sets up the failure
	 *
	 * @param string $code the reason code, one of the class constants.
	 * @param string $detail the underlying error detail.
	 * @return void
	 */
	public function __construct( $code, $detail = '' ) {
		$this->code   = $code;
		$this->detail = $detail;
	}

	/**
	 * Returns the reason code
	 *
	 * @return string the reason code, one of the class constants
	 */
	public function get_code() {
		return $this->code;
	}

	/**
	 * Returns the underlying error detail, for logs
	 *
	 * @return string the underlying error detail, or an empty string
	 */
	public function get_detail() {
		return $this->detail;
	}

	/**
	 * Returns the admin-facing message for the reason code
	 *
	 * @return string the translated message
	 */
	public function get_message() {
		switch ( $this->code ) {
			case self::NO_KEY:
				return __( 'No JWT private secret or JWKS URL is configured', 'ah-jwt-auth' );
			case self::MALFORMED_KEY:
				return __( 'The provided key/key array is empty or malformed', 'ah-jwt-auth' );
			case self::MALFORMED_TOKEN:
				return __( 'The provided JWT is malformed', 'ah-jwt-auth' );
			case self::INVALID_TOKEN:
				return __( 'The provided JWT was invalid', 'ah-jwt-auth' );
			case self::INVALID_SIGNATURE:
				return __( 'Cannot verify the signature of the JWT. Please double check that your private secret or JWKS URL is configured correctly', 'ah-jwt-auth' );
			case self::NOT_YET_VALID:
				return __( 'The provided JWT is trying to be used before it\'s eligible as defined by the \'nbf\' and/or \'iat\' claim', 'ah-jwt-auth' );
			case self::EXPIRED:
				return __( 'The provided JWT has since expired, as defined by the \'exp\' claim', 'ah-jwt-auth' );
			case self::MISSING_AUDIENCE:
				return __( 'The JWT does not contain the required aud claim.', 'ah-jwt-auth' );
			case self::AUDIENCE_MISMATCH:
				return __( 'The JWT aud claim does not match the configured audience.', 'ah-jwt-auth' );
			case self::MISSING_ISSUER:
				return __( 'The JWT does not contain the required iss claim.', 'ah-jwt-auth' );
			case self::ISSUER_MISMATCH:
				return __( 'The JWT iss claim does not match the configured issuer.', 'ah-jwt-auth' );
			default:
				return __( 'There was an unhandled exception while verifying the JWT', 'ah-jwt-auth' );
		}
	}
}
