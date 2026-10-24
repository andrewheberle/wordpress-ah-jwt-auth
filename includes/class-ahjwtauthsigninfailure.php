<?php
/**
 *
 * AhJwtAuthSignInFailure describes why a request could not be signed in.
 *
 * @file
 * @category AhJwtAuthSignInFailure
 * @package  AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 *
 * The result of a failed sign-in: a reason code, the admin-facing message for
 * that reason, the message shown to the visitor when Fail-Closed is enabled,
 * and the underlying error detail for logs.
 *
 * @category Class
 * @package  AhJwtAuth
 */
class AhJwtAuthSignInFailure {
	const NO_TOKEN             = 'no_token';
	const INVALID_TOKEN        = 'invalid_token';
	const MISSING_EMAIL        = 'missing_email';
	const NO_ACCOUNT           = 'no_account';
	const USER_CREATION_FAILED = 'user_creation_failed';

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
	 * Why the JWT failed verification, for the invalid_token code.
	 *
	 * @var AhJwtAuthVerificationFailure|null
	 */
	private $verification_failure;

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
	 * Returns an invalid_token failure for a JWT that failed verification
	 *
	 * @param AhJwtAuthVerificationFailure $verification_failure why the JWT failed verification.
	 * @return AhJwtAuthSignInFailure the failure
	 */
	public static function invalid_token( AhJwtAuthVerificationFailure $verification_failure ) {
		$failure                       = new self( self::INVALID_TOKEN, $verification_failure->get_detail() );
		$failure->verification_failure = $verification_failure;

		return $failure;
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
	 * Returns whether the failure is reported as a warning rather than an error
	 *
	 * @return bool true for a warning
	 */
	public function is_warning() {
		return self::NO_TOKEN === $this->code;
	}

	/**
	 * Returns the admin-facing message for the reason code
	 *
	 * @return string the translated message
	 */
	public function get_message() {
		switch ( $this->code ) {
			case self::NO_TOKEN:
				return __( 'The expected JWT was not found. Please double check your reverse proxy configuration.', 'ah-jwt-auth' );
			case self::INVALID_TOKEN:
				return $this->verification_failure->get_message();
			case self::MISSING_EMAIL:
				return __( 'The JWT does not include the email claim that identifies the user. Please check your reverse proxy configuration.', 'ah-jwt-auth' );
			case self::NO_ACCOUNT:
				return __( 'A valid JWT was found, but the user does not exist and automatic user creation is disabled.', 'ah-jwt-auth' );
			default:
				return __( 'A valid JWT was found, but the user could not be created.', 'ah-jwt-auth' );
		}
	}

	/**
	 * Returns the title of the page shown to the visitor when Fail-Closed is enabled
	 *
	 * @return string the translated title
	 */
	public function get_visitor_title() {
		if ( self::NO_TOKEN === $this->code ) {
			return __( 'JWT Authentication Required', 'ah-jwt-auth' );
		}

		return __( 'JWT Authentication Error', 'ah-jwt-auth' );
	}

	/**
	 * Returns the message shown to the visitor when Fail-Closed is enabled
	 *
	 * @return string the translated message
	 */
	public function get_visitor_message() {
		switch ( $this->code ) {
			case self::NO_TOKEN:
				return __( 'Access Denied: This site requires a valid JWT.', 'ah-jwt-auth' );
			case self::INVALID_TOKEN:
				return __( 'Authentication failed: The provided JWT is invalid or expired.', 'ah-jwt-auth' );
			case self::MISSING_EMAIL:
				return __( 'Authentication failed: The provided JWT did not include an email claim.', 'ah-jwt-auth' );
			case self::NO_ACCOUNT:
				return __( 'Authentication failed: No account exists for this JWT.', 'ah-jwt-auth' );
			default:
				return __( 'Authentication failed: The account for this JWT could not be created.', 'ah-jwt-auth' );
		}
	}
}
