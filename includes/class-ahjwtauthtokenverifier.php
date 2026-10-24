<?php
/**
 *
 * AhJwtAuthTokenVerifier verifies a JWT and its claims.
 *
 * @file
 * @category AhJwtAuthTokenVerifier
 * @package  AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use DomainException;
use Exception;
use InvalidArgumentException;
use UnexpectedValueException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;

/**
 *
 * Verifies the signature and time claims of a JWT using a key source, then
 * checks the aud and iss claims against the configured values.
 *
 * @category Class
 * @package  AhJwtAuth
 */
class AhJwtAuthTokenVerifier {
	/**
	 * The source of the key used to verify the JWT signature.
	 *
	 * @var AhJwtAuthKeySource
	 */
	private $key_source;

	/**
	 * The expected aud claim, or an empty string to skip the check.
	 *
	 * @var string
	 */
	private $audience;

	/**
	 * The expected iss claim, or an empty string to skip the check.
	 *
	 * @var string
	 */
	private $issuer;

	/**
	 * Sets up the verifier
	 *
	 * An empty audience or issuer disables that check, to maintain backwards
	 * compatibility with existing installations.
	 *
	 * @param AhJwtAuthKeySource $key_source the source of the key used to verify the JWT signature.
	 * @param string             $audience the expected aud claim.
	 * @param string             $issuer the expected iss claim.
	 * @return void
	 */
	public function __construct( AhJwtAuthKeySource $key_source, $audience = '', $issuer = '' ) {
		$this->key_source = $key_source;
		$this->audience   = trim( (string) $audience );
		$this->issuer     = trim( (string) $issuer );
	}

	/**
	 * Verifies the JWT
	 *
	 * @param string $jwt the JWT to verify.
	 * @return object|AhJwtAuthVerificationFailure the payload from the JWT, or why it failed verification
	 */
	public function verify( $jwt ) {
		$key = $this->key_source->get_key();
		if ( false === $key ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::NO_KEY );
		}

		// The firebase/php-jwt exceptions extend UnexpectedValueException, so they are caught first.
		try {
			$payload = JWT::decode( $jwt, $key );
		} catch ( InvalidArgumentException $e ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::MALFORMED_KEY, $e->getMessage() );
		} catch ( DomainException $e ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::MALFORMED_TOKEN, $e->getMessage() );
		} catch ( SignatureInvalidException $e ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::INVALID_SIGNATURE, $e->getMessage() );
		} catch ( BeforeValidException $e ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::NOT_YET_VALID, $e->getMessage() );
		} catch ( ExpiredException $e ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::EXPIRED, $e->getMessage() );
		} catch ( UnexpectedValueException $e ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::INVALID_TOKEN, $e->getMessage() );
		} catch ( Exception $e ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::UNEXPECTED, $e->getMessage() );
		}

		$failure = $this->check_audience( $payload );
		if ( null === $failure ) {
			$failure = $this->check_issuer( $payload );
		}

		return null === $failure ? $payload : $failure;
	}

	/**
	 * Checks the aud claim against the configured audience.
	 *
	 * @param object $payload the payload from the JWT.
	 * @return AhJwtAuthVerificationFailure|null the failure, or null if the audience is valid or the check is disabled
	 */
	private function check_audience( $payload ) {
		if ( '' === $this->audience ) {
			return null;
		}

		if ( ! isset( $payload->aud ) ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::MISSING_AUDIENCE );
		}

		$audiences = is_array( $payload->aud ) ? $payload->aud : array( $payload->aud );
		foreach ( $audiences as $audience ) {
			if ( is_string( $audience ) && hash_equals( $this->audience, $audience ) ) {
				return null;
			}
		}

		return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::AUDIENCE_MISMATCH );
	}

	/**
	 * Checks the iss claim against the configured issuer.
	 *
	 * @param object $payload the payload from the JWT.
	 * @return AhJwtAuthVerificationFailure|null the failure, or null if the issuer is valid or the check is disabled
	 */
	private function check_issuer( $payload ) {
		if ( '' === $this->issuer ) {
			return null;
		}

		if ( ! isset( $payload->iss ) ) {
			return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::MISSING_ISSUER );
		}

		if ( is_string( $payload->iss ) && hash_equals( $this->issuer, $payload->iss ) ) {
			return null;
		}

		return new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::ISSUER_MISMATCH );
	}
}
