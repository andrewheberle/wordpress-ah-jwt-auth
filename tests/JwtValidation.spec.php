<?php
/**
 * Token verifier specs.
 *
 * @package AhJwtAuth
 */

declare(strict_types=1);

use AhJwtAuth\AhJwtAuthStaticKeySource;
use AhJwtAuth\AhJwtAuthTokenVerifier;
use AhJwtAuth\AhJwtAuthVerificationFailure;
use Firebase\JWT\JWT;

const TEST_SECRET = 'a-test-secret-at-least-256-bits-long';

function verify_token_for_test( $payload, $audience = '', $issuer = '' ) {
	$verifier = new AhJwtAuthTokenVerifier( new AhJwtAuthStaticKeySource( TEST_SECRET ), $audience, $issuer );

	return $verifier->verify( JWT::encode( $payload, TEST_SECRET, 'HS256' ) );
}

function rsa_key_pair_for_test() {
	$private_key = openssl_pkey_new(
		array(
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		)
	);
	openssl_pkey_export( $private_key, $private_key_pem );
	$details = openssl_pkey_get_details( $private_key );

	return array(
		'private' => $private_key_pem,
		'public' => $details['key'],
	);
}

function expect_failure( $result, $code ) {
	expect( $result )->toBeAnInstanceOf( AhJwtAuthVerificationFailure::class );
	expect( $result->get_code() )->toBe( $code );
}

describe(
	'AhJwtAuthTokenVerifier key and signature',
	function() {
		it(
			'decodes a minimal signed JWT',
			function() {
				$decoded = verify_token_for_test( array( 'email' => 'admin@example.com' ) );

				expect( $decoded->email )->toBe( 'admin@example.com' );
			}
		);

		it(
			'decodes an RS256 JWT when the key source holds a PEM public key',
			function() {
				$key_pair = rsa_key_pair_for_test();
				$verifier = new AhJwtAuthTokenVerifier( new AhJwtAuthStaticKeySource( $key_pair['public'] ) );

				$decoded = $verifier->verify( JWT::encode( array( 'email' => 'admin@example.com' ), $key_pair['private'], 'RS256' ) );

				expect( $decoded->email )->toBe( 'admin@example.com' );
			}
		);

		it(
			'fails with no_key when the key source has no key configured',
			function() {
				$verifier = new AhJwtAuthTokenVerifier( new AhJwtAuthStaticKeySource( '' ) );

				expect_failure( $verifier->verify( JWT::encode( array(), TEST_SECRET, 'HS256' ) ), AhJwtAuthVerificationFailure::NO_KEY );
			}
		);

		it(
			'fails with invalid_signature when the JWT is signed with the wrong secret',
			function() {
				$verifier = new AhJwtAuthTokenVerifier( new AhJwtAuthStaticKeySource( TEST_SECRET ) );
				$jwt      = JWT::encode( array( 'email' => 'admin@example.com' ), 'the-wrong-secret-at-least-256-bits-long', 'HS256' );

				expect_failure( $verifier->verify( $jwt ), AhJwtAuthVerificationFailure::INVALID_SIGNATURE );
			}
		);

		it(
			'fails with invalid_token when the value is not a JWT',
			function() {
				$verifier = new AhJwtAuthTokenVerifier( new AhJwtAuthStaticKeySource( TEST_SECRET ) );

				expect_failure( $verifier->verify( 'Basic dXNlcjpwYXNz' ), AhJwtAuthVerificationFailure::INVALID_TOKEN );
			}
		);

		it(
			'keeps the underlying error as the failure detail',
			function() {
				$verifier = new AhJwtAuthTokenVerifier( new AhJwtAuthStaticKeySource( TEST_SECRET ) );

				expect( $verifier->verify( 'Basic dXNlcjpwYXNz' )->get_detail() )->toBe( 'Wrong number of segments' );
			}
		);
	}
);

describe(
	'AhJwtAuthTokenVerifier time claims',
	function() {
		it(
			'decodes a JWT with a full set of claims',
			function() {
				$iat     = time() - 240;
				$decoded = verify_token_for_test(
					array(
						'iss'   => 'example.com',
						'email' => 'admin@example.com',
						'aud'   => 'oauth-client-id',
						'iat'   => $iat,
						'nbf'   => $iat,
						'exp'   => $iat + 480,
					),
					'oauth-client-id',
					'example.com'
				);

				expect( $decoded->iss )->toBe( 'example.com' );
				expect( $decoded->email )->toBe( 'admin@example.com' );
				expect( $decoded->aud )->toBe( 'oauth-client-id' );
			}
		);

		it(
			'fails with expired for an expired JWT',
			function() {
				$iat = time() - 240;

				expect_failure(
					verify_token_for_test( array( 'iat' => $iat, 'nbf' => $iat, 'exp' => $iat + 120 ) ),
					AhJwtAuthVerificationFailure::EXPIRED
				);
			}
		);

		it(
			'fails with not_yet_valid for a JWT issued in the future',
			function() {
				$iat = time() + 240;

				expect_failure(
					verify_token_for_test( array( 'iat' => $iat, 'exp' => $iat + 120 ) ),
					AhJwtAuthVerificationFailure::NOT_YET_VALID
				);
			}
		);

		it(
			'fails with not_yet_valid for a JWT used before its nbf claim',
			function() {
				$iat = time() - 60;

				expect_failure(
					verify_token_for_test( array( 'iat' => $iat, 'nbf' => $iat + 120, 'exp' => $iat + 480 ) ),
					AhJwtAuthVerificationFailure::NOT_YET_VALID
				);
			}
		);
	}
);

describe(
	'AhJwtAuthTokenVerifier issuer validation',
	function() {
		it(
			'decodes a JWT without checking iss when no issuer is configured',
			function() {
				expect( verify_token_for_test( array( 'iss' => 'anything' ) )->iss )->toBe( 'anything' );
			}
		);

		it(
			'decodes a JWT with the configured issuer',
			function() {
				expect( verify_token_for_test( array( 'iss' => 'example.com' ), '', 'example.com' )->iss )->toBe( 'example.com' );
			}
		);

		it(
			'trims the configured issuer before validation',
			function() {
				expect( verify_token_for_test( array( 'iss' => 'example.com' ), '', ' example.com ' )->iss )->toBe( 'example.com' );
			}
		);

		it(
			'fails with missing_issuer when the configured issuer is missing from the payload',
			function() {
				expect_failure( verify_token_for_test( array(), '', 'example.com' ), AhJwtAuthVerificationFailure::MISSING_ISSUER );
			}
		);

		it(
			'fails with issuer_mismatch for a different issuer',
			function() {
				expect_failure( verify_token_for_test( array( 'iss' => 'example.com' ), '', 'example.org' ), AhJwtAuthVerificationFailure::ISSUER_MISMATCH );
			}
		);

		it(
			'fails with issuer_mismatch for a non-string iss claim',
			function() {
				expect_failure( verify_token_for_test( array( 'iss' => 12345 ), '', 'example.com' ), AhJwtAuthVerificationFailure::ISSUER_MISMATCH );
			}
		);
	}
);

describe(
	'AhJwtAuthTokenVerifier audience validation',
	function() {
		it(
			'decodes a JWT without checking aud when no audience is configured',
			function() {
				expect( verify_token_for_test( array( 'email' => 'admin@example.com' ) )->email )->toBe( 'admin@example.com' );
			}
		);

		it(
			'decodes a JWT with a matching string audience',
			function() {
				expect( verify_token_for_test( array( 'aud' => 'oauth-client-id' ), 'oauth-client-id' )->aud )->toBe( 'oauth-client-id' );
			}
		);

		it(
			'decodes a JWT with a matching audience in an array claim',
			function() {
				$decoded = verify_token_for_test( array( 'aud' => array( 'other-client-id', 'oauth-client-id' ) ), 'oauth-client-id' );

				expect( $decoded->aud )->toContain( 'oauth-client-id' );
			}
		);

		it(
			'trims the configured audience before validation',
			function() {
				expect( verify_token_for_test( array( 'aud' => 'oauth-client-id' ), ' oauth-client-id ' )->aud )->toBe( 'oauth-client-id' );
			}
		);

		it(
			'fails with missing_audience when the configured audience is missing from the payload',
			function() {
				expect_failure( verify_token_for_test( array(), 'oauth-client-id' ), AhJwtAuthVerificationFailure::MISSING_AUDIENCE );
			}
		);

		it(
			'fails with audience_mismatch for a different string audience',
			function() {
				expect_failure( verify_token_for_test( array( 'aud' => 'wrong-client-id' ), 'oauth-client-id' ), AhJwtAuthVerificationFailure::AUDIENCE_MISMATCH );
			}
		);

		it(
			'fails with audience_mismatch when no array audience matches',
			function() {
				expect_failure(
					verify_token_for_test( array( 'aud' => array( 'wrong-client-id', 'other-client-id' ) ), 'oauth-client-id' ),
					AhJwtAuthVerificationFailure::AUDIENCE_MISMATCH
				);
			}
		);

		it(
			'fails with audience_mismatch for a non-string aud claim',
			function() {
				expect_failure( verify_token_for_test( array( 'aud' => 12345 ), 'oauth-client-id' ), AhJwtAuthVerificationFailure::AUDIENCE_MISMATCH );
			}
		);
	}
);

describe(
	'AhJwtAuthVerificationFailure',
	function() {
		it(
			'has an admin message for every failure code',
			function() {
				$codes    = ( new ReflectionClass( AhJwtAuthVerificationFailure::class ) )->getConstants();
				$fallback = ( new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::UNEXPECTED ) )->get_message();

				foreach ( $codes as $code ) {
					if ( AhJwtAuthVerificationFailure::UNEXPECTED !== $code ) {
						expect( ( new AhJwtAuthVerificationFailure( $code ) )->get_message() )->not->toBe( $fallback );
					}
				}
			}
		);
	}
);
