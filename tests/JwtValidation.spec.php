<?php
/**
 * Audience validation specs.
 *
 * @package AhJwtAuth
 */

declare(strict_types=1);

use AhJwtAuth\AhJwtAuthSignIn;
use Firebase\JWT\JWT;

function verify_token_for_test( $configured_audience, $payload, $configured_key = 'a-test-secret-at-least-256-bits-long', $signing_key = null, $algorithm = 'HS256' ) {
	$GLOBALS['ahjwtauth_test_options']['ahjwtauth-audience'] = $configured_audience;
	$GLOBALS['ahjwtauth_test_options']['ahjwtauth-private-secret'] = $configured_key;
	$GLOBALS['ahjwtauth_test_options']['ahjwtauth-jwks-url'] = '';

	$jwt = JWT::encode( $payload, null === $signing_key ? $configured_key : $signing_key, $algorithm );

	$reflection = new ReflectionClass( AhJwtAuthSignIn::class );
	$sign_in = $reflection->newInstanceWithoutConstructor();
	$method = $reflection->getMethod( 'verify_token' );
	$method->setAccessible( true );

	return $method->invoke( $sign_in, $jwt );
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

describe(
	'AhJwtAuthSignIn Basic JWT validation',
	function() {
		beforeEach(
			function() {
				$GLOBALS['ahjwtauth_test_options'] = array();
			}
		);
	
		it(
			'decodes a minimal signed JWT',
			function() {
				$payload = array(
					'email' => 'admin@example.com',
				);

				$decoded = verify_token_for_test( '', $payload );

				expect( $decoded )->not->toBe( false );
				expect( $decoded->email )->toBe( 'admin@example.com' );
			}
		);

		it(
			'decodes a JWT with all full set of claims',
			function() {
				$iat = time() - 240;
				$payload = array(
					'iss' => 'example.com',
					'email' => 'admin@example.com',
					'aud' => 'oauth-client-id',
					'iat' => $iat,
					'nbf' => $iat,
					'exp' => $iat + 480,
				);

				$decoded = verify_token_for_test( 'oauth-client-id', $payload );

				expect( $decoded )->not->toBe( false );
				expect( $decoded->iss )->toBe( 'example.com' );
				expect( $decoded->email )->toBe( 'admin@example.com' );
				expect( $decoded->aud )->toBe( 'oauth-client-id' );
			}
		);

		it(
			'rejects an expired JWT',
			function() {
				$iat = time() - 240;
				$payload = array(
					'iss' => 'example.com',
					'email' => 'admin@example.com',
					'aud' => 'oauth-client-id',
					'iat' => $iat,
					'nbf' => $iat,
					'exp' => $iat + 120,
				);

				$decoded = verify_token_for_test( 'oauth-client-id', $payload );

				expect( $decoded )->toBe( false );
			}
		);

		it(
			'rejects a JWT issued in the future',
			function() {
				$iat = time() + 240;
				$payload = array(
					'iss' => 'example.com',
					'email' => 'admin@example.com',
					'aud' => 'oauth-client-id',
					'iat' => $iat,
					'nbf' => $iat,
					'exp' => $iat + 120,
				);

				$decoded = verify_token_for_test( 'oauth-client-id', $payload );

				expect( $decoded )->toBe( false );
			}
		);

		it(
			'rejects a JWT that is not yet valid',
			function() {
				$iat = time() - 60;
				$payload = array(
					'iss' => 'example.com',
					'email' => 'admin@example.com',
					'aud' => 'oauth-client-id',
					'iat' => $iat,
					'nbf' => $iat + 120,
					'exp' => $iat + 480,
				);

				$decoded = verify_token_for_test( 'oauth-client-id', $payload );

				expect( $decoded )->toBe( false );
			}
		);

		it(
			'accepts a JWT that is has the correct issuer',
			function() {
				$GLOBALS['ahjwtauth_test_options']['ahjwtauth-issuer'] = 'example.com';
				$iat = time() - 60;
				$payload = array(
					'iss' => 'example.com',
					'email' => 'admin@example.com',
					'aud' => 'oauth-client-id',
					'iat' => $iat,
					'nbf' => $iat,
					'exp' => $iat + 480,
				);

				$decoded = verify_token_for_test( 'oauth-client-id', $payload );

				expect( $decoded )->not->toBe( false );
				expect( $decoded->iss )->toBe( 'example.com' );
				expect( $decoded->email )->toBe( 'admin@example.com' );
				expect( $decoded->aud )->toBe( 'oauth-client-id' );
			}
		);

		it(
			'rejects a JWT that is has the incorrect issuer',
			function() {
				$GLOBALS['ahjwtauth_test_options']['ahjwtauth-issuer'] = 'example.org';
				$iat = time() - 60;
				$payload = array(
					'iss' => 'example.com',
					'email' => 'admin@example.com',
					'aud' => 'oauth-client-id',
					'iat' => $iat,
					'nbf' => $iat,
					'exp' => $iat + 480,
				);

				$decoded = verify_token_for_test( 'oauth-client-id', $payload );

				expect( $decoded )->toBe( false );
			}
		);
	}
);

describe(
	'AhJwtAuthSignIn JWT audience validation',
	function() {
		beforeEach(
			function() {
				$GLOBALS['ahjwtauth_test_options'] = array();
			}
		);

		it(
			'decodes a signed JWT without checking aud when no audience is configured',
			function() {
				$payload = array(
					'email' => 'admin@example.com',
				);

				$decoded = verify_token_for_test( '', $payload );

				expect( $decoded )->not->toBe( false );
				expect( $decoded->email )->toBe( 'admin@example.com' );
			}
		);

		it(
			'decodes a signed JWT with a matching string audience',
			function() {
				$payload = array(
					'email' => 'admin@example.com',
					'aud' => 'oauth-client-id',
				);

				$decoded = verify_token_for_test( 'oauth-client-id', $payload );

				expect( $decoded )->not->toBe( false );
				expect( $decoded->aud )->toBe( 'oauth-client-id' );
			}
		);

		it(
			'decodes an RS256 JWT when the configured key value is a PEM public key',
			function() {
				$key_pair = rsa_key_pair_for_test();
				$payload = array(
					'email' => 'admin@example.com',
					'aud' => 'oauth-client-id',
				);

				$decoded = verify_token_for_test( 'oauth-client-id', $payload, $key_pair['public'], $key_pair['private'], 'RS256' );

				expect( $decoded )->not->toBe( false );
				expect( $decoded->aud )->toBe( 'oauth-client-id' );
			}
		);

		it(
			'decodes a signed JWT with a matching audience in an array claim',
			function() {
				$payload = array(
					'email' => 'admin@example.com',
					'aud' => array( 'other-client-id', 'oauth-client-id' ),
				);

				$decoded = verify_token_for_test( 'oauth-client-id', $payload );

				expect( $decoded )->not->toBe( false );
				expect( $decoded->aud )->toContain( 'oauth-client-id' );
			}
		);

		it(
			'trims the configured audience before validation',
			function() {
				$payload = array(
					'email' => 'admin@example.com',
					'aud' => 'oauth-client-id',
				);

				$decoded = verify_token_for_test( ' oauth-client-id ', $payload );

				expect( $decoded )->not->toBe( false );
				expect( $decoded->aud )->toBe( 'oauth-client-id' );
			}
		);

		it(
			'rejects a signed JWT when the configured audience is missing from the payload',
			function() {
				$payload = array(
					'email' => 'admin@example.com',
				);

				expect( verify_token_for_test( 'oauth-client-id', $payload ) )->toBe( false );
			}
		);

		it(
			'rejects a signed JWT with a mismatched string audience',
			function() {
				$payload = array(
					'email' => 'admin@example.com',
					'aud' => 'wrong-client-id',
				);

				expect( verify_token_for_test( 'oauth-client-id', $payload ) )->toBe( false );
			}
		);

		it(
			'rejects a signed JWT with a mismatched array audience',
			function() {
				$payload = array(
					'email' => 'admin@example.com',
					'aud' => array( 'wrong-client-id', 'other-client-id' ),
				);

				expect( verify_token_for_test( 'oauth-client-id', $payload ) )->toBe( false );
			}
		);

		it(
			'rejects a signed JWT with a non-string audience claim value',
			function() {
				$payload = array(
					'email' => 'admin@example.com',
					'aud' => 12345,
				);

				expect( verify_token_for_test( 'oauth-client-id', $payload ) )->toBe( false );
			}
		);

		it(
			'rejects a JWT signed with the wrong secret before audience validation can pass',
			function() {
				$GLOBALS['ahjwtauth_test_options']['ahjwtauth-audience'] = 'oauth-client-id';
				$GLOBALS['ahjwtauth_test_options']['ahjwtauth-private-secret'] = 'the-expected-secret-at-least-256-bits-long';
				$GLOBALS['ahjwtauth_test_options']['ahjwtauth-jwks-url'] = '';

				$jwt = JWT::encode(
					array(
						'email' => 'admin@example.com',
						'aud' => 'oauth-client-id',
					),
					'the-wrong-secret-at-least-256-bits-long',
					'HS256'
				);

				$reflection = new ReflectionClass( AhJwtAuthSignIn::class );
				$sign_in = $reflection->newInstanceWithoutConstructor();
				$method = $reflection->getMethod( 'verify_token' );
				$method->setAccessible( true );

				expect( $method->invoke( $sign_in, $jwt ) )->toBe( false );
			}
		);
	}
);
