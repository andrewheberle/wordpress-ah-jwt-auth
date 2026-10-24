<?php
/**
 * Key source specs.
 *
 * @package AhJwtAuth
 */

declare(strict_types=1);

use AhJwtAuth\AhJwtAuthJwksKeySource;
use AhJwtAuth\AhJwtAuthStaticKeySource;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * PSR-18 client that serves a fixed JWKS and records requested URLs.
 */
class FakeJwksClient implements ClientInterface {
	public $requested_urls = array();

	private $jwks;

	public function __construct( array $jwks ) {
		$this->jwks = $jwks;
	}

	public function sendRequest( RequestInterface $request ): ResponseInterface {
		$this->requested_urls[] = (string) $request->getUri();

		return new Response( 200, array( 'Content-Type' => 'application/json' ), json_encode( $this->jwks ) );
	}
}

function base64url_for_test( $data ) {
	return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
}

function jwks_for_test( $public_key_pem, $kid ) {
	$details = openssl_pkey_get_details( openssl_pkey_get_public( $public_key_pem ) );

	return array(
		'keys' => array(
			array(
				'kty' => 'RSA',
				'kid' => $kid,
				'alg' => 'RS256',
				'use' => 'sig',
				'n'   => base64url_for_test( $details['rsa']['n'] ),
				'e'   => base64url_for_test( $details['rsa']['e'] ),
			),
		),
	);
}

describe(
	'AhJwtAuthStaticKeySource',
	function() {
		it(
			'verifies an HS256 JWT signed with the configured secret',
			function() {
				$secret = 'a-test-secret-at-least-256-bits-long';
				$jwt    = JWT::encode( array( 'email' => 'admin@example.com' ), $secret, 'HS256' );

				$key = ( new AhJwtAuthStaticKeySource( $secret ) )->get_key();

				expect( JWT::decode( $jwt, $key )->email )->toBe( 'admin@example.com' );
			}
		);

		it(
			'verifies an RS256 JWT when the configured key is a PEM public key',
			function() {
				$key_pair = rsa_key_pair_for_test();
				$jwt      = JWT::encode( array( 'email' => 'admin@example.com' ), $key_pair['private'], 'RS256' );

				$key = ( new AhJwtAuthStaticKeySource( $key_pair['public'] ) )->get_key();

				expect( JWT::decode( $jwt, $key )->email )->toBe( 'admin@example.com' );
			}
		);

		it(
			'returns false when no key material is configured',
			function() {
				expect( ( new AhJwtAuthStaticKeySource( '' ) )->get_key() )->toBe( false );
				expect( ( new AhJwtAuthStaticKeySource( '   ' ) )->get_key() )->toBe( false );
				expect( ( new AhJwtAuthStaticKeySource( false ) )->get_key() )->toBe( false );
			}
		);
	}
);

describe(
	'AhJwtAuthJwksKeySource',
	function() {
		it(
			'verifies an RS256 JWT against the JWKS fetched from the configured URL',
			function() {
				$key_pair = rsa_key_pair_for_test();
				$client   = new FakeJwksClient( jwks_for_test( $key_pair['public'], 'key-1' ) );
				$jwt      = JWT::encode( array( 'email' => 'admin@example.com' ), $key_pair['private'], 'RS256', 'key-1' );

				$key = ( new AhJwtAuthJwksKeySource( 'https://example.com/.well-known/jwks.json', $client ) )->get_key();

				expect( JWT::decode( $jwt, $key )->email )->toBe( 'admin@example.com' );
				expect( $client->requested_urls )->toBe( array( 'https://example.com/.well-known/jwks.json' ) );
			}
		);

		it(
			'rejects a JWT signed by a key that is not in the JWKS',
			function() {
				$published = rsa_key_pair_for_test();
				$attacker  = rsa_key_pair_for_test();
				$client    = new FakeJwksClient( jwks_for_test( $published['public'], 'key-1' ) );
				$jwt       = JWT::encode( array( 'email' => 'admin@example.com' ), $attacker['private'], 'RS256', 'key-1' );

				$key = ( new AhJwtAuthJwksKeySource( 'https://example.com/.well-known/jwks.json', $client ) )->get_key();

				expect(
					function() use ( $jwt, $key ) {
						JWT::decode( $jwt, $key );
					}
				)->toThrow( new SignatureInvalidException( 'Signature verification failed' ) );
			}
		);
	}
);
