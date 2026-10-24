<?php
/**
 * Settings specs.
 *
 * @package AhJwtAuth
 */

declare(strict_types=1);

use AhJwtAuth\AhJwtAuthJwksKeySource;
use AhJwtAuth\AhJwtAuthSettings;
use AhJwtAuth\AhJwtAuthStaticKeySource;

function store_options_for_test( array $options ) {
	$GLOBALS['ahjwtauth_test_options'] = $options;
}

describe(
	'AhJwtAuthSettings',
	function() {
		beforeEach(
			function() {
				store_options_for_test( array() );
			}
		);

		it(
			'returns the defaults when nothing is stored',
			function() {
				$settings = new AhJwtAuthSettings();

				expect( $settings->jwks_url() )->toBe( '' );
				expect( $settings->private_secret() )->toBe( '' );
				expect( $settings->jwt_header() )->toBe( 'Authorization' );
				expect( $settings->audience() )->toBe( '' );
				expect( $settings->issuer() )->toBe( '' );
				expect( $settings->default_user_role() )->toBe( 'subscriber' );
				expect( $settings->user_creation_disabled() )->toBe( false );
				expect( $settings->fail_closed() )->toBe( false );
			}
		);

		it(
			'returns the stored values',
			function() {
				store_options_for_test(
					array(
						AhJwtAuthSettings::JWKS_URL               => 'https://example.com/.well-known/jwks.json',
						AhJwtAuthSettings::PRIVATE_SECRET         => 'a-secret',
						AhJwtAuthSettings::JWT_HEADER             => 'X-Auth-Token',
						AhJwtAuthSettings::AUDIENCE               => 'oauth-client-id',
						AhJwtAuthSettings::ISSUER                 => 'example.com',
						AhJwtAuthSettings::USER_ROLE              => 'editor',
						AhJwtAuthSettings::DISABLE_USER_CREATION  => '1',
						AhJwtAuthSettings::FAIL_CLOSED            => '1',
					)
				);
				$settings = new AhJwtAuthSettings();

				expect( $settings->jwks_url() )->toBe( 'https://example.com/.well-known/jwks.json' );
				expect( $settings->private_secret() )->toBe( 'a-secret' );
				expect( $settings->jwt_header() )->toBe( 'X-Auth-Token' );
				expect( $settings->audience() )->toBe( 'oauth-client-id' );
				expect( $settings->issuer() )->toBe( 'example.com' );
				expect( $settings->default_user_role() )->toBe( 'editor' );
				expect( $settings->user_creation_disabled() )->toBe( true );
				expect( $settings->fail_closed() )->toBe( true );
			}
		);

		it(
			'uses the Authorization header when the stored header is blank',
			function() {
				store_options_for_test( array( AhJwtAuthSettings::JWT_HEADER => '  ' ) );

				expect( ( new AhJwtAuthSettings() )->jwt_header() )->toBe( 'Authorization' );
			}
		);

		it(
			'selects the JWKS key source when a JWKS URL is stored',
			function() {
				store_options_for_test(
					array(
						AhJwtAuthSettings::JWKS_URL       => 'https://example.com/.well-known/jwks.json',
						AhJwtAuthSettings::PRIVATE_SECRET => 'a-secret',
					)
				);

				expect( ( new AhJwtAuthSettings() )->key_source() )->toBeAnInstanceOf( AhJwtAuthJwksKeySource::class );
			}
		);

		it(
			'selects the static key source when the stored JWKS URL is empty',
			function() {
				store_options_for_test(
					array(
						AhJwtAuthSettings::JWKS_URL       => '',
						AhJwtAuthSettings::PRIVATE_SECRET => 'a-secret',
					)
				);

				expect( ( new AhJwtAuthSettings() )->key_source() )->toBeAnInstanceOf( AhJwtAuthStaticKeySource::class );
			}
		);

		it(
			'selects the static key source when no JWKS URL has ever been stored',
			function() {
				expect( ( new AhJwtAuthSettings() )->key_source() )->toBeAnInstanceOf( AhJwtAuthStaticKeySource::class );
			}
		);
	}
);
