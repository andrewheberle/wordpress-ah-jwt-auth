<?php
/**
 * Authenticator specs.
 *
 * @package AhJwtAuth
 */

declare(strict_types=1);

use AhJwtAuth\AhJwtAuthAuthenticator;
use AhJwtAuth\AhJwtAuthSettings;
use AhJwtAuth\AhJwtAuthSignInFailure;
use AhJwtAuth\AhJwtAuthVerificationFailure;
use Firebase\JWT\JWT;

function authenticate_for_test( array $headers, array $options = array() ) {
	$GLOBALS['ahjwtauth_test_options'] = array_merge(
		array( AhJwtAuthSettings::PRIVATE_SECRET => TEST_SECRET ),
		$options
	);

	return ( new AhJwtAuthAuthenticator( new AhJwtAuthSettings() ) )->authenticate( $headers );
}

function bearer_for_test( array $payload ) {
	return array( 'Authorization' => 'Bearer ' . JWT::encode( $payload, TEST_SECRET, 'HS256' ) );
}

function add_user_for_test( $login, $email, $role ) {
	$user             = new WP_User();
	$user->ID         = count( $GLOBALS['ahjwtauth_test_users'] ) + 1;
	$user->user_login = $login;
	$user->user_email = $email;
	$user->set_role( $role );
	$GLOBALS['ahjwtauth_test_users'][] = $user;

	return $user;
}

function expect_sign_in_failure( $result, $code ) {
	expect( $result )->toBeAnInstanceOf( AhJwtAuthSignInFailure::class );
	expect( $result->get_code() )->toBe( $code );
}

describe(
	'AhJwtAuthAuthenticator token extraction',
	function() {
		beforeEach(
			function() {
				$GLOBALS['ahjwtauth_test_users'] = array();
				add_user_for_test( 'admin', 'admin@example.com', 'administrator' );
			}
		);

		it(
			'fails with no_token when the configured header is missing',
			function() {
				expect_sign_in_failure( authenticate_for_test( array( 'Cookie' => 'a=b' ) ), AhJwtAuthSignInFailure::NO_TOKEN );
			}
		);

		it(
			'reads the configured header case-insensitively',
			function() {
				$jwt  = JWT::encode( array( 'email' => 'admin@example.com' ), TEST_SECRET, 'HS256' );
				$user = authenticate_for_test( array( 'x-auth-token' => $jwt ), array( AhJwtAuthSettings::JWT_HEADER => 'X-Auth-Token' ) );

				expect( $user->user_login )->toBe( 'admin' );
			}
		);

		it(
			'accepts a token without the Bearer prefix',
			function() {
				$jwt = JWT::encode( array( 'email' => 'admin@example.com' ), TEST_SECRET, 'HS256' );

				expect( authenticate_for_test( array( 'Authorization' => $jwt ) )->user_login )->toBe( 'admin' );
			}
		);

		it(
			'fails with invalid_token carrying the verification failure',
			function() {
				$headers = array( 'Authorization' => 'Bearer ' . JWT::encode( array( 'email' => 'admin@example.com' ), 'the-wrong-secret-at-least-256-bits-long', 'HS256' ) );
				$result  = authenticate_for_test( $headers );

				expect_sign_in_failure( $result, AhJwtAuthSignInFailure::INVALID_TOKEN );
				expect( $result->get_message() )->toBe( ( new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::INVALID_SIGNATURE ) )->get_message() );
				expect( $result->get_detail() )->toBe( 'Signature verification failed' );
			}
		);
	}
);

describe(
	'AhJwtAuthAuthenticator user resolution',
	function() {
		beforeEach(
			function() {
				$GLOBALS['ahjwtauth_test_users'] = array();
				add_user_for_test( 'editor', 'editor@example.com', 'editor' );
			}
		);

		it(
			'fails with missing_email when the JWT has no email claim',
			function() {
				expect_sign_in_failure( authenticate_for_test( bearer_for_test( array( 'sub' => '123' ) ) ), AhJwtAuthSignInFailure::MISSING_EMAIL );
			}
		);

		it(
			'fails with missing_email when the email claim is not a string',
			function() {
				expect_sign_in_failure(
					authenticate_for_test( bearer_for_test( array( 'email' => array( 'editor@example.com' ) ) ) ),
					AhJwtAuthSignInFailure::MISSING_EMAIL
				);
			}
		);

		it(
			'returns the existing user for the email claim without changing their role',
			function() {
				$user = authenticate_for_test( bearer_for_test( array( 'email' => 'editor@example.com' ) ) );

				expect( $user->user_login )->toBe( 'editor' );
				expect( $user->roles )->toBe( array( 'editor' ) );
			}
		);

		it(
			'applies a valid role claim to an existing user',
			function() {
				$user = authenticate_for_test( bearer_for_test( array( 'email' => 'editor@example.com', 'role' => 'Author' ) ) );

				expect( $user->roles )->toBe( array( 'author' ) );
			}
		);

		it(
			'ignores an unknown role claim for an existing user',
			function() {
				$user = authenticate_for_test( bearer_for_test( array( 'email' => 'editor@example.com', 'role' => 'not-a-role' ) ) );

				expect( $user->roles )->toBe( array( 'editor' ) );
			}
		);

		it(
			'fails with no_account when the user does not exist and creation is disabled',
			function() {
				expect_sign_in_failure(
					authenticate_for_test(
						bearer_for_test( array( 'email' => 'new@example.com' ) ),
						array( AhJwtAuthSettings::DISABLE_USER_CREATION => '1' )
					),
					AhJwtAuthSignInFailure::NO_ACCOUNT
				);
				expect( get_user_by( 'email', 'new@example.com' ) )->toBe( false );
			}
		);

		it(
			'creates a new user with the configured default role when there is no role claim',
			function() {
				$user = authenticate_for_test(
					bearer_for_test( array( 'email' => 'new@example.com' ) ),
					array( AhJwtAuthSettings::USER_ROLE => 'author' )
				);

				expect( $user->user_login )->toBe( 'new@example.com' );
				expect( $user->user_email )->toBe( 'new@example.com' );
				expect( $user->roles )->toBe( array( 'author' ) );
			}
		);

		it(
			'creates a new user with a valid role claim',
			function() {
				$user = authenticate_for_test( bearer_for_test( array( 'email' => 'new@example.com', 'role' => 'editor' ) ) );

				expect( $user->roles )->toBe( array( 'editor' ) );
			}
		);

		it(
			'creates a new user with the configured default role when the role claim is unknown',
			function() {
				$user = authenticate_for_test(
					bearer_for_test( array( 'email' => 'new@example.com', 'role' => 'not-a-role' ) ),
					array(
						AhJwtAuthSettings::USER_ROLE => 'author',
						'default_role'               => 'contributor',
					)
				);

				expect( $user->roles )->toBe( array( 'author' ) );
			}
		);

		it(
			'fails with user_creation_failed when WordPress cannot create the user',
			function() {
				add_user_for_test( 'new@example.com', 'someone-else@example.com', 'subscriber' );

				$result = authenticate_for_test( bearer_for_test( array( 'email' => 'new@example.com' ) ) );

				expect_sign_in_failure( $result, AhJwtAuthSignInFailure::USER_CREATION_FAILED );
				expect( $result->get_detail() )->toBe( 'Sorry, that username already exists!' );
			}
		);
	}
);

describe(
	'AhJwtAuthSignInFailure',
	function() {
		it(
			'has its own admin and visitor message for every failure code',
			function() {
				$codes = ( new ReflectionClass( AhJwtAuthSignInFailure::class ) )->getConstants();

				$admin_messages   = array();
				$visitor_messages = array();
				foreach ( $codes as $code ) {
					$failure = AhJwtAuthSignInFailure::INVALID_TOKEN === $code
						? AhJwtAuthSignInFailure::invalid_token( new AhJwtAuthVerificationFailure( AhJwtAuthVerificationFailure::EXPIRED ) )
						: new AhJwtAuthSignInFailure( $code );

					$admin_messages[]   = $failure->get_message();
					$visitor_messages[] = $failure->get_visitor_message();
				}

				expect( count( array_unique( $admin_messages ) ) )->toBe( count( $codes ) );
				expect( count( array_unique( $visitor_messages ) ) )->toBe( count( $codes ) );
			}
		);
	}
);
