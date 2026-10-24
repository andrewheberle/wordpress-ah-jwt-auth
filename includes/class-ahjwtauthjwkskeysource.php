<?php
/**
 *
 * AhJwtAuthJwksKeySource provides keys from a JSON Web Key Set (JWKS) URL.
 *
 * @file
 * @category AhJwtAuthJwksKeySource
 * @package  AhJwtAuth
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Firebase\JWT\CachedKeySet;
use ItalyStrap\Cache\Expiration;
use ItalyStrap\Cache\Pool;
use ItalyStrap\Storage\BinaryCacheDecorator;
use ItalyStrap\Storage\Transient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientInterface;

/**
 *
 * Provides the key set published at a JWKS URL, cached in WordPress transients.
 *
 * @category Class
 * @package  AhJwtAuth
 */
class AhJwtAuthJwksKeySource implements AhJwtAuthKeySource {
	/**
	 * The JWKS URL.
	 *
	 * @var string
	 */
	private $jwks_url;

	/**
	 * The HTTP client used to fetch the JWKS.
	 *
	 * @var ClientInterface
	 */
	private $http_client;

	/**
	 * Sets up the key source
	 *
	 * @param string          $jwks_url the JWKS URL.
	 * @param ClientInterface $http_client the HTTP client used to fetch the JWKS.
	 * @return void
	 */
	public function __construct( $jwks_url, ClientInterface $http_client ) {
		$this->jwks_url    = $jwks_url;
		$this->http_client = $http_client;
	}

	/**
	 * Returns the key set to verify the JWT
	 *
	 * The JWKS is fetched lazily when a key is looked up, and cached for a week.
	 *
	 * @return CachedKeySet the key set used for verifying the signature of the JWT
	 */
	public function get_key() {
		return new CachedKeySet(
			$this->jwks_url,
			$this->http_client,
			new Psr17Factory(),
			new Pool( new BinaryCacheDecorator( new Transient() ), new Expiration() ),
			WEEK_IN_SECONDS,
			true
		);
	}
}
