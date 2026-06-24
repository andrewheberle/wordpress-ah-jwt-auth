<?php
/**
 * Kahlan test configuration.
 *
 * @package AhJwtAuth
 */

use Kahlan\Filter\Filters;

Filters::apply(
	$this,
	'bootstrap',
	function ( $next ) {
		require __DIR__ . '/tests/bootstrap.php';

		return $next();
	}
);
