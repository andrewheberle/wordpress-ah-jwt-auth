<?php
/**
 * Cross-platform Kahlan test runner.
 *
 * @package AhJwtAuth
 */

declare(strict_types=1);

$vendor_dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ahjwtauth-test-vendor';
putenv( 'COMPOSER_VENDOR_DIR=' . $vendor_dir );
$_ENV['COMPOSER_VENDOR_DIR'] = $vendor_dir;
$_SERVER['COMPOSER_VENDOR_DIR'] = $vendor_dir;

function ahjwtauth_run_command( $command ) {
	$descriptor_spec = array(
		0 => STDIN,
		1 => STDOUT,
		2 => STDERR,
	);

	$process = proc_open( $command, $descriptor_spec, $pipes, dirname( __DIR__ ) );
	if ( ! is_resource( $process ) ) {
		fwrite( STDERR, 'Unable to start command: ' . $command . PHP_EOL );
		exit( 1 );
	}

	$status = proc_close( $process );
	if ( 0 !== $status ) {
		exit( $status );
	}
}

ahjwtauth_run_command( 'composer install --no-interaction --no-progress' );

$kahlan = $vendor_dir . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'kahlan';
if ( 'Windows' === PHP_OS_FAMILY ) {
	$kahlan .= '.bat';
}

ahjwtauth_run_command( escapeshellarg( $kahlan ) . ' --spec=tests' );
