<?php
/**
 *
 * This file renders the settings page for the plugin
 *
 * @file
 * @package AhJwtAuth
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="wrap">
	<h1><?php echo esc_html__( 'AH JWT Auth', 'ah-jwt-auth' ); ?></h1>

	<form method="post" action="options.php">
		<?php settings_fields( 'ahjwtauth-sign-in-widget' ); ?>
		<?php do_settings_sections( 'ahjwtauth-sign-in-widget' ); ?>
		<?php submit_button(); ?>
	</form>
</div>
