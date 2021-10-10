<?php

/**
 * @file
 * This displays our options page
 */

?>
<div class="wrap">
	<h1>AH JWT Auth</h1>

	<form method="post" action="options.php">
		<?php settings_fields( 'ahjwtauth-sign-in-widget' ); ?>
		<?php do_settings_sections( 'ahjwtauth-sign-in-widget' ); ?>
		<?php submit_button(); ?>
	</form>
</div>
