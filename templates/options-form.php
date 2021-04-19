<div class="wrap">
	<h1>JWT Proxy Auth Plugin</h1>

	<form method="post" action="options.php">
		<?php settings_fields( 'jwtauth-sign-in-widget' ); ?>
		<?php do_settings_sections( 'jwtauth-sign-in-widget' ); ?>
		<?php submit_button(); ?>
	</form>
</div>
