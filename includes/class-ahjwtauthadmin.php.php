<?php
namespace AhJwtAuth;

class AhJwtAuthAdmin {
	public function __construct() {
		add_action( 'admin_init', array( $this, 'registerSettingsAction' ) );
		add_action( 'admin_menu', array( $this, 'optionsMenuAction' ) );
	}

	public function optionsMenuAction() {
		add_options_page(
			'AH JWT Auth Options',
			'AH JWT Auth',
			'manage_options',
			'ahjwtauth-sign-in-widget',
			array( $this, 'optionsPageAction' )
		);
	}

	public function optionsPageAction() {
		if ( current_user_can( 'manage_options' ) )  {
			include( plugin_dir_path( __FILE__ )."../templates/options-form.php" );
		} else {
			wp_die( 'You do not have sufficient permissions to access this page.' );
		}
	}

	public function optionsPageTextInputAction($option_name, $type, $placeholder=false, $description=false) {
		$option_value = get_option( $option_name, '' );
		printf(
			'<input type="%s" id="%s" name="%s" value="%s" style="width: 100%%" autocomplete="off" placeholder="%s" />',
			esc_attr( $type ),
			esc_attr( $option_name ),
			esc_attr( $option_name ),
			esc_attr( $option_value ),
			esc_attr( $placeholder )
		);
		if ( false !== $description )
			echo '<p class="description">'.$description.'</p>';
	}

	public function optionsPageSelectInputAction($option_name, $description=false) {
		$option_value = get_option( $option_name, '' );
		printf( '<select id="%s" name="%s">', esc_attr( $option_name ), esc_attr( $option_name ) );
		wp_dropdown_roles( $option_value );
		printf('</select>');
		if ( false !== $description ) {
			echo '<p class="description">'.$description.'</p>';
		}
	}

	public function registerSettingsAction() {
		add_settings_section(
			'ahjwtauth-sign-in-widget-options-section',
			'',
			null,
			'ahjwtauth-sign-in-widget'
		);
		
		register_setting(
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-private-secret',
			array(
				'type' => 'string',
				'show_in_rest' => false,
			),
		);

		register_setting(
			'ahjwtauth-sign-in-widget', 
			'ahjwtauth-jwks-url', 
			array(
				'type' => 'string',
				'show_in_rest' => true,
			),
		);

		register_setting(
			'ahjwtauth-sign-in-widget', 
			'ahjwtauth-jwt-header', 
			array(
				'type' => 'string',
				'show_in_rest' => true,
				'default' => 'Authorization',
			),
		);

		add_settings_field(
			'ahjwtauth-private-secret',
			'JWT Private Secret',
			function() { $this->optionsPageTextInputAction('ahjwtauth-private-secret', 'text', __('Paste your JWT private secret here.', 'ah-jwt-auth'), __('This secret is used for verifying the token (use this field or the "JWKS URL", not both).', 'ah-jwt-auth')); },
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section'
		);

		add_settings_field(
			'ahjwtauth-jwks-url',
			'JWKS URL',
			function() {
				$this->optionsPageTextInputAction(
					'ahjwtauth-jwks-url',
					'text',
					__('Enter the JWKS URL to validate the JWT.', 'ah-jwt-auth'),
					__('The retreived JWKS is used for verifying the token (use this field or the "JWT Private Secret", not both)',
					'ah-jwt-auth')
				); 
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			'ahjwtauth-jwt-header',
			'JWT Header',
			function() {
				$this->optionsPageTextInputAction(
					'ahjwtauth-jwt-header',
					'text',
					__('Enter the HTTP header that contains the JWT.', 'ah-jwt-auth'),
					__('The JWT will be retrieved from the specified HTTP header. This defaults to the "Authorization" header.', 'ah-jwt-auth'),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			'ahjwtauth-user-role',
			'Default User Role',
			function() {
				$this->optionsPageSelectInputAction(
					'ahjwtauth-user-role',
					__('Select the role for and auto-created user if a role claim is not found in the JWT.', 'ah-jwt-auth'),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);
	}
}
