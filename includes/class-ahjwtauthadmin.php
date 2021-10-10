<?php
/**
 *
 * AhJwtAuthAdmin handles the admin side of the plugin.
 *
 * @file
 * @category AhJwtAuthAdmin
 * @package AhJwtAuth
 */

namespace AhJwtAuth;

/**
 *
 * This class handles the settings/admin sie of the plugin to
 * allow configuration of the plugin.
 *
 * @category Class
 * @package AhJwtAuth
 */
class AhJwtAuthAdmin {
	/**
	 * Sets up the class ready for use
	 *
	 * @return void
	 */
	public function __construct() {
		add_action( 'admin_init', array( $this, 'register_settings_action' ) );
		add_action( 'admin_menu', array( $this, 'options_menu_action' ) );
	}

	/**
	 * Sets up the plugin options page action
	 *
	 * @return void
	 */
	public function options_menu_action() {
		add_options_page(
			'AH JWT Auth Options',
			'AH JWT Auth',
			'manage_options',
			'ahjwtauth-sign-in-widget',
			array( $this, 'options_page_action' )
		);
	}

	/**
	 * Includes the option page if the user has permissions
	 *
	 * @return void
	 */
	public function options_page_action() {
		if ( current_user_can( 'manage_options' ) ) {
			include( plugin_dir_path( __FILE__ ) . '../templates/options-form.php' );
		} else {
			wp_die( 'You do not have sufficient permissions to access this page.' );
		}
	}

	/**
	 * Displays a text input field on the options page
	 *
	 * @return void
	 */
	public function options_page_text_input_action( $option_name, $type, $placeholder = false, $description = false ) {
		$option_value = get_option( $option_name, '' );
		printf(
			'<input type="%s" id="%s" name="%s" value="%s" style="width: 100%%" autocomplete="off" placeholder="%s" />',
			esc_attr( $type ),
			esc_attr( $option_name ),
			esc_attr( $option_name ),
			esc_attr( $option_value ),
			esc_attr( $placeholder )
		);
		if ( false !== $description ) {
			echo '<p class="description">' . esc_html( $description ) . '</p>';
		}
	}

	/**
	 * Displays a select/drop-down input field on the options page
	 *
	 * @return void
	 */
	public function options_page_select_input_action( $option_name, $description = false ) {
		$option_value = get_option( $option_name, '' );
		printf( '<select id="%s" name="%s">', esc_attr( $option_name ), esc_attr( $option_name ) );
		wp_dropdown_roles( $option_value );
		printf( '</select>' );
		if ( false !== $description ) {
			echo '<p class="description">' . esc_html( $description ) . '</p>';
		}
	}

	/**
	 * Displays a text input field on the options page
	 *
	 * @return void
	 */
	public function register_settings_action() {
		add_settings_section(
			'ahjwtauth-sign-in-widget-options-section',
			'',
			null,
			'ahjwtauth-sign-in-widget',
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
			function() {
				$this->options_page_text_input_action(
					'ahjwtauth-private-secret',
					'text',
					__( 'Paste your JWT private secret here.', 'ah-jwt-auth' ),
					__( 'This secret is used for verifying the token (use this field or the "JWKS URL", not both).', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section'
		);

		add_settings_field(
			'ahjwtauth-jwks-url',
			'JWKS URL',
			function() {
				$this->options_page_text_input_action(
					'ahjwtauth-jwks-url',
					'text',
					__( 'Enter the JWKS URL to validate the JWT.', 'ah-jwt-auth' ),
					__( 'The retreived JWKS is used for verifying the token (use this field or the "JWT Private Secret", not both)', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			'ahjwtauth-jwt-header',
			'JWT Header',
			function() {
				$this->options_page_text_input_action(
					'ahjwtauth-jwt-header',
					'text',
					__( 'Enter the HTTP header that contains the JWT.', 'ah-jwt-auth' ),
					__( 'The JWT will be retrieved from the specified HTTP header. This defaults to the "Authorization" header.', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			'ahjwtauth-user-role',
			'Default User Role',
			function() {
				$this->options_page_select_input_action(
					'ahjwtauth-user-role',
					__( 'Select the role for and auto-created user if a role claim is not found in the JWT.', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);
	}
}
