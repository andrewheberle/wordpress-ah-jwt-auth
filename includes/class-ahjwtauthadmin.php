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

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 *
 * This class handles the settings/admin side of the plugin to
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
			__( 'AH JWT Auth Options', 'ah-jwt-auth' ),
			__( 'AH JWT Auth', 'ah-jwt-auth' ),
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
			include plugin_dir_path( __FILE__ ) . '../templates/options-form.php';
		} else {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'ah-jwt-auth' ) );
		}
	}

	/**
	 * Displays a text input field on the options page
	 *
	 * @param string $option_name the name of the plugin option.
	 * @param string $type the type of input field.
	 * @param string $placeholder the placeholder text to include in the input field.
	 * @param string $description description to display under option.
	 * @return void
	 */
	public function options_page_text_input_action( $option_name, $type, $placeholder = false, $description = false ) {
		$option_value = get_option( $option_name, AhJwtAuthSettings::DEFAULTS[ $option_name ] );
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
	 * @param string $option_name the name of the plugin option.
	 * @param string $description description to display under option.
	 * @return void
	 */
	public function options_page_select_input_action( $option_name, $description = false ) {
		$option_value = get_option( $option_name, AhJwtAuthSettings::DEFAULTS[ $option_name ] );
		printf( '<select id="%s" name="%s">', esc_attr( $option_name ), esc_attr( $option_name ) );
		wp_dropdown_roles( $option_value );
		printf( '</select>' );
		if ( false !== $description ) {
			echo '<p class="description">' . esc_html( $description ) . '</p>';
		}
	}

	/**
	 * Displays a checkbox input field on the options page
	 *
	 * @param string $option_name the name of the plugin option.
	 * @param string $label the label displayed next to the checkbox.
	 * @param string $description description to display under option.
	 * @return void
	 */
	public function options_page_checkbox_input_action( $option_name, $label, $description = false ) {
		$option_value = get_option( $option_name, AhJwtAuthSettings::DEFAULTS[ $option_name ] );
		printf(
			'<input type="hidden" name="%1$s" value="0" /><label for="%1$s"><input type="checkbox" id="%1$s" name="%1$s" value="1" %2$s /> %3$s</label>',
			esc_attr( $option_name ),
			checked( '1', $option_value, false ),
			esc_html( $label )
		);
		if ( false !== $description ) {
			echo '<p class="description">' . esc_html( $description ) . '</p>';
		}
	}

	/**
	 * Sets up actions for plugin settings
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
			AhJwtAuthSettings::PRIVATE_SECRET,
			array(
				'type'              => 'string',
				'show_in_rest'      => false,
				'sanitize_callback' => 'sanitize_textarea_field',
				'default'           => AhJwtAuthSettings::DEFAULTS[ AhJwtAuthSettings::PRIVATE_SECRET ],
			),
		);

		register_setting(
			'ahjwtauth-sign-in-widget',
			AhJwtAuthSettings::JWKS_URL,
			array(
				'type'              => 'string',
				'show_in_rest'      => true,
				'sanitize_callback' => 'esc_url_raw',
				'default'           => AhJwtAuthSettings::DEFAULTS[ AhJwtAuthSettings::JWKS_URL ],
			),
		);

		register_setting(
			'ahjwtauth-sign-in-widget',
			AhJwtAuthSettings::JWT_HEADER,
			array(
				'type'              => 'string',
				'show_in_rest'      => true,
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => AhJwtAuthSettings::DEFAULTS[ AhJwtAuthSettings::JWT_HEADER ],
			),
		);

		register_setting(
			'ahjwtauth-sign-in-widget',
			AhJwtAuthSettings::AUDIENCE,
			array(
				'type'              => 'string',
				'show_in_rest'      => true,
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => AhJwtAuthSettings::DEFAULTS[ AhJwtAuthSettings::AUDIENCE ],
			),
		);

		register_setting(
			'ahjwtauth-sign-in-widget',
			AhJwtAuthSettings::ISSUER,
			array(
				'type'              => 'string',
				'show_in_rest'      => true,
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => AhJwtAuthSettings::DEFAULTS[ AhJwtAuthSettings::ISSUER ],
			),
		);

		register_setting(
			'ahjwtauth-sign-in-widget',
			AhJwtAuthSettings::USER_ROLE,
			array(
				'type'              => 'string',
				'show_in_rest'      => true,
				'sanitize_callback' => function ( $value ) {
					$valid_roles = wp_roles()->get_names();
					if ( array_key_exists( $value, $valid_roles ) ) {
						return $value;
					}
					return AhJwtAuthSettings::DEFAULTS[ AhJwtAuthSettings::USER_ROLE ];
				},
				'default'           => AhJwtAuthSettings::DEFAULTS[ AhJwtAuthSettings::USER_ROLE ],
			),
		);

		register_setting(
			'ahjwtauth-sign-in-widget',
			AhJwtAuthSettings::DISABLE_USER_CREATION,
			array(
				'type'              => 'string',
				'show_in_rest'      => true,
				'default'           => AhJwtAuthSettings::DEFAULTS[ AhJwtAuthSettings::DISABLE_USER_CREATION ],
				'sanitize_callback' => function ( $value ) {
					return '1' === $value ? '1' : '0';
				},
			),
		);

		register_setting(
			'ahjwtauth-sign-in-widget',
			AhJwtAuthSettings::FAIL_CLOSED,
			array(
				'type'              => 'string',
				'show_in_rest'      => true,
				'default'           => AhJwtAuthSettings::DEFAULTS[ AhJwtAuthSettings::FAIL_CLOSED ],
				'sanitize_callback' => function ( $value ) {
					return '1' === $value ? '1' : '0';
				},
			),
		);

		add_settings_field(
			AhJwtAuthSettings::PRIVATE_SECRET,
			'JWT Private Secret',
			function () {
				$this->options_page_text_input_action(
					AhJwtAuthSettings::PRIVATE_SECRET,
					'text',
					__( 'Paste your JWT private secret here.', 'ah-jwt-auth' ),
					__( 'This secret is used for verifying the token (use this field or the "JWKS URL", not both).', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section'
		);

		add_settings_field(
			AhJwtAuthSettings::JWKS_URL,
			'JWKS URL',
			function () {
				$this->options_page_text_input_action(
					AhJwtAuthSettings::JWKS_URL,
					'text',
					__( 'Enter the JWKS URL to validate the JWT.', 'ah-jwt-auth' ),
					__( 'The retrieved JWKS is used for verifying the token (use this field or the "JWT Private Secret", not both)', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			AhJwtAuthSettings::JWT_HEADER,
			'JWT Header',
			function () {
				$this->options_page_text_input_action(
					AhJwtAuthSettings::JWT_HEADER,
					'text',
					__( 'Enter the HTTP header that contains the JWT.', 'ah-jwt-auth' ),
					__( 'The JWT will be retrieved from the specified HTTP header. This defaults to the "Authorization" header.', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			AhJwtAuthSettings::ISSUER,
			'JWT Issuer',
			function () {
				$this->options_page_text_input_action(
					AhJwtAuthSettings::ISSUER,
					'text',
					__( 'Enter the expected iss claim value.', 'ah-jwt-auth' ),
					__( 'If set, incoming JWTs must include a matching iss claim. Leave empty to disable issuer validation.', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			AhJwtAuthSettings::AUDIENCE,
			'JWT Audience',
			function () {
				$this->options_page_text_input_action(
					AhJwtAuthSettings::AUDIENCE,
					'text',
					__( 'Enter the expected aud claim value.', 'ah-jwt-auth' ),
					__( 'If set, incoming JWTs must include a matching aud claim. Leave empty to disable audience validation.', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			AhJwtAuthSettings::USER_ROLE,
			'Default User Role',
			function () {
				$this->options_page_select_input_action(
					AhJwtAuthSettings::USER_ROLE,
					__( 'Select the role for an auto-created user if a role claim is not found in the JWT.', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			AhJwtAuthSettings::DISABLE_USER_CREATION,
			'Automatic User Creation',
			function () {
				$this->options_page_checkbox_input_action(
					AhJwtAuthSettings::DISABLE_USER_CREATION,
					__( 'Disable automatic user creation', 'ah-jwt-auth' ),
					__( 'Require users to be manually provisioned before they can sign in with a valid JWT.', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);

		add_settings_field(
			AhJwtAuthSettings::FAIL_CLOSED,
			'Enforce Strict Auth (Fail-Closed)',
			function () {
				$this->options_page_checkbox_input_action(
					AhJwtAuthSettings::FAIL_CLOSED,
					__( 'Enable strict Fail-Closed mode', 'ah-jwt-auth' ),
					__( 'Require a valid JWT for all unauthenticated traffic. If a token is invalid, expired, or entirely missing, block access immediately.', 'ah-jwt-auth' ),
				);
			},
			'ahjwtauth-sign-in-widget',
			'ahjwtauth-sign-in-widget-options-section',
		);
	}
}
