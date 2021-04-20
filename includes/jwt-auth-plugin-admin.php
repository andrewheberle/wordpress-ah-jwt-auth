<?php
namespace JwtAuth;

class JwtAuthAdmin
{
  public function __construct(){
    add_action('admin_init', array($this, 'registerSettingsAction'));

    add_action('admin_menu', array($this, 'optionsMenuAction'));
  }

  public function optionsMenuAction() {
    add_options_page(
        'JWT Auth Options',
        'JWT Auth',
        'manage_options',
        'jwtauth-sign-in-widget',
        array($this, 'optionsPageAction')
    );
  }

  public function optionsPageAction() {
    if (current_user_can('manage_options'))  {
        include(plugin_dir_path(__FILE__)."../templates/options-form.php");
    } else {
        wp_die( 'You do not have sufficient permissions to access this page.' );
    }
  }

  public function optionsPageTextInputAction($option_name, $type, $placeholder=false, $description=false) {
    $option_value = get_option($option_name, '');
    printf(
        '<input type="%s" id="%s" name="%s" value="%s" style="width: 100%%" autocomplete="off" placeholder="%s" />',
        esc_attr($type),
        esc_attr($option_name),
        esc_attr($option_name),
        esc_attr($option_value),
        esc_attr($placeholder)
    );
    if($description)
        echo '<p class="description">'.$description.'</p>';
  }

  public function registerSettingsAction() {
    add_settings_section(
      'jwtauth-sign-in-widget-options-section',
      '',
      null,
      'jwtauth-sign-in-widget'
    );
    
    register_setting('jwtauth-sign-in-widget', 'jwtauth-private-secret', array(
      'type' => 'string',
      'show_in_rest' => false,
    ));

    register_setting('jwtauth-sign-in-widget', 'jwtauth-jwks-url', array(
      'type' => 'string',
      'show_in_rest' => true,
    ));

    register_setting('jwtauth-sign-in-widget', 'jwtauth-jwt-header', array(
      'type' => 'string',
      'show_in_rest' => true,
      'default' => 'Authorization',
    ));

    add_settings_field(
        'jwtauth-private-secret',
        'JWT Private Secret',
        function() { $this->optionsPageTextInputAction('jwtauth-private-secret', 'text', 'Copy paste your JWT\'s private secret here. ', 'It is used for verifying the token (use this field or the "JWKS URL", not both).'); },
        'jwtauth-sign-in-widget',
        'jwtauth-sign-in-widget-options-section'
    );

    add_settings_field(
      'jwtauth-jwks-url',
      'JWKS URL',
      function() { $this->optionsPageTextInputAction('jwtauth-jwks-url', 'text', 'Enter the JWKS URL to validate the JWT.', 'It is used for verifying the token (use this field or the "JWT Private Secret", not both)'); },
      'jwtauth-sign-in-widget',
      'jwtauth-sign-in-widget-options-section'
    );

    add_settings_field(
      'jwtauth-jwt-header',
      'JWT Header',
      function() { $this->optionsPageTextInputAction('jwtauth-jwt-header', 'text', 'Enter the header that contains the JWT.', 'It is used to retrieve the JWT. The default is "Authorization".'); },
      'jwtauth-sign-in-widget',
      'jwtauth-sign-in-widget-options-section'
    );
  }
}
