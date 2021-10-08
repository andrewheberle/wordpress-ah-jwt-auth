<?php
namespace AhJwtAuth;

/**
 * Plugin Name: AH JWT Auth
 * Description: This plugin allows sign in to WordPress using a JSON Web Token (JWT) contained in a HTTP Header
 * Version: 1.3.0
 * Author: Andrew Heberle
 * Text Domain: ah-jwt-auth
 * Author URI: https://gitlab.com/andrewheberle/ah-jwt-auth/
 * License: GPL v3 or later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 */

require 'vendor/autoload.php';
require 'includes/ah-jwt-auth-admin.php';

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\JWK;

class AhJwtAuthSignIn {
    public function __construct() {
        $this->AhJwtAuthAdmin = new AhJwtAuthAdmin();

        add_action('admin_notices', array($this, 'ahjwtauth_admin_notice'));
        add_action('init', array($this, 'ahjwtauth_log_user_in'));
    }

    public function ahjwtauth_log_user_in() {
        // if user is already logged in just return immediately
        if (is_user_logged_in()) {
            return;
        }

        // get jwt
        $jwt = $this->getToken();
        if ($jwt === false) {
            return;
        }

        // verify JWT and grab payload
        $payload = $this->verifyToken($jwt);
        if ($payload === false) {
            return;
        }

        // If we cannot extract the user's email from header
        if (!isset($payload->email)) {
            $this->error = __('AH JWT Auth expects email attribute to identify user, but it does not exist in the JWT. Please check your reverse proxy configuration', 'ah-jwt-auth');
            return;
        }
        $email = $payload->email;

        $user = get_user_by('email', $email);

        if (!$user) {
            $random_password = wp_generate_password($length = 64, $include_standard_special_chars = false);
            $user_id = wp_create_user($email, $random_password, $email);
            $user = get_user_by('id', $user_id);

            // set role on creation to configured default if not included in jwt
            if (!isset($payload->role)) {
              $user->set_role(get_option('ahjwtauth-user-role', 'subscriber'));
            }
        }

        // If we can extract the user's role from the JWT, then set the role, otherwise leave as-is
        if (isset($payload->role)) {
            $user->set_role(strtolower($payload->role));
        }

        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);
        do_action('wp_login', $user->login, $user);

        // redirect after login
        $redirectUrl = home_url();
        if (current_user_can('manage_options')) {
            $redirectUrl = admin_url();
        }
        wp_safe_redirect(isset($_GET['redirect_to']) ? $_GET['redirect_to'] : $redirectUrl);
        exit;
    }

    public function ahjwtauth_admin_notice() {
        if (isset($this->error)) {
            $class = 'notice notice-error';
            $message = $this->error;
            printf('<div class="%1$s"><p>%2$s</p></div>', esc_attr($class), esc_html($message));
        }

        if (isset($this->warning)) {
            $class = 'notice notice-warning is-dismissible';
            $message = $this->warning;
            printf('<div class="%1$s"><p>%2$s</p></div>', esc_attr($class), esc_html($message));
        }
    }

    private function getToken() {
        $jwtHeader = $this->getHeader();
        if (!isset($_SERVER[$jwtHeader])) {
            $this->warning = __('AH JWT Auth is enabled, but the expected JWT was not found. Please double check your reverse proxy configuration', 'ah-jwt-auth');
            return false;
        }

        // handle "Header: Bearer <JWT>" form
        $array = explode(" ", $_SERVER[$jwtHeader]);
        if ($array[0] == "Bearer") {
            array_shift($array);
        }

        return implode(" ", $array);
    }

    private function verifyToken($jwt) {
        $key = $this->getKey();
        if ($key === false) {
            return false;
        }
        try {
            $payload = JWT::decode($jwt, $key, array('RS256', 'HS256'));
        } catch (SignatureInvalidException $e) {
            $this->error = __('AH JWT Auth cannot verify the JWT. Please double check that your private secret or JWKS URL is configured correctly', 'ah-jwt-auth');
            return false;
        } catch (Exception $e) {
            return false;
        }
        return $payload;
    }

    private function getKey() {
        $jwksUrl = get_option('ahjwtauth-jwks-url');
        if ($jwksUrl !== "") {
            // retrieve json from JWKS URL with caching
            $json = get_transient('ahjwtauth_jwks_json');
 
            // if transient did not exist, attempt to get url
            if ($json === false) {
                $response = wp_remote_get($jwksUrl);
                if (is_wp_error($response)) {
                    $this->error = __('AH JWT Auth: error retrieving the JWKS URL: ' . $response->get_error_message(), 'ah-jwt-auth');
                    return false;
                }

                $json = wp_remote_retrieve_body($response);
            }
            if ($json == '') {
                $this->error = __('AH JWT Auth could not retrieve the specified JWKS URL', 'ah-jwt-auth');
                return false;
            }
            // try to decode json
            $jwks = @json_decode($json, true);
            if ($jwks === null) {
                $this->error = __('AH JWT Auth cannot decode the JSON retrieved from the JWKS URL', 'ah-jwt-auth');
                return false;
            }
            // cache json for future
            set_transient('ahjwtauth_jwks_json', $json, 60 * 240 );

            // parse the JWKS response
            try {
                $key = JWK::parseKeySet($jwks);
            } catch (Exception $e) {
                $this->error = $e->getMessage();
                return false;
            }
        } else {
            // otherwise use shared secret
            $key = get_option('ahjwtauth-private-secret');
        }

        return $key;
    }

    private function getHeader() {
        // returns a header in "HTTP" form into a form usable with $_SERVER['HEADER']
        // by converting to uppercase, replaces "-" with "_" and prefixes with "HTTP_"
        return 'HTTP_' . str_replace("-", "_", strtoupper(get_option('ahjwtauth-jwt-header')));
    }
}

$ahJwtAuth = new AhJwtAuthSignIn();