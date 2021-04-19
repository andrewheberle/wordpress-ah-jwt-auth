<?php
namespace Jwtauth;

/**
 * Plugin Name: JWT Auth Plugin
 * Description: The plugin authenticates the user in Wordpress and set him/her role via JWT.
 * Version: 1.0.0
 * Author: Andrew Heberle
 * Author URI: https://gitlab.com/andrewheberle/wp-jwt-auth-plugin/
 * License: Apache License, Version 2.0
 * License URI: http://directory.fsf.org/wiki/License:Apache2.0
 */

require 'vendor/autoload.php';
require 'includes/jwt-auth-admin.php';

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\JWK;

class JwtAuthSignIn {
    public function __construct() {
        $this->JwtAuthAdmin = new JwtAuthAdmin();

        add_action('admin_notices', array($this, 'jwtauth_admin_notice_error'));
        add_action('init', array($this, 'logUserInWordpress'));
    }

    public function logUserInWordpress() {
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
            $this->error = 'JWT Auth Plugin expects email attribute to identify user, but it does not exist in the JWT. Please check your reverse proxy configuration';
            return;
        }
        $email = $payload->email;

        // If the user has logged in
        $current_user_id = wp_get_current_user()->ID;
        if ($current_user_id) {
            return;
        }

        $user = get_user_by('email', $email);

        if (!$user) {
            $random_password = wp_generate_password($length = 64, $include_standard_special_chars = false);
            $user_id = wp_create_user($email, $random_password, $email);
            $user = get_user_by('id', $user_id);
        }
        // If we can extract the user's role from header, then set the role
        // Otherwise set it to default role: subscriber
        if (isset($payload->role)) {
            $user->set_role(strtolower($payload->role));
        }

        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);
        do_action('wp_login', $user->login, $user);
        wp_safe_redirect(isset($_GET['redirect_to']) ? $_GET['redirect_to'] : home_url());
        exit;
    }

    public function jwtauth_admin_notice_error() {
        $class = 'notice notice-error';
        if (isset($this->error)) {
            $message = $this->error;
            printf('<div class="%1$s"><p>%2$s</p></div>', esc_attr($class), esc_html($message));
        }
    }

    private function getToken() {
        $jwtHeader = $this->getHeader();
        if (!isset($_SERVER[$jwtHeader])) {
            $this->error = 'Proxy Auth Plugin is enabled, but it does not receive the expected JWT. Please double check your reverse proxy configuration';
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
            $this->error = 'JWT Auth Plugin cannot verify the JWT. Please double check if your private secret or JWKS URL is configured correctly';
            return false;
        } catch (Exception $e) {
            return false;
        }
        return $payload;
    }

    private function getKey() {
        $jwksUrl = get_option('jwtauth-jwks-url');
        if ($jwksUrl !== "") {
            try {
                $jwks = json_decode(file_get_contents($jwksUrl), true);
                $key = JWK::parseKeySet($jwks);
            } catch (Exception $e) {
                $this->error = $e->getMessage();
                return false;
            }
        } else {
          $key = get_option('jwtauth-private-secret');
        }

        return $key;
    }

    private function getHeader() {
        // returns a header in "HTTP" form into a form usable with $_SERVER['HEADER']
        // by converting to uppercase, replaces "-" with "_" and prefixes with "HTTP_"
        return 'HTTP_' . str_replace("-", "_", strtoupper(get_option('datawiza-jwt-header')));
    }
}

$jwtAuth = new JwtAuthSignIn();