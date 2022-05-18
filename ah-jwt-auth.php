<?php
/**
 * AH JWT Auth
 *
 * @package AhJwtAuth
 * @author Andrew Heberle
 * @copyright 2021 Andrew Heberle
 * @license GPL v3 or later
 *
 * @wordpress-plugin
 * Plugin Name: AH JWT Auth
 * Description: This plugin allows sign in to WordPress using a JSON Web Token (JWT) contained in a HTTP Header
 * Version: 1.4.0
 * Author: Andrew Heberle
 * Text Domain: ah-jwt-auth
 * Author URI: https://github.com/andrewheberle/wordpress-ah-jwt-auth/
 * License: GPL v3 or later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 */

namespace AhJwtAuth;

require 'vendor/autoload.php';
require 'includes/class-ahjwtauthsignin.php';
require 'includes/class-ahjwtauthadmin.php';

$ah_jwt_auth = new AhJwtAuthSignIn();
