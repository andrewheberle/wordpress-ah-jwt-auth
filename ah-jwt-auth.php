<?php
/**
 * AH JWT Auth
 *
 * @package AhJwtAuth
 * @author Andrew Heberle
 * @copyright 2026 Andrew Heberle
 * @license GPL v3 or later
 *
 * @wordpress-plugin
 * Plugin Name: AH JWT Auth
 * Description: This plugin allows sign in to WordPress using a JSON Web Token (JWT) contained in a HTTP Header
 * Version: 2.2.0
 * Author: Andrew Heberle
 * Text Domain: ah-jwt-auth
 * Author URI: https://github.com/andrewheberle/wordpress-ah-jwt-auth/
 * License: GPL v3 or later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 *
 * Copyright (C) 2021-2026  Andrew Heberle
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

namespace AhJwtAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once plugin_dir_path( __FILE__ ) . 'vendor/autoload.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-ahjwtauthsignin.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-ahjwtauthadmin.php';

register_deactivation_hook( __FILE__, function () {
    $timestamp = wp_next_scheduled( 'ahjwtauth_fetch_jwks' );
    if ( $timestamp ) {
        wp_unschedule_event( $timestamp, 'ahjwtauth_fetch_jwks' );
    }
} );

new AhJwtAuthSignIn();
