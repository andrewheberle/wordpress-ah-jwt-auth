<?php
/*
Plugin Name: Storage
Description: A library for storing data in a WordPress context
Plugin URI: https://italystrap.com
Author: Enea Overclokk
Author URI: https://italystrap.com
Version: 1.0.0
License: MIT
*/

require __DIR__ . '/vendor/autoload.php';

/**
 * @see \get_option()
 * @see \add_option()
 * @see \update_option()
 * @see \delete_option()
 *
 * @see \get_theme_mod()
 * @see \set_theme_mod()
 * @see \update_theme_mod()
 * @see \remove_theme_mod()
 *
 * @see \get_site_option()
 * @see \add_site_option()
 * @see \update_site_option()
 * @see \delete_site_option()
 *
 * @see \get_network_option()
 * @see \add_network_option()
 * @see \update_network_option()
 * @see \delete_network_option()
 *
 * @see \get_transient()
 * @see \set_transient()
 * @see \delete_transient()
 *
 * @see \get_site_transient()
 * @see \set_site_transient()
 * @see \delete_site_transient()
 *
 * @see \wp_cache_add()
 * @see \wp_cache_get()
 * @see \wp_cache_set()
 * @see \wp_cache_delete()
 * @see \wp_cache_flush()
 *
 * @see \wp_cache_replace()
 * @see \wp_cache_get_multiple()
 * @see \wp_cache_set_multiple()
 * @see \wp_cache_delete_multiple()
 * @see \wp_cache_incr()
 * @see \wp_cache_decr()
 */
