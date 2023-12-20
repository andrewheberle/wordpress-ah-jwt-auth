=== AH JWT Auth ===
Contributors: andrewheberle
Donate link: https://paypal.me/andrewheberle
Tags: jwt, sso, login, auth, authentication
Requires at least: 4.7
Tested up to: 6.3.2
Stable tag: 1.5.2
Requires PHP: 7.0
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

This plugin allows sign in to WordPress using a JSON Web Token (JWT) contained in a HTTP Header.

== Description ==

This plugin allows sign in to WordPress using a JSON Web Token (JWT) contained in a HTTP Header that is added by a reverse proxy
that sits in front of your WordPress deployment.

Authentication and optionally role assignment is handled by claims contained in the JWT.

Verification of the JWT is handled by either:

* a shared secret key
* retrieving a JSON Web Key Set (JWKS) from a configured URL

During the login process if the user does not exist an account will be created with a matching role from the JWT.

If the JWT did not contain a role claim then user is created with the role set in the plugin settings (by default this is the subscriber role).

== Frequently Asked Questions ==

= What header is the JWT retrieved from? =

By default the plugin looks for the JWT in the `Authorization` header as follows:

    Authorization: Bearer <JWT Here>

However the token may be retrieved from a configurable HTTP header, for example integration with Cloudflare Access would use
the `Cf-Access-Jwt-Assertion` header.

= What should the JWT contain? =

The JWT must contain at least an `email` claim and may also contain a `role` claim:

    {
        "email": "admin@example.com",
        "role": "admin"
    }

= What signature algorimths are supported to verify the JWT? =

Currently only the HS256 and RS256 alorithms are supported.

== Screenshots ==

1. This example shows a configuration with a WordPress install behind Cloudflare Access for SSO via JWT

== Changelog ==

= 1.5.2 =
* Make JWKS refresh function public

= 1.5.1 =
* Fixes for JWKS refresh process

= 1.5.0 =
* Add WP cron job to refresh JWKS daily

= 1.4.1 =
* Update dependencies to resolve security issue

= 1.3.1 =
* Clean-ups and bug fixes

= 1.3.0 =
* Allow setting default role for auto-created users

= 1.2.2 =
* Version bump for plugin update on WordPress.org

= 1.2.1 =
* Version bump for plugin update on WordPress.org

= 1.2.0 =
* Fix a bug where an invalid JSON response from JWKS URL was cached leading to broken SSO 

= 1.1.0 =
* Make login process more efficient by skipping JWT verify/login if user is already authenticated 

= 1.0.3 =
* Initial release on WordPress.org

= 1.0.2 =
* Added internationalisation for strings
* Changes based on WordPress.org plugin submission feedback

= 1.0.1 =
* Added more error checking

= 1.0.0 =
* First version

== Upgrade Notice ==

= 1.0.3 =
Initial public release

= 1.0.2 =
Internationalisation for strings

= 1.0.1 =
Better handling or errors.
