=== AH JWT Auth ===
Contributors: andrewheberle
Donate link: https://paypal.me/andrewheberle
Tags: jwt, sso, login, auth, authentication
Requires at least: 4.7
Tested up to: 5.7.1
Stable tag: 1.0.3
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

If the JWT did not contain a role claim then user is created with the default subscriber role.

== Frequently Asked Questions ==

= What header is the JWT retrieved from? =

By default the plugin looks for the JWT in the `Authorization` header as follows:

  Authorization: Bearer <JWT Here>

However the token may be retrieved from a configirable HTTP header, for example integration with Cloudflare Access would use
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

= 1.0.2 =
* Added internationalisation for strings
* Changes based on WordPress.org plugin submission feedback

= 1.0.1 =
* Added more error checking

= 1.0.0 =
* First version (not released on WordPress.org).

== Upgrade Notice ==

= 1.0.2 =
Internationalisation for strings

= 1.0.1 =
Better handling or errors.
