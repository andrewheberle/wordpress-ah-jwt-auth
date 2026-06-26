=== AH JWT Auth ===
Contributors: andrewheberle
Donate link: https://paypal.me/andrewheberle
Tags: jwt, sso, login, auth, authentication
Requires at least: 4.7
Tested up to: 6.9.4
Stable tag: 2.1.0
Requires PHP: 8.0
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

This plugin allows sign in to WordPress using a JSON Web Token (JWT) contained
in a HTTP Header.

== Description ==

This plugin allows sign in to WordPress using a JSON Web Token (JWT) contained
in a HTTP Header that is added by a reverse proxy that sits in front of your
WordPress deployment.

Authentication and optionally role assignment is handled by claims contained in
the JWT.

If configured, the plugin also validates the JWT `aud` and `iss` claims against
the expected application audience and JWT issuer values.

Verification of the JWT is handled by either:

* a shared secret for HS256 (as per RFC 7518 this must be at least 256-bits in
  size)
* a PEM encoded public key for RS256
* retrieving a JSON Web Key Set (JWKS) from a configured URL (also for RS256)

During the login process if the user does not exist an account will be created
with a matching role from the JWT, unless automatic user creation has been
disabled in the plugin settings.

If the JWT did not contain a role claim then user is created with the role set
in the plugin settings (by default this is the subscriber role).

Automatic user creation is enabled by default for backwards compatibility. It
can be disabled when user provisioning should remain manual.

== Frequently Asked Questions ==

= What header is the JWT retrieved from? =

By default the plugin looks for the JWT in the `Authorization` header as
follows:

    Authorization: Bearer <JWT Here>

However the token may be retrieved from a configurable HTTP header, for example
to integrate with Cloudflare Access, which was the original target for this
plugin, you would configure the use of the `Cf-Access-Jwt-Assertion` header.

= What claims should the JWT contain? =

The JWT must contain at least an `email` claim and may also contain a `role` claim:

    {
        "iss": "example.com",
        "aud": "example-audience-id",
        "email": "admin@example.com",
        "iat": 1356999524,
        "nbf": 1357000000,
        "role": "admin"
    }

The `aud` and `iss` claims are only required when a JWT Audience and/or Issuer
value has been configured in the plugin settings, however as they are standard
JWT claims it is recommended to set these options to verify those claims exist
and are valid.

= What signature algorithms are supported to verify the JWT? =

Currently only the HS256 and RS256 algorithms are supported.

== Screenshots ==

1. This example shows a configuration with a WordPress install behind
   Cloudflare Access for SSO via JWT

== Changelog ==

= 2.3.0 =
* Replace JWKS caching process

= 2.2.0 =
* Spelling fixes and hardening
* Add option to enforce JWT auth (ie "fail-closed") rather than falling
  through to WordPress authentication.

= 2.1.0 =
* Add option to verify JWT issuer

= 2.0.0 =
* **Breaking Change:** Any secrets that are less than 256-bits (32-characters)
  in length will fail JWT HS256 verification

= 1.6.0 =
* Added option to verify JWT Audience (AUD)
* Added option to disable automatic user creation

= 1.5.4 =
* Fix bug that meant role was not being set based on selection

= 1.5.3 =
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
