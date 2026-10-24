# AH JWT Auth

## Introduction

This plugin will validate incoming requests that contain a JWT in a configurable HTTP header in order to log into WordPress.

This plugin assumes that it can retrieve a valid JWT from a configured HTTP header (the default is the `Authorization` header), so all requests should come from a reverse proxy than enforces authentication/access.

## How it works

* The plugin retrieves the user id (email) from the JWT and then checks if such
  a user exists. If not, the plugin creates a new user by using this email and
  signs them in, unless automatic user creation has been disabled in the plugin
  settings.
* If a `role` claim is included in the JWT this will be assigned to the user.
* If a JWT audience and/or issuer is configured in the plugin settings, the JWT
  must include a matching `aud` and/or `iss` claim.
* The plugin expects the JWT is passed as a HTTP header (default is
  `Authorization`). For example, the payload of JWT may look like:  

```json
{
  "email": "admin@example.com",
  "aud": "example-oauth-client-id",
  "iss": "example.com",
  "role": "admin"
}
```

### User Creation

Users are created with a random password (64 characters long), which
effectively means access via JWT is the only possible option for those
users unless an admin resets the password to a known value.

During the creation process the user is assigned the configured default role
or the role from the "role" claim in the JWT (if present).

In addition the SSO process will set an existing users role to match the "role"
claim in the JWT if it was present.

Automatic user creation can be disabled in the plugin settings. When disabled,
a valid JWT only signs in users that already exist in WordPress.

### Fail Closed Authentication

The plugin supports a "fail-closed" option which when enabled will actively
block access to WordPress if a valid JWT is not found.

This option is disabled by default and should be enabled with caution as this
could easily block access to your site if an issue prevents a valid JWT from
being added to the request or prevents verification of the JWT such as time
skew or token/key/JWKS mismatches/expiry.

## Releasing

1. In GitHub Actions, run **Prepare release** on `main` and pick `patch`,
   `minor` or `major`. It pushes a `release/X.Y.Z` branch that bumps the
   `Version:` header and `Stable tag`, sets "Tested up to" to the current
   WordPress version, and drafts a changelog entry from the PRs merged since
   the last release.
2. Open the PR from the link in the workflow summary. Rewrite the changelog
   entry in `readme.txt` for users, and revert "Tested up to" if you have not
   tested with that WordPress version.
3. Merge the PR. The **Release** workflow runs the tests, deploys to
   WordPress.org, creates the tag and GitHub release from the changelog entry,
   and attaches the SBOM.

To update the readme or plugin assets on WordPress.org between releases (for
example a "Tested up to" bump), run **Sync readme**, which pushes `main`'s
`readme.txt` and `.wordpress-org` assets only.

## Credits

This plugin uses code originally from [https://github.com/datawiza-inc/wordpress-proxy-auth-plugin](https://github.com/datawiza-inc/wordpress-proxy-auth-plugin) with modifications to add more features and to make things more generic so they are usable with any provider/proxy that adds the JWT as a HTTP Header.
