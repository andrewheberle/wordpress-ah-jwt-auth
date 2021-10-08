# AH JWT Auth

## Introduction

This plugin will validate incoming requests that contain a JWT in a configurable HTTP header in order to log into WordPress.

This plugin assumes that it can retrieve a valid JWT from a configured HTTP header (the default is the `Authorization` header), so all requests should come from a reverse proxy than enforces authentication/access.

## How it works

* The plugin retrieves the user id (email) from the JWT and then checks if such a user exists. If not, the plugin creates a new user by using this email and signs him/her in.
* If a `role` claim is included in the JWT this will be assigned to the user.
* The plugin expects the JWT is passed as a HTTP header (default is `Authorization`). For example, the payload of JWT may look like:  

```json
{
  "email": "admin@example.com",
  "role": "admin"
}
```

### User Creation

Users are created with a random password (64 characters long), which effectively means access only via SSO is possible.

During the creation process the user is assigned the configured default role or the role from the "role" claim in the JWT if it was included.

In addition the SSO process will set an existing users role to match the "role" claim in the JWT if it was present.

## Credits

This plugin uses code originally from (https://github.com/datawiza-inc/wordpress-proxy-auth-plugin)[https://github.com/datawiza-inc/wordpress-proxy-auth-plugin] with modifications to add more features and to make things more generic so they are usable with any provider/proxy that adds the JWT as a HTTP Header.