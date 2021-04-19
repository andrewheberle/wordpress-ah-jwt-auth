# JWT Auth Plugin

## Introduction

This plugin will validate incoming requests that contain a JWT in a configurable HTTP header in order to log into Wordpress.

This plugin assumes that it can retrieve a valid JWT from a configured HTTP header (the default is the `Authorization` header), so all requests should come from a reverse proxy than enforces authentication/access.

## How it works

* The plugin retrieves the user id (email) from the JWT and then checks if such a user exists. If not, the plugin creates a new user by using this email and signs him/her in.
* If a `role` claim is included in the JWT this will be assigned to the user.
* The plugin expects the JWT including user id as a HTTP header. For example, the payload of JWT may look like:  

```json
{
  "email": "admin@yourwebsite.com",
  "role": "admin"
}
```
