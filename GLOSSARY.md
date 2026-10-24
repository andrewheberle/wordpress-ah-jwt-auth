# AH JWT Auth

Signs visitors into WordPress using a JSON Web Token that an upstream proxy or identity provider places in an HTTP header.

## Language

**Plugin data**:
The configuration the plugin stores for itself on a site: its settings and its own bookkeeping. Removed when the plugin is uninstalled.
_Avoid_: plugin settings (only part of it), user data

**Provisioned user**:
A WordPress account the plugin created from a JWT. Once created it is site data, owned by the site rather than the plugin, and outlives the plugin.
_Avoid_: JWT user, auto-created user
