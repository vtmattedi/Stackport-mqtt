# PKI boundary

This repository intentionally does not generate or store CA private keys.

Keep these outside the repository on a secured administrative/offline system:

- `nm-root-ca.key`
- `nm-mqtt-intermediate.key`

The public `nm-root-ca.crt` is distributed to NM-NW firmware. For StackPort deployment, the public root, broker leaf key, and leaf-plus-intermediate full chain are base64-encoded into the separate StackPort-managed env files documented in the root README.

The broker certificate must contain `DNS:mqtt.mattediworks.com` in its Subject Alternative Name. Add `DNS:mqtt` only if trusted internal clients must connect by the Compose service name.
