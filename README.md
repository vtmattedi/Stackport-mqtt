# MQTT for StackPort

Production-oriented, TLS-only Eclipse Mosquitto for:

```text
mqtts://mqtt.mattediworks.com:8883
```

The hostnames in this guide (`mqtt.mattediworks.com`, `mqtt-ws.mattediworks.com`, `nm-root-ca.crt`) are one deployment's example values: replace them with yours.

This is a normal managed StackPort project. Its Compose file never publishes a host port. StackPort owns public TCP `8883`; Mosquitto owns TLS termination, authentication, and deny-by-default authorization.

## What StackPort does

- Writes four project env files containing the broker bootstrap inputs.
- Deploys `mqtt-init` and `mqtt` from `docker-compose.yml`.
- Persists broker state in `mqtt-data` and leaf TLS material in `mqtt-certs`.
- Attaches `mqtt` to `stackport-proxy` when the TCP exposure is created.
- Publishes `8883 → mqtt:8883` through a StackPort-owned TCP proxy.
- Routes an HTTPS domain (`mqtt-ws.mattediworks.com`) to the plain WebSocket listener `mqtt:9001` for browser clients; nginx terminates TLS with Let's Encrypt.
- Provides the container terminal used for client/role administration.

StackPort does not create the private PKI. The Root and MQTT Intermediate private keys remain on the secured offline administration system.

## Before onboarding

Create the following outside StackPort. `pki/pki.ps1` generates all of it, plus the four env files, using Docker (see [pki/README.md](pki/README.md)):

- `nm-root-ca.crt` — public Root CA certificate.
- `fullchain.pem` — `mqtt.mattediworks.com` leaf certificate followed by the MQTT Intermediate certificate.
- `privkey.pem` — broker leaf private key.

The leaf certificate must contain `DNS:mqtt.mattediworks.com` in its SAN. Never provide StackPort with `nm-root-ca.key` or `nm-mqtt-intermediate.key`.

Convert each required PEM file to one-line base64. These commands only encode existing material; they do not generate a new CA.

Linux/macOS:

```sh
base64 < nm-root-ca.crt | tr -d '\n'
base64 < fullchain.pem | tr -d '\n'
base64 < privkey.pem | tr -d '\n'
```

PowerShell:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('nm-root-ca.crt'))
[Convert]::ToBase64String([IO.File]::ReadAllBytes('fullchain.pem'))
[Convert]::ToBase64String([IO.File]::ReadAllBytes('privkey.pem'))
```

Generate a unique admin password of at least 32 characters with a cryptographically secure password generator.

## Initialize entirely through StackPort

### 1. Create and pull/upload the project

Use these project fields:

- Name: `MQTT`
- Compose file: `docker-compose.yml`
- Health-check interval: `0` (disabled; there is no HTTP endpoint)
- HTTP domains: none at first (the WebSocket domain is added in step 4b)

The Compose target detector should show `mqtt:8883`. The four env files below are marked optional at Compose-parse time so target discovery works before secrets are configured. Runtime initialization still fails closed if any value is missing.

### 2. Add four env files

In the project page’s Environment Files section, create these exact paths and variables. Put each base64 value on one line.

`secrets/admin.env`

```dotenv
MQTT_ADMIN_USERNAME=mqtt-admin
MQTT_ADMIN_PASSWORD=<random-secret-at-least-32-characters>
```

`secrets/root-ca.env`

```dotenv
MQTT_ROOT_CA_B64=<base64-of-public-nm-root-ca.crt>
```

`secrets/broker-cert.env`

```dotenv
MQTT_BROKER_FULLCHAIN_B64=<base64-of-fullchain.pem>
```

`secrets/broker-key.env`

```dotenv
MQTT_BROKER_PRIVATE_KEY_B64=<base64-of-broker-leaf-privkey.pem>
```

Splitting the material into separate files keeps each StackPort env-file request comfortably below the API request-size limit. StackPort writes them immediately before Compose actions.

### 3. Deploy

Run the normal StackPort deploy/recreate action. `mqtt-init` performs these steps automatically:

1. Requires all four env files and a 32+ character admin password.
2. Base64-decodes the public Root CA, broker full chain, and broker leaf key.
3. Validates their PEM headers and installs them with restrictive ownership/modes in `mqtt-certs`.
4. Creates `mqtt-data/dynamic-security.json` only when it does not already exist.
5. Creates the Dynamic Security administrator.
6. Changes every default ACL action to deny.
7. Starts `mqtt` only after initialization succeeds.

If a value is missing or malformed, `mqtt-init` exits non-zero and Mosquitto does not start. Inspect the `mqtt-init` logs from StackPort for the exact missing variable.

### 4. Add the public TCP exposure

On the same project page, add:

```text
Public port:    8883
Service:        mqtt
Container port: 8883
```

Do not add a Compose `ports:` entry. Port 8883 is the device listener only; the browser domain below is separate.

### 4b. Add the browser WebSocket domain (optional)

Browsers do not trust the private NM Root CA, so web clients connect through StackPort's nginx, which presents a Let's Encrypt certificate. On the project page add an HTTP domain:

```text
Domain:         mqtt-ws.mattediworks.com
Service:        mqtt
Container port: 9001
SSL:            on
```

Create an `A` record for `mqtt-ws.mattediworks.com` pointing at the StackPort VPS first. Leave the health-check path empty (the listener does not serve HTTP).

Paho JavaScript:

```js
const client = new Paho.Client("mqtt-ws.mattediworks.com", 443, "/mqtt", "web-" + crypto.randomUUID());
client.connect({ useSSL: true, userName: "web-client", password: "...", keepAliveInterval: 30 });
```

Notes:

- Authentication and ACLs are the same Dynamic Security clients and roles. An `nmnw` user can read and write everything, so create a separate user per web app and do not reuse a gateway or device credential in a browser. A read-only role for dashboards can be added later.
- Keep `keepAliveInterval` at 30s or less: nginx closes idle connections after its default 60s `proxy_read_timeout`. For longer keepalives set `proxy_read_timeout` in the domain's extra config.
- Port 9001 is plain WebSocket and exists only on the Docker network. It is not published to the host.

### 5. Configure DNS

Create an IPv4 `A` record:

```text
mqtt.mattediworks.com → <StackPort VPS public IPv4>
```

Add `AAAA` only after IPv6 has been intentionally tested end-to-end.

## Access model

Access is granted by Dynamic Security **roles**: lists of topic rules that you define for your own application, in the admin console or API (`admin/README.md`). Two accounts are special and are never given to applications:

- **`mqtt-admin`**: the broker's bootstrap administrator. Never use it from firmware or services.
- **`dynsec-admin`** (role, created by `setup-roles.sh`): used only by the admin API's own broker user. It allows the Dynamic Security channel (`$CONTROL`) and read-only `$SYS`.

`#` does not match `$`-prefixed topics, so a role with `#` never reaches `$CONTROL` or `$SYS`. Create one user per gateway, device or service for individual revocation, or share one; the role grants the access.

### Profiles

A profile is an optional, deployment-specific bundle: extra roles in `scripts/profiles/<name>.sh` and an extra section appended to the served documentation (`MQTT_DOCS_PROFILE`). The only one shipped is `nightmare`, for the NightMare Network: a single trusted role `nmnw` with publish, subscribe and receive on `#`, because its topics are global and device-rooted and per-device ACLs cannot work. A generic deployment ignores profiles.

## Initialize access from the StackPort terminal

Open the project's running `mqtt` container in StackPort's Terminal control. The scripts prompt for the admin username and password without echo.

Inspect the deny defaults, clients and roles:

```sh
sh /stackport-scripts/show-security-state.sh
```

Create the core role once (safe to repeat). Add a profile name to also create that profile's roles:

```sh
sh /stackport-scripts/setup-roles.sh              # core role only
sh /stackport-scripts/setup-roles.sh nightmare    # plus the nmnw role
```

Create a user (gateway, device or service) with a role. Use a unique random password of at least 24 characters. The role is required, either as the second argument or through `MQTT_DEFAULT_ROLE`:

```sh
sh /stackport-scripts/provision-client.sh gateway-aabbccddeeff my-role
```

Passwords are not printed. Clients connect with the host and port, the CA certificate, and the username and password you created.

Useful direct administration commands from the same terminal follow this pattern:

```sh
mosquitto_ctrl -h localhost -p 8883 \
  --cafile /mosquitto/certs/nm-root-ca.crt --insecure \
  -u mqtt-admin dynsec help
```

Relevant operations include `disableClient`, `enableClient`, `setClientPassword`, `deleteClient`, `getClient`, and `getRole`.

## Admin API

`mqtt-admin` (see [admin/README.md](admin/README.md)) is an HTTP API for creating, disabling, rotating and deleting MQTT users, plus broker statistics and its own documentation. It runs in this Compose project, connects with its own `dynsec-admin` user, and stays dormant until `secrets/admin-api.env` exists.

It has two authentication modes, chosen with `ADMIN_AUTH_MODE`:

- `token` (default): static bearer tokens you generate with `mqtt-admin token new`; only their hashes are configured. Use this to run the project on its own.
- `federated`: tokens issued by an identity provider with introspection. MattediWorks' control plane uses this mode.

The admin README has the token generation and configuration steps, the scopes, and what step-up (strong authentication) means in each mode. There is no UI in this project; call the API or build one on top of it.

## External validation

Run TLS/hostname verification and confirm anonymous access is rejected:

```sh
sh scripts/verify-tls.sh \
  mqtt.mattediworks.com 8883 /secure/path/nm-root-ca.crt
```

Run an authenticated publish/subscribe round trip with any `nmnw` user. From Windows PowerShell:

```powershell
.\scripts\smoke-test.ps1 -Username <user> -Topic smoke/ping -CaFile D:\pki-nm-2\nm-root-ca.crt
```

or `sh scripts/smoke-test.sh <user> smoke/ping <ca>` on Linux/macOS. Use a throwaway user and delete it afterwards:

```sh
mosquitto_ctrl -h localhost -p 8883 --cafile /mosquitto/certs/nm-root-ca.crt --insecure -u mqtt-admin dynsec deleteClient <user>
```

Also verify:

- TCP `8883` is reachable.
- `wss://mqtt-ws.mattediworks.com/mqtt` connects with valid credentials and is refused without them.
- TCP `9001` is not reachable from the internet.
- TCP `1883` is not reachable.
- Invalid passwords and disabled clients fail.
- An `nmnw` user cannot publish to `$CONTROL/#` or subscribe to `$SYS/#`.
- The certificate chains to the NM Root CA and hostname verification succeeds.

## Certificate rotation in StackPort

1. Issue a new broker leaf certificate from the offline MQTT Intermediate CA.
2. Replace `MQTT_BROKER_FULLCHAIN_B64` and `MQTT_BROKER_PRIVATE_KEY_B64` in their StackPort env files.
3. Recreate the project. `mqtt-init` atomically replaces the volume files before Mosquitto starts.
4. Rerun TLS and authenticated smoke tests.

NM-NW firmware remains unchanged because devices trust the stable Root CA, not the leaf certificate.

## Persistence and backup

- `mqtt-data`: broker persistence plus Dynamic Security clients, roles, ACLs, and password hashes.
- `mqtt-certs`: decoded public chain, broker leaf key, and public Root CA.

Future StackPort full backup should include both volumes, project source/configuration, the four env files, and TCP exposure metadata. It must never include Root or Intermediate CA private keys.
