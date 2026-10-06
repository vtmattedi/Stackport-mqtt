# MQTT for StackPort

Production-oriented, TLS-only Eclipse Mosquitto for:

```text
mqtts://mqtt.mattediworks.com:8883
```

This is a normal managed StackPort project. Its Compose file never publishes a host port. StackPort owns public TCP `8883`; Mosquitto owns TLS termination, authentication, and deny-by-default authorization.

## What StackPort does

- Writes four project env files containing the broker bootstrap inputs.
- Deploys `mqtt-init` and `mqtt` from `docker-compose.yml`.
- Persists broker state in `mqtt-data` and leaf TLS material in `mqtt-certs`.
- Attaches `mqtt` to `stackport-proxy` when the TCP exposure is created.
- Publishes `8883 → mqtt:8883` through a StackPort-owned TCP proxy.
- Provides the container terminal used for client/role administration.

StackPort does not create the private PKI. The Root and MQTT Intermediate private keys remain on the secured offline administration system.

## Before onboarding

Create the following outside StackPort:

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
- HTTP domains: none

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

Do not add a Compose `ports:` entry. Do not add an HTTP domain for the broker.

### 5. Configure DNS

Create an IPv4 `A` record:

```text
mqtt.mattediworks.com → <StackPort VPS public IPv4>
```

Add `AAAA` only after IPv6 has been intentionally tested end-to-end.

## Initialize device access from the StackPort terminal

Open the project’s running `mqtt` container in StackPort’s Terminal control.

Inspect the deny defaults, clients, and roles:

```sh
sh /stackport-scripts/show-security-state.sh
```

Create a device with a unique password and device-specific role:

```sh
sh /stackport-scripts/provision-device.sh esp32-nm-6ca172e0
```

Default grants for that command are:

```text
publish:   devices/esp32-nm-6ca172e0/events/#
subscribe: devices/esp32-nm-6ca172e0/commands/#
receive:   devices/esp32-nm-6ca172e0/commands/#
```

Override both filters when the final NM-NW topic ontology differs:

```sh
sh /stackport-scripts/provision-device.sh \
  esp32-nm-6ca172e0 \
  'nm/devices/esp32-nm-6ca172e0/events/#' \
  'nm/devices/esp32-nm-6ca172e0/commands/#'
```

The scripts prompt without echo for both admin and device passwords. Passwords are not printed.

Useful direct administration commands from the same terminal follow this pattern:

```sh
mosquitto_ctrl -h localhost -p 8883 \
  --cafile /mosquitto/certs/nm-root-ca.crt --insecure \
  -u mqtt-admin dynsec help
```

Use the interactive password prompt when offered. Relevant operations include `disableClient`, `enableClient`, `setClientPassword`, `deleteClient`, `getClient`, and `getRole`.

## External validation

Run TLS/hostname verification and confirm anonymous access is rejected:

```sh
sh scripts/verify-tls.sh \
  mqtt.mattediworks.com 8883 /secure/path/nm-root-ca.crt
```

Run an authenticated publish/subscribe round trip:

```sh
sh scripts/smoke-test.sh \
  esp32-nm-6ca172e0 \
  devices/esp32-nm-6ca172e0/events/smoke \
  /secure/path/nm-root-ca.crt
```

Also verify:

- TCP `8883` is reachable.
- TCP `1883` is not reachable.
- Invalid passwords and disabled clients fail.
- Publishing or subscribing outside a device role fails.
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
