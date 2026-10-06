# mqtt-admin

Broker administration API behind `mw-bff`. It validates MW Identity delegated tokens and manages MQTT **clients** through Mosquitto's Dynamic Security plugin. It never exposes the broker's access model: roles are read-only and only roles in `MQTT_ALLOWED_ROLES` (default `nmnw`) can be assigned.

```text
browser -> mw-bff (/api/mqtt/*) -> mqtt-admin -> Dynamic Security ($CONTROL over mqtts) -> mosquitto
```

## Security model

- Every `/admin/api/*` route needs `Authorization: Bearer <delegated token>`. The token is validated by authenticated introspection (`POST {MW_IDENTITY_INTERNAL_BASE_URL}/oauth/introspect` with this service's own Identity client). It must be active, have a subject, include audience `mw-mqtt`, and carry the route's scope. Introspection failures deny the request.
- Step-up (fresh WebAuthn) is enforced by `mw-bff`, as for the other services.
- The service connects to the broker as its own user `mqtt-admin-api` with role `dynsec-admin` (only `$CONTROL/dynamic-security/#` access), never as the bootstrap `mqtt-admin`. The broker certificate is verified against the NM Root CA; `MQTT_TLS_SERVER_NAME` is checked even though the service dials `mqtt:8883` internally.
- `mqtt-admin` and the service's own user are protected: they cannot be disabled, rotated or deleted through the API.
- Passwords: when omitted the service generates one (24 random bytes, base64url) and returns it **once** in the response (`Cache-Control: no-store`). Supplied passwords must be 24-128 characters. Passwords are never logged and never echoed back when supplied by the caller.
- Every change is logged as a JSON `audit` line (actor = Identity `sub`, action, target, result).

## Routes and scopes

| Method and path | Scope | Notes |
|---|---|---|
| `GET /health` | none | liveness |
| `GET /ready` | none | 503 until the broker connection is up |
| `GET /admin/api/server` | `mqtt.server.read` | broker connection, Dynamic Security reachability, client count |
| `GET /admin/api/roles` | `mqtt.roles.read` | roles with ACLs, plus `assignable` |
| `GET /admin/api/clients` | `mqtt.clients.read` | `{clients:[{username,disabled,roles}]}` |
| `GET /admin/api/clients/{username}` | `mqtt.clients.read` | |
| `POST /admin/api/clients` | `mqtt.clients.write` | `{username, role?, password?}`, 201, generated password returned once |
| `POST /admin/api/clients/{username}/disable` | `mqtt.clients.write` | 204 |
| `POST /admin/api/clients/{username}/enable` | `mqtt.clients.write` | 204 |
| `POST /admin/api/clients/{username}/password` | `mqtt.credentials.rotate` | optional `{password}`, otherwise generated and returned once |
| `DELETE /admin/api/clients/{username}` | `mqtt.clients.delete` | 204 |

Errors are `{"error":"<code>"}`: `unauthorized` (401), `forbidden` (403), `protected_user` (403), `invalid_username`/`invalid_password`/`invalid_body`/`role_not_allowed` (400), `not_found` (404), `already_exists` (409), `broker_unavailable` (503). Unmapped routes return 404/405 and never reach the broker.

Usernames match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`.

## Configuration

See [../secrets/admin-api.env.example](../secrets/admin-api.env.example). `MQTT_ROOT_CA_B64` is shared with the broker's `secrets/root-ca.env`.

The service exits with a clear log line when required configuration is missing and Compose keeps restarting it, so it is dormant until `secrets/admin-api.env` exists.

## Onboarding

1. **Broker user.** In the `mqtt` container terminal:
   ```sh
   sh /stackport-scripts/setup-roles.sh
   sh /stackport-scripts/provision-client.sh mqtt-admin-api dynsec-admin
   ```
2. **Identity application.** Register a confidential resource application in MW Identity with `client_id=mw-mqtt` and `audience=mw-mqtt` (if the registry needs `openid` metadata, keep it out of the delegated scopes). Save the one-time secret.
3. **Stackport env file.** Create `secrets/admin-api.env` from the example: the `mqtt-admin-api` password, the Identity base URL and the issued secret.
4. **Deploy** the project. `mqtt-admin` should become healthy and `GET /ready` should return 200.
5. **Domain.** In Stackport add an HTTP domain, for example `mqtt-admin.mattediworks.com`, service `mqtt-admin`, container port `8090`, SSL on, health-check path `/health`. This is how mw-bff reaches the other downstream services as well.
6. **mw-bff.** Add `mw-mqtt` to the BFF application's allowed audiences and these scopes to its allowed and delegated scopes (`BFF_DELEGATION_SCOPES`): `mqtt.clients.read`, `mqtt.clients.write`, `mqtt.clients.delete`, `mqtt.credentials.rotate`, `mqtt.roles.read`, `mqtt.server.read`. Add an explicit `/mqtt/*` facade for the routes above (mark create, rotate and delete as step-up), following the BFF guide's "Adding a new service".

## Development

```sh
cd admin
go test ./...
```
