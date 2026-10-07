# mqtt-admin

HTTP API for administering a Mosquitto broker's **clients** (users) and the **roles** that grant them access, through its Dynamic Security plugin. It runs next to the broker, authenticates callers with bearer tokens, and has two authentication modes so it works on its own or behind an identity provider.

```text
caller ──(Authorization: Bearer …)──> mqtt-admin ──($CONTROL over mqtts)──> mosquitto
```

There is no UI in this service. Call the API directly, or build a UI on top of it (the API is small and documented below). MattediWorks' own console is one such UI: it sits behind `mw-bff` and uses `federated` mode.

## Quick start (standalone)

1. **Broker user.** In the broker container terminal:
   ```sh
   sh /stackport-scripts/setup-roles.sh              # add a profile name (e.g. nightmare) for its extra roles
   sh /stackport-scripts/provision-client.sh mqtt-admin-api dynsec-admin
   ```
2. **Generate a token** (see [Tokens](#token-mode-default)):
   ```sh
   mqtt-admin token new --name ops --scopes write --expires 2027-01-31
   ```
3. **Create `secrets/admin-api.env`** with the broker user's password and the token entry the command printed:
   ```dotenv
   MQTT_API_PASSWORD=<password you gave mqtt-admin-api>
   MQTT_ADMIN_TOKENS=ops:<sha256>:write:2027-01-31
   ```
4. **Deploy** the project, then add a domain for service `mqtt-admin`, container port `8090`, health path `/health`.
5. **Call it:**
   ```sh
   curl -s -H "Authorization: Bearer $TOKEN" https://admin-mqtt.example.com/admin/api/clients
   ```

`ADMIN_AUTH_MODE` is `token` unless you set it. If no token is configured the service refuses to start and says how to create one.

## Authentication modes

Set `ADMIN_AUTH_MODE` in `secrets/admin-api.env`.

| Mode | Use it when | Tokens come from | Needs |
|---|---|---|---|
| `token` (default) | you run the service on its own | static tokens you generate; only their hashes are configured | `MQTT_ADMIN_TOKENS` |
| `federated` | you have an identity provider with token introspection, such as MW Identity | short-lived delegated tokens the provider issues per user and per action | `MW_IDENTITY_INTERNAL_BASE_URL`, `MW_IDENTITY_INTROSPECTION_CLIENT_SECRET` |

Everything else is identical in both modes: the routes, the scopes, the guardrails, the audit log and the rate limit. A mode that is not selected is not loaded: `token` mode never contacts an identity provider, and `federated` mode ignores `MQTT_ADMIN_TOKENS`.

### Token mode (default)

A token is 32 random bytes, shown **once** when generated. The configuration holds only its SHA-256 hash, so the environment file cannot be used to authenticate and a leaked config does not leak a credential.

**Generate** with the binary. It reads no configuration and never connects to the broker, so run it anywhere you have the binary, ideally your own machine so the token never passes through a browser terminal:

```sh
# from admin/ with Go installed
go run ./cmd/mqtt-admin token new --name ci --scopes read --expires 2027-01-31

# or with Docker (--no-deps stops Compose from starting the broker)
docker compose run --rm --no-deps mqtt-admin token new --name ci --scopes read --expires 2027-01-31
```

It prints the token and the configuration entry. Store the token in a password manager; it cannot be recovered. To use a token you already have (at least 32 characters), pipe it in: `printf %s "$TOKEN" | mqtt-admin token hash`.

**Generate without the binary** (all you need is a random token and its SHA-256):

```sh
TOKEN="mqa_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
echo "$TOKEN"                                    # store it; shown only now
printf %s "$TOKEN" | sha256sum | cut -d' ' -f1   # the hash for MQTT_ADMIN_TOKENS
```

```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$token = 'mqa_' + [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$token                                           # store it; shown only now
[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($token))).ToLower()
```

**Configure** by adding entries to `MQTT_ADMIN_TOKENS`, separated by `;` (or newlines):

```text
name:sha256hex:scopes[:expires]
```

```dotenv
MQTT_ADMIN_TOKENS=ci:3f2a…c91:read:2027-01-31;ops:9b1c…e04:write;breakglass:77de…a10:admin:2026-12-31
```

| Field | Rules |
|---|---|
| `name` | 1-64 characters of `a-z`, `0-9`, `.`, `_`, `-`. Unique. Appears in logs and the audit trail as `token:<name>`, so name tokens after the person or job |
| `sha256hex` | 64 hex characters: the hash of the token, **never the token itself** (the service rejects anything else) |
| `scopes` | scope names or presets joined with `+` |
| `expires` | optional. `YYYY-MM-DD` (valid through the end of that day, UTC) or an RFC 3339 time. Omit for no expiry |

**Scopes and presets**

| Preset | Grants |
|---|---|
| `read` | `mqtt.clients.read`, `mqtt.roles.read`, `mqtt.server.read` |
| `write` | `read` plus `mqtt.clients.write` and `mqtt.credentials.rotate` (create, enable, disable, new password). **No delete** |
| `admin` | everything: deleting clients, and creating, editing and deleting roles |

`mqtt.roles.write` (create roles, edit their rules, give or take roles from clients) and `mqtt.roles.delete` change who may do what, so they are **not part of `write`**: a token configured as `write` before roles could be edited does not gain that power. Grant them on purpose, for example `write+mqtt.roles.write`.

You can mix presets and single scopes: `read+mqtt.clients.delete`. `mqtt.server.read` also covers the statistics and the documentation routes.

**Use it** in the `Authorization` header:

```sh
curl -s -H "Authorization: Bearer $TOKEN" https://admin-mqtt.example.com/admin/api/clients

curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"gateway-1"}' https://admin-mqtt.example.com/admin/api/clients
# -> {"username":"gateway-1","role":"nmnw","password":"…"}   the password is shown once
```

**Rotate and revoke.** Tokens are read at startup, so a change takes effect when the service restarts (recreate the project in Stackport).
- *Rotate:* generate a new token under a new name, deploy, move the caller over, then delete the old entry and deploy again.
- *Revoke:* delete the entry and redeploy. Expired entries stop working on their own and are refused with a logged `token_expired`.

**Good practice**
- Give people the `read` preset. Keep `write` and `admin` tokens for few people or jobs, and put an `expires` date on anything that can change clients (the service logs a warning at startup for a changing token that never expires).
- One token per person or job, so the audit trail says who did what and a single token can be revoked.
- Treat the token like a password: password manager, not chat, not source control. Generated tokens start with `mqa_` so secret scanners can recognise them.

### Federated mode

Requests carry a short-lived delegated token issued by an identity provider. The service validates it by authenticated introspection (RFC 7662): `POST {MW_IDENTITY_INTERNAL_BASE_URL}/oauth/introspect` with its own client credentials. The token must be active, have a subject, include the audience `MW_IDENTITY_AUDIENCE` (default `mw-mqtt`), and carry the route's scope. Introspection failures deny the request.

```dotenv
ADMIN_AUTH_MODE=federated
MW_IDENTITY_INTERNAL_BASE_URL=https://identity.example.com
MW_IDENTITY_INTROSPECTION_CLIENT_SECRET=<issued secret>
# optional: MW_IDENTITY_INTROSPECTION_CLIENT_ID=mw-mqtt  MW_IDENTITY_AUDIENCE=mw-mqtt
```

The actor in the audit trail is the identity provider's `sub`. MattediWorks' setup, including the `mw-bff` facade and the scopes to register, is in the control plane repository's `docs/dev_docs/stackport-onboarding.md`, section 3b.

## Step-up (strong authentication)

Some actions are dangerous enough that a valid token should not be enough: issuing a credential, re-enabling a client, changing a password, deleting a client. The safeguard is "step-up": the person must have proved their identity again recently, for example with a passkey, before the action runs.

**`mqtt-admin` does not implement step-up itself, in either mode.** It checks who the caller is and what the caller may do, not how recently they authenticated. Step-up belongs to whatever sits in front of the API and talks to a human.

- **Federated mode, MattediWorks:** `mw-bff` implements it. The routes it treats as sensitive are exactly these, defined in `mw-bff/internal/httpapi/strong_auth.go` (`sensitiveMQTTRoute`):

  | Route | Step-up |
  |---|---|
  | `POST /clients` (create) | required |
  | `POST /clients/{username}/enable` | required |
  | `POST /clients/{username}/password` (new password) | required |
  | `POST /roles`, `DELETE /roles/{name}` | required |
  | `POST /roles/{name}/acls`, `POST /roles/{name}/acls/remove` | required |
  | `PUT` and `DELETE /clients/{username}/roles/{role}` | required |
  | `DELETE /clients/{username}` | required |
  | `POST /clients/{username}/disable` | **not** required: it only removes access, so it stays a fast kill switch |
  | every `GET` | not required |

  Before forwarding a sensitive route, the BFF checks that the session's last passkey (WebAuthn) login is no older than `BFF_STRONG_AUTH_MAX_AGE_MINUTES` (default 5). If it is, the request goes through. If not, the BFF answers `403 {"error":{"code":"step_up_required","step_up_url":"/api/auth/step-up"}}` and does not forward anything. The console saves the pending operation in the browser (never a secret), sends the person through the identity provider's step-up, and runs the operation once when they return.
- **Token mode: there is no step-up.** A token holding `mqtt.clients.write` can create clients, and one holding `mqtt.clients.delete` can delete them, from the moment it is stolen until it is revoked or expires. For now, if you want step-up you implement it yourself.

**If you need it in token mode**, put it where the human is, not in this service:
1. **Front the API with your own gateway or UI** that authenticates people (passkey, TOTP, SSO), applies the table above, and only then calls `mqtt-admin` with a write token that **only that gateway** holds. People never see the write token.
2. **Or keep write tokens out of people's hands:** humans hold `read` tokens; `write` and `admin` tokens live in a secrets manager used by CI jobs that require a reviewed change.
3. **Reduce what a stolen token can do:** short `expires` dates, one token per person or job, no `admin` preset unless needed, and restrict the domain at your reverse proxy (IP allow-list or VPN).

## Security model

- The service connects to the broker as its own user (`MQTT_API_USERNAME`, default `mqtt-admin-api`) with the `dynsec-admin` role, which only allows the Dynamic Security channel and read-only `$SYS`. It never uses the broker's bootstrap `mqtt-admin`. The broker certificate is verified against `MQTT_ROOT_CA_B64`; `MQTT_TLS_SERVER_NAME` is checked even if the service dials the broker by an internal name.
- Roles can be managed here, behind guardrails that are enforced by the service, not by the caller:
  - **Reserved roles** (`MQTT_RESERVED_ROLES`, default `admin,dynsec-admin`) cannot be created, edited, deleted or assigned. They belong to the broker's own administration. If the service's broker user holds a different role, add it to the list.
  - **The control channel is never grantable.** Any rule whose topic starts with `$CONTROL` is refused, for every rule type, because a role that grants it lets its holders rewrite every user and role. Publishing into any `$`-prefixed topic is refused too. Reading `$SYS` (statistics) is allowed.
  - Rules are validated: a known type, a well-formed topic filter (`+` and `#` only as whole levels, `#` last, at most 1024 bytes, no control characters), a priority between -1000 and 1000. `%u` and `%c` are accepted for per-client isolation.
  - A role that clients still hold is not deleted unless the caller repeats the request with `?force=true`; the 409 answer says how many clients it would affect.
  - Creating a role with its first rules is all-or-nothing: if a rule cannot be added the role is removed again.
  - Every role and role-assignment change is in the audit log with the rule it touched.
- `MQTT_ALLOWED_ROLES`, when set, narrows which roles can be given to clients (a deliberate allow-list). By default every role that is not reserved can be assigned.
- `mqtt-admin` and the service's own user are protected (`MQTT_PROTECTED_USERS`): they cannot be disabled, rotated or deleted through the API.
- Passwords: when omitted the service generates one (24 random bytes, base64url) and returns it **once** (`Cache-Control: no-store`). Supplied passwords must be 24-128 characters. Passwords and tokens are never logged and never echoed back.
- Unauthenticated callers reach only `/health` and `/ready`. A caller that keeps causing 401/403 responses is throttled: after `MQTT_AUTH_FAIL_LIMIT` failures per client address per minute (default 20, `0` disables) it gets `429` until the window ends. Successful requests are never counted. The client address is the `X-Real-IP` set by the reverse proxy.
- Token comparison is constant-time and does not reveal how many tokens exist.
- Every change is logged as a JSON `audit` line: actor (`token:<name>` or the identity provider's `sub`), action, target, result.

## Routes and scopes

| Method and path | Scope | Notes |
|---|---|---|
| `GET /health` | none | `200 {"status":"ok"}` while the broker connection is up, `503 {"status":"degraded"}` while it is down. The connection is kept open and reconnects on its own. Use it as the health-check path |
| `GET /ready` | none | alias of `/health` |
| `GET /admin/api/server` | `mqtt.server.read` | broker connection, Dynamic Security reachability, client count |
| `GET /admin/api/stats` | `mqtt.server.read` | latest broker `$SYS` snapshot: clients, store, messages, bytes, load averages, memory, uptime. In memory only; `stale` is true after 60 s without an update |
| `GET /admin/api/docs` | `mqtt.server.read` | published documentation versions |
| `GET /admin/api/docs/{version}` | `mqtt.server.read` | the document as `{version,status,content_type,documentation}`; `?lang=pt` or `?lang=en` (English by default). Embedded from `internal/docs/content/` |
| `GET /admin/api/roles` | `mqtt.roles.read` | `{roles:[{name,description,acls,reserved,assignable,clientCount}], assignable:[names]}` |
| `GET /admin/api/roles/{name}` | `mqtt.roles.read` | one role, plus `clients`: the usernames that hold it |
| `POST /admin/api/roles` | `mqtt.roles.write` | `{name, description?, acls?:[{type,topic,allow?,priority?}]}`, 201. All-or-nothing |
| `DELETE /admin/api/roles/{name}` | `mqtt.roles.delete` | 204. `409 role_in_use` with `{clients:n}` unless `?force=true`, which unlinks the clients first |
| `POST /admin/api/roles/{name}/acls` | `mqtt.roles.write` | `{type, topic, allow?, priority?}`, 201 |
| `POST /admin/api/roles/{name}/acls/remove` | `mqtt.roles.write` | `{type, topic}`, 204. A POST because topic filters do not belong in a path |
| `PUT /admin/api/clients/{username}/roles/{role}` | `mqtt.roles.write` | give a role to a client, 204. Idempotent |
| `DELETE /admin/api/clients/{username}/roles/{role}` | `mqtt.roles.write` | take it away, 204 |
| `GET /admin/api/clients` | `mqtt.clients.read` | `{clients:[{username,disabled,roles}]}` |
| `GET /admin/api/clients/{username}` | `mqtt.clients.read` | |
| `POST /admin/api/clients` | `mqtt.clients.write` | `{username, role?, password?}`, 201, generated password returned once. Without `role`, the client gets `MQTT_DEFAULT_ROLE`, or the only assignable role; otherwise `400 role_required` |
| `POST /admin/api/clients/{username}/disable` | `mqtt.clients.write` | 204 |
| `POST /admin/api/clients/{username}/enable` | `mqtt.clients.write` | 204 |
| `POST /admin/api/clients/{username}/password` | `mqtt.credentials.rotate` | optional `{password}`, otherwise generated and returned once |
| `DELETE /admin/api/clients/{username}` | `mqtt.clients.delete` | 204 |

Errors are `{"error":"<code>"}`: `unauthorized` (401), `forbidden` (403), `protected_user` (403), `invalid_username`/`invalid_password`/`invalid_body`/`role_not_allowed` (400), `not_found` (404), `already_exists` (409), `broker_unavailable` (503), `too_many_failures` (429), and for roles: `invalid_role`/`invalid_acl`/`invalid_description`/`role_required` (400), `reserved_role`/`forbidden_topic` (403), `role_in_use` (409). Unmapped routes return 404/405 and never reach the broker. Usernames match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_AUTH_MODE` | `token` | `token` or `federated` |
| `MQTT_ADMIN_TOKENS` | none | token entries (token mode; required there) |
| `MW_IDENTITY_INTERNAL_BASE_URL`, `MW_IDENTITY_INTROSPECTION_CLIENT_SECRET` | none | required in federated mode |
| `MW_IDENTITY_INTROSPECTION_CLIENT_ID`, `MW_IDENTITY_AUDIENCE` | `mw-mqtt` | federated mode |
| `MW_IDENTITY_HTTP_TIMEOUT_SECONDS` | `5` | federated mode |
| `MQTT_API_PASSWORD` | none | password of the broker user, always required |
| `MQTT_API_USERNAME` | `mqtt-admin-api` | the broker user |
| `MQTT_BROKER_URL` | `ssl://mqtt:8883` | broker address |
| `MQTT_TLS_SERVER_NAME` | host of `MQTT_BROKER_URL` | name the broker certificate must match; set it when the service dials an internal name (such as `mqtt`) but the certificate carries the public host |
| `MQTT_PUBLIC_HOST` | none | broker host shown in the served documentation |
| `MQTT_PUBLIC_PORT` | `8883` | broker TLS port shown in the documentation |
| `MQTT_WS_URL` | none | WebSocket URL shown in the documentation; the browser section is omitted when empty |
| `MQTT_CA_NAME` | `ca.crt` | CA file name shown in the documentation |
| `MQTT_DOCS_PROFILE` | none | optional documentation profile appended to the served docs (`nightmare`); unknown names are ignored |
| `MQTT_ROOT_CA_B64` | none | base64 PEM of the CA that signed the broker certificate; shared with the broker's `secrets/root-ca.env` |
| `MQTT_ALLOWED_ROLES` | none | optional allow-list of the roles that may be given to clients; empty means every role that is not reserved |
| `MQTT_RESERVED_ROLES` | `admin,dynsec-admin` | roles the API never creates, edits, deletes or assigns |
| `MQTT_DEFAULT_ROLE` | none | role given to a new client when the caller names none (otherwise the only assignable role is used) |
| `MQTT_PROTECTED_USERS` | `mqtt-admin` | clients the API never changes (the service's own user is always protected) |
| `MQTT_AUTH_FAIL_LIMIT` | `20` | refused requests per address per minute before 429; `0` disables |
| `PORT` | `8090` | listen port |

See [../secrets/admin-api.env.example](../secrets/admin-api.env.example). The service exits with a clear message when required configuration is missing or invalid and Compose keeps restarting it, so it stays dormant until `secrets/admin-api.env` is correct.

## Known Mosquitto issue and how the service avoids it

Mosquitto 2.1.2's dynamic security plugin has a memory bug: a client created with its role **inside** the `createClient` command keeps a dangling reference to that role after the role is deleted. The client then shows a blank role name, and the broker can read freed memory or crash. We reproduced it with the broker's own commands, independent of this service, and it does not happen when the role is attached with a separate `addClientRole`, or when it is removed from the clients before the role is deleted.

The service therefore:

- never sends roles inside `createClient`: it creates the client, then attaches the role with `addClientRole`, and removes the client again if that fails;
- unlinks every client from a role (`removeClientRole`) before it deletes the role. This also makes deleting a role safe for clients created the old way, by an earlier version of this service;
- hides blank role names from client listings.

If you manage the broker yourself, apply the same two rules (attach roles with `addClientRole`, and unlink before `deleteRole`), or avoid deleting roles from other tools.

## Development

```sh
cd admin
go test ./...
```
