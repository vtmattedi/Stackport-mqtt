# PKI boundary

This repository intentionally does not generate or store CA private keys.

Keep these outside the repository on a secured administrative/offline system:

- `nm-root-ca.key`
- `nm-mqtt-intermediate.key`

The public `nm-root-ca.crt` is distributed to NM-NW firmware. For StackPort deployment, the public root, broker leaf key, and leaf-plus-intermediate full chain are base64-encoded into the separate StackPort-managed env files documented in the root README.

The broker certificate must contain `DNS:mqtt.mattediworks.com` in its Subject Alternative Name. Add `DNS:mqtt` only if trusted internal clients must connect by the Compose service name.

## Issuing certificates (`pki.ps1` / `pki.sh`)

OpenSSL runs in a throwaway `alpine/openssl` Docker container, so nothing needs to be installed. All output goes to a directory **outside this repository** (default `D:\pki-nm`); `pki.ps1` refuses a directory inside the repo. Never run it on the VPS.

Requirements: Docker. Run from the repository root in PowerShell.

### First-time setup

```powershell
.\pki\pki.ps1 init           # Root CA (10y) + MQTT Intermediate (5y); refuses to overwrite
.\pki\pki.ps1 issue-leaf     # broker leaf (397d), SAN DNS:mqtt.mattediworks.com, then verifies it
.\pki\pki.ps1 export-env     # writes ready-to-paste StackPort env files
```

Use `-Dir E:\somewhere` to change the output directory and `-HostName other.example.com` to change the leaf name.

Afterwards move `nm-root-ca.key` and `nm-mqtt-intermediate.key` to offline storage and delete them from the working directory. Keep `nm-root-ca.crt` for the firmware.

### Output

| File in the output dir | Purpose | Goes to StackPort |
|---|---|---|
| `nm-root-ca.key`, `nm-mqtt-intermediate.key` | CA private keys | **Never** |
| `nm-root-ca.crt` | public Root CA, also embedded in firmware | yes |
| `fullchain.pem`, `privkey.pem` | broker leaf + intermediate, leaf key | yes |
| `stackport-env/admin.env` | admin user and generated password | `secrets/admin.env` |
| `stackport-env/root-ca.env` | base64 Root CA | `secrets/root-ca.env` |
| `stackport-env/broker-cert.env` | base64 fullchain | `secrets/broker-cert.env` |
| `stackport-env/broker-key.env` | base64 leaf key | `secrets/broker-key.env` |

Paste the **contents** of each `stackport-env` file into the matching env file on the StackPort project page.

### Renewing the broker certificate

The leaf expires after 397 days. To renew, put `nm-mqtt-intermediate.key` back in the output directory, then:

```powershell
.\pki\pki.ps1 issue-leaf
.\pki\pki.ps1 export-env
```

Replace only `broker-cert.env` and `broker-key.env` in StackPort and recreate the project. `admin.env` is preserved (delete `stackport-env/admin.env` first if you want a new password). Firmware is unaffected because it trusts the Root CA.

### Checking expiry

```powershell
.\pki\pki.ps1 status
```

Prints days remaining for the Root, Intermediate and leaf. It exits non-zero when the leaf has fewer than 60 days left (`WARN_DAYS`) or a CA has fewer than 365, so it can be used in a reminder or scheduled check. It only needs the public certificates, so the CA keys can stay offline. Run it about once a quarter and always before a planned renewal.

### Renewing the Intermediate (about every 4 years)

Needs `nm-root-ca.key` back in the output directory temporarily.

```powershell
.\pki\pki.ps1 renew-intermediate
.\pki\pki.ps1 export-env
```

By default the Intermediate **key is reused** and only the certificate is re-signed (the old one is kept as `nm-mqtt-intermediate.crt.bak-<date>`). Existing leaves stay valid, and `fullchain.pem` is rebuilt. Replace only `secrets/broker-cert.env` in StackPort and recreate the project. Firmware is unaffected.

To rotate the Intermediate key as well (for example after a suspected leak), set `NEW_KEY=1`. Old leaves then stop verifying, so run `issue-leaf` and `export-env` and replace both broker env files. Remove `nm-root-ca.key` from the directory afterwards.

### Renewing the Root (about every 10 years)

Not automated: a new Root must ship in firmware. Release firmware that trusts both the old and new Root before the old one expires, then re-run `init` in a new directory and issue a new Intermediate and leaf.

### Other commands

```powershell
.\pki\pki.ps1 verify         # check chain, hostname and expiry of the current leaf
```

Validity can be changed with the `ROOT_DAYS`, `INT_DAYS` and `LEAF_DAYS` variables inside `pki.sh`.
