#!/bin/sh
# Runs inside an alpine/openssl container (see pki.ps1 / pki-docker.sh). Do not run on the VPS.
# Work dir /pki is a host directory OUTSIDE the repository.
#
#   init                 create Root CA + MQTT Intermediate (refuses if they exist)
#   issue-leaf [name]    issue a new broker leaf (default CN/SAN: mqtt.mattediworks.com)
#   export-env           write StackPort env files to /pki/stackport-env (admin password kept if present)
#   verify               verify chain and SAN of the current leaf
#   status               days remaining for Root, Intermediate and leaf (exit 1 if renewal is due)
#   renew-intermediate   re-sign the Intermediate with the Root key (needs nm-root-ca.key; NEW_KEY=1 rotates its key)
set -eu

cd /pki
HOST=${2:-mqtt.mattediworks.com}
ROOT_DAYS=${ROOT_DAYS:-3650}
INT_DAYS=${INT_DAYS:-1825}
LEAF_DAYS=${LEAF_DAYS:-397}

keygen() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }

cmd_init() {
  if [ -e nm-root-ca.key ] || [ -e nm-mqtt-intermediate.key ]; then
    echo "CA material already exists in /pki; refusing to overwrite." >&2
    exit 1
  fi
  umask 077
  keygen nm-root-ca.key
  openssl req -x509 -new -key nm-root-ca.key -sha256 -days "$ROOT_DAYS" \
    -subj "/O=NM/CN=NM Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out nm-root-ca.crt

  keygen nm-mqtt-intermediate.key
  openssl req -new -key nm-mqtt-intermediate.key -subj "/O=NM/CN=NM MQTT Intermediate CA" -out int.csr
  printf '%s\n' \
    "basicConstraints=critical,CA:TRUE,pathlen:0" \
    "keyUsage=critical,keyCertSign,cRLSign" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid" > int.ext
  openssl x509 -req -in int.csr -CA nm-root-ca.crt -CAkey nm-root-ca.key -CAcreateserial \
    -sha256 -days "$INT_DAYS" -extfile int.ext -out nm-mqtt-intermediate.crt
  rm -f int.csr int.ext nm-root-ca.srl
  echo "Created Root CA and MQTT Intermediate in /pki."
}

cmd_issue_leaf() {
  [ -s nm-mqtt-intermediate.key ] || { echo "Intermediate missing; run init first." >&2; exit 1; }
  umask 077
  keygen privkey.pem
  openssl req -new -key privkey.pem -subj "/O=NM/CN=$HOST" -out broker.csr
  printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" \
    "subjectAltName=DNS:$HOST" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid" > leaf.ext
  openssl x509 -req -in broker.csr -CA nm-mqtt-intermediate.crt -CAkey nm-mqtt-intermediate.key \
    -CAcreateserial -sha256 -days "$LEAF_DAYS" -extfile leaf.ext -out broker.crt
  cat broker.crt nm-mqtt-intermediate.crt > fullchain.pem
  rm -f broker.csr leaf.ext nm-mqtt-intermediate.srl
  cmd_verify
}

cmd_verify() {
  openssl verify -CAfile nm-root-ca.crt -untrusted nm-mqtt-intermediate.crt -verify_hostname "$HOST" broker.crt
  openssl x509 -in broker.crt -noout -subject -enddate -ext subjectAltName
}

# Re-sign the Intermediate with the Root key. Reuses the existing Intermediate key by default,
# so already-issued leaves keep validating; NEW_KEY=1 rotates the key (leaves must be re-issued).
cmd_renew_intermediate() {
  [ -s nm-root-ca.key ] || { echo "nm-root-ca.key missing; bring it back from offline storage first." >&2; exit 1; }
  [ -s nm-mqtt-intermediate.key ] || { echo "Intermediate key missing; run init first." >&2; exit 1; }
  umask 077
  stamp=$(date +%Y%m%d)
  cp nm-mqtt-intermediate.crt "nm-mqtt-intermediate.crt.bak-$stamp"
  if [ "${NEW_KEY:-0}" = 1 ]; then
    cp nm-mqtt-intermediate.key "nm-mqtt-intermediate.key.bak-$stamp"
    keygen nm-mqtt-intermediate.key
  fi
  openssl req -new -key nm-mqtt-intermediate.key -subj "/O=NM/CN=NM MQTT Intermediate CA" -out int.csr
  printf '%s\n' \
    "basicConstraints=critical,CA:TRUE,pathlen:0" \
    "keyUsage=critical,keyCertSign,cRLSign" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid" > int.ext
  openssl x509 -req -in int.csr -CA nm-root-ca.crt -CAkey nm-root-ca.key -CAcreateserial \
    -sha256 -days "$INT_DAYS" -extfile int.ext -out nm-mqtt-intermediate.crt
  rm -f int.csr int.ext nm-root-ca.srl
  openssl verify -CAfile nm-root-ca.crt nm-mqtt-intermediate.crt
  if [ "${NEW_KEY:-0}" = 1 ]; then
    echo "Intermediate key rotated: run issue-leaf and export-env, then redeploy."
  elif [ -s broker.crt ]; then
    # Rebuild the chain the broker serves so it carries the renewed Intermediate.
    cat broker.crt nm-mqtt-intermediate.crt > fullchain.pem
    echo "Existing leaf still valid. Run export-env and replace secrets/broker-cert.env in StackPort."
  fi
  echo "Remove nm-root-ca.key from this directory now."
}

# Days left per certificate; exits 1 if any is under WARN_DAYS (leaf) or 365 (CAs).
cmd_status() {
  rc=0
  for entry in "nm-root-ca.crt:365" "nm-mqtt-intermediate.crt:365" "broker.crt:${WARN_DAYS:-60}"; do
    f=${entry%%:*}; warn=${entry##*:}
    [ -s "$f" ] || { echo "$f: missing"; rc=1; continue; }
    end=$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)
    left=$(( ( $(date -u -D '%b %e %H:%M:%S %Y GMT' -d "$end" +%s) - $(date -u +%s) ) / 86400 ))
    state=ok
    [ "$left" -lt "$warn" ] && { state="RENEW SOON"; rc=1; }
    [ "$left" -lt 0 ] && state=EXPIRED
    printf '%-28s expires %s  (%s days)  %s\n' "$f" "$end" "$left" "$state"
  done
  return $rc
}

b64() { base64 < "$1" | tr -d '\n'; }

cmd_export_env() {
  umask 077
  mkdir -p stackport-env
  if [ ! -s stackport-env/admin.env ]; then
    printf 'MQTT_ADMIN_USERNAME=mqtt-admin\nMQTT_ADMIN_PASSWORD=%s\n' \
      "$(openssl rand -hex 24)" > stackport-env/admin.env
  fi
  printf 'MQTT_ROOT_CA_B64=%s\n' "$(b64 nm-root-ca.crt)" > stackport-env/root-ca.env
  printf 'MQTT_BROKER_FULLCHAIN_B64=%s\n' "$(b64 fullchain.pem)" > stackport-env/broker-cert.env
  printf 'MQTT_BROKER_PRIVATE_KEY_B64=%s\n' "$(b64 privkey.pem)" > stackport-env/broker-key.env
  echo "Wrote /pki/stackport-env/{admin,root-ca,broker-cert,broker-key}.env"
  echo "Paste each into the matching StackPort env file: secrets/<name>.env"
}

case "${1:-}" in
  init) cmd_init ;;
  issue-leaf) cmd_issue_leaf ;;
  export-env) cmd_export_env ;;
  verify) cmd_verify ;;
  status) cmd_status ;;
  renew-intermediate) cmd_renew_intermediate ;;
  *) echo "Usage: pki.sh init | issue-leaf [host] | renew-intermediate | export-env | verify | status" >&2; exit 1 ;;
esac
