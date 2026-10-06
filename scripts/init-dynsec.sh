#!/bin/sh
set -eu

config=/mosquitto/data/dynamic-security.json
cert=/mosquitto/certs/fullchain.pem
key=/mosquitto/certs/privkey.pem
root_ca=/mosquitto/certs/nm-root-ca.crt

: "${MQTT_ADMIN_USERNAME:?Missing MQTT_ADMIN_USERNAME in secrets/admin.env}"
: "${MQTT_ADMIN_PASSWORD:?Missing MQTT_ADMIN_PASSWORD in secrets/admin.env}"
: "${MQTT_ROOT_CA_B64:?Missing MQTT_ROOT_CA_B64 in secrets/root-ca.env}"
: "${MQTT_BROKER_FULLCHAIN_B64:?Missing MQTT_BROKER_FULLCHAIN_B64 in secrets/broker-cert.env}"
: "${MQTT_BROKER_PRIVATE_KEY_B64:?Missing MQTT_BROKER_PRIVATE_KEY_B64 in secrets/broker-key.env}"

if [ "${#MQTT_ADMIN_PASSWORD}" -lt 32 ]; then
  echo "MQTT_ADMIN_PASSWORD must contain at least 32 characters." >&2
  exit 1
fi

install -d -m 750 -o 1883 -g 1883 /mosquitto/certs
umask 077
printf '%s' "$MQTT_BROKER_FULLCHAIN_B64" | base64 -d > "$cert.tmp"
printf '%s' "$MQTT_BROKER_PRIVATE_KEY_B64" | base64 -d > "$key.tmp"
printf '%s' "$MQTT_ROOT_CA_B64" | base64 -d > "$root_ca.tmp"
mv "$cert.tmp" "$cert"
mv "$key.tmp" "$key"
mv "$root_ca.tmp" "$root_ca"

case "$(head -n 1 "$cert")" in
  "-----BEGIN CERTIFICATE-----") ;;
  *) echo "Invalid certificate chain decoded from MQTT_BROKER_FULLCHAIN_B64" >&2; exit 1 ;;
esac
case "$(head -n 1 "$key")" in
  "-----BEGIN PRIVATE KEY-----"|"-----BEGIN RSA PRIVATE KEY-----"|"-----BEGIN EC PRIVATE KEY-----") ;;
  *) echo "Invalid private key decoded from MQTT_BROKER_PRIVATE_KEY_B64" >&2; exit 1 ;;
esac
case "$(head -n 1 "$root_ca")" in
  "-----BEGIN CERTIFICATE-----") ;;
  *) echo "Invalid Root CA decoded from MQTT_ROOT_CA_B64" >&2; exit 1 ;;
esac

chown 1883:1883 "$cert" "$key" "$root_ca"
chmod 640 "$cert"
chmod 600 "$key"
chmod 644 "$root_ca"

if [ ! -s "$config" ]; then
  mosquitto_ctrl dynsec init "$config" "$MQTT_ADMIN_USERNAME" "$MQTT_ADMIN_PASSWORD" >/dev/null
  # mosquitto_ctrl starts with permissive receive/unsubscribe defaults. V1 is
  # fail-closed, so deny every default action and grant access only through roles.
  sed -i \
    -e 's/"publishClientReceive":true/"publishClientReceive":false/' \
    -e 's/"unsubscribe":true/"unsubscribe":false/' \
    "$config"
  echo "Dynamic Security initialized for administrative client '$MQTT_ADMIN_USERNAME'."
else
  echo "Existing Dynamic Security state retained."
fi

chown -R 1883:1883 /mosquitto/data
chmod 700 /mosquitto/data
chmod 600 "$config"
