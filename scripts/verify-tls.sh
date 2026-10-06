#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
host=${1:-mqtt.mattediworks.com}
port=${2:-8883}
ca=${3:-${MQTT_CA_FILE:-}}

if [ -z "$ca" ] || [ ! -s "$ca" ]; then
  echo "Usage: $0 [host] [port] <path-to-nm-root-ca.crt>" >&2
  exit 1
fi

# Reaching CONNACK is not required here: without credentials the expected broker
# response is an authentication refusal. TLS and hostname verification happen first.
output=$(docker run --rm -v "$ca:/ca.crt:ro" eclipse-mosquitto:2.1.2-alpine \
  mosquitto_sub -h "$host" -p "$port" --cafile /ca.crt -t '$SYS/#' -W 3 2>&1 || true)

if printf '%s' "$output" | grep -Eqi 'certificate verify failed|hostname verification failed|host name verification failed'; then
  echo "$output" >&2
  exit 1
fi
if ! printf '%s' "$output" | grep -Eqi 'not authorised|not authorized|connection refused'; then
  echo "TLS verification did not reach the broker's authentication boundary." >&2
  echo "$output" >&2
  exit 1
fi

echo "TLS chain and hostname verification passed for $host:$port; anonymous MQTT was rejected."
