#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
host=${MQTT_HOST:-mqtt.mattediworks.com}
port=${MQTT_PORT:-8883}
username=${1:-}
topic=${2:-}
ca=${3:-${MQTT_CA_FILE:-}}

if [ -z "$username" ] || [ -z "$topic" ] || [ -z "$ca" ]; then
  echo "Usage: $0 <username> <permitted-topic> <path-to-nm-root-ca.crt>" >&2
  exit 1
fi
if [ ! -s "$ca" ]; then
  echo "Missing $ca" >&2
  exit 1
fi

restore_tty() {
  stty echo 2>/dev/null || true
}
trap restore_tty EXIT INT TERM
printf 'Password for %s: ' "$username" >&2
stty -echo
IFS= read -r password
restore_tty
printf '\n' >&2

name="mqtt-smoke-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT INT TERM

docker run -d --name "$name" -v "$ca:/ca.crt:ro" eclipse-mosquitto:2.1.2-alpine \
  mosquitto_sub -h "$host" -p "$port" --cafile /ca.crt \
  -u "$username" -P "$password" -t "$topic" -C 1 -W 15 >/dev/null

sleep 1
docker run --rm -v "$ca:/ca.crt:ro" eclipse-mosquitto:2.1.2-alpine \
  mosquitto_pub -h "$host" -p "$port" --cafile /ca.crt \
  -u "$username" -P "$password" -t "$topic" -m "stackport-smoke-$$"

status=$(docker wait "$name")
logs=$(docker logs "$name" 2>&1)
if [ "$status" != 0 ] || [ "$logs" != "stackport-smoke-$$" ]; then
  echo "$logs" >&2
  exit 1
fi

echo "Authenticated TLS publish/subscribe round trip passed on $topic."
