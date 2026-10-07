#!/bin/sh
set -eu

# Creates one MQTT user (gateway, device, backend, ...) with a role. Create as many users
# as you want, or flash one shared user everywhere: the role is what grants access.
#   sh /stackport-scripts/provision-client.sh <username> <role>
# The role is the second argument, or MQTT_DEFAULT_ROLE. Create roles in the admin console
# or API first (or with setup-roles.sh <profile>).
client=${1:-}
role=${2:-${MQTT_DEFAULT_ROLE:-}}
if ! printf '%s' "$client" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' || [ -z "$role" ]; then
  echo "Usage: $0 <username> <role>   (or set MQTT_DEFAULT_ROLE)" >&2
  exit 1
fi

. "$(dirname "$0")/admin-lib.sh"

if [ -z "${MQTT_CLIENT_PASSWORD:-}" ]; then
  printf 'New password for %s: ' "$client" >&2
  stty -echo
  IFS= read -r MQTT_CLIENT_PASSWORD
  restore_tty
  printf '\n' >&2
fi
if [ "${#MQTT_CLIENT_PASSWORD}" -lt 24 ]; then
  echo "Password must contain at least 24 characters." >&2
  exit 1
fi

ctrl createClient "$client" -p "$MQTT_CLIENT_PASSWORD"
ctrl addClientRole "$client" "$role"

unset MQTT_ADMIN_PASSWORD MQTT_CLIENT_PASSWORD
trap - EXIT INT TERM

echo "Provisioned $client with role $role"
