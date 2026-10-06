#!/bin/sh
set -eu

# Creates one MQTT user (gateway, device, backend, ...) with a role. Create as many users
# as you want, or flash one shared user everywhere: the role is what grants access.
#   sh /stackport-scripts/provision-client.sh <username> [role]
# The role defaults to `nmnw` (run setup-roles.sh once first).
client=${1:-}
role=${2:-nmnw}
if ! printf '%s' "$client" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'; then
  echo "Usage: $0 <username> [role]" >&2
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
