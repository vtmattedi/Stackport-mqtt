#!/bin/sh
set -eu

# Run this from StackPort's terminal for the running mqtt container:
#   sh /stackport-scripts/provision-device.sh <device-id>
device=${1:-}
if ! printf '%s' "$device" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'; then
  echo "Usage: $0 <device-username> [publish-filter] [subscribe-filter]" >&2
  exit 1
fi

publish_filter=${2:-"devices/$device/events/#"}
subscribe_filter=${3:-"devices/$device/commands/#"}
admin_username=${MQTT_ADMIN_USERNAME:-mqtt-admin}

restore_tty() {
  stty echo 2>/dev/null || true
}
trap restore_tty EXIT INT TERM

printf 'MQTT admin username [%s]: ' "$admin_username" >&2
IFS= read -r entered_admin
if [ -n "$entered_admin" ]; then admin_username=$entered_admin; fi
printf 'MQTT admin password: ' >&2
stty -echo
IFS= read -r admin_password
restore_tty
printf '\nNew password for %s: ' "$device" >&2
stty -echo
IFS= read -r device_password
restore_tty
printf '\n' >&2

if [ "${#device_password}" -lt 24 ]; then
  echo "Device password must contain at least 24 characters." >&2
  exit 1
fi

ctrl() {
  mosquitto_ctrl -h localhost -p 8883 \
    --cafile /mosquitto/certs/nm-root-ca.crt --insecure \
    -u "$admin_username" -P "$admin_password" dynsec "$@"
}

role="device-$device"
ctrl createClient "$device" -p "$device_password"
ctrl createRole "$role"
ctrl addRoleACL "$role" publishClientSend "$publish_filter" allow
ctrl addRoleACL "$role" subscribePattern "$subscribe_filter" allow
ctrl addRoleACL "$role" publishClientReceive "$subscribe_filter" allow
ctrl addClientRole "$device" "$role"

unset admin_password device_password
trap - EXIT INT TERM

echo "Provisioned $device"
echo "  publish:   $publish_filter"
echo "  subscribe: $subscribe_filter"
