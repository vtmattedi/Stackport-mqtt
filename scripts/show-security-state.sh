#!/bin/sh
set -eu

# Run from StackPort's terminal for the mqtt container.
admin_username=${MQTT_ADMIN_USERNAME:-mqtt-admin}
restore_tty() { stty echo 2>/dev/null || true; }
trap restore_tty EXIT INT TERM
printf 'MQTT admin username [%s]: ' "$admin_username" >&2
IFS= read -r entered_admin
if [ -n "$entered_admin" ]; then admin_username=$entered_admin; fi
printf 'MQTT admin password: ' >&2
stty -echo
IFS= read -r admin_password
restore_tty
printf '\n' >&2

mosquitto_ctrl -h localhost -p 8883 --cafile /mosquitto/certs/nm-root-ca.crt --insecure -u "$admin_username" -P "$admin_password" dynsec getDefaultACLAccess
mosquitto_ctrl -h localhost -p 8883 --cafile /mosquitto/certs/nm-root-ca.crt --insecure -u "$admin_username" -P "$admin_password" dynsec listClients
mosquitto_ctrl -h localhost -p 8883 --cafile /mosquitto/certs/nm-root-ca.crt --insecure -u "$admin_username" -P "$admin_password" dynsec listRoles
unset admin_password
trap - EXIT INT TERM
