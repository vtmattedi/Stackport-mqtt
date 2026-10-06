#!/bin/sh
# Sourced by the admin scripts. Run them from StackPort's terminal for the mqtt container.
# Prompts for the admin credentials without echo, unless MQTT_ADMIN_PASSWORD is already set.

restore_tty() { stty echo 2>/dev/null || true; }
trap restore_tty EXIT INT TERM

admin_username=${MQTT_ADMIN_USERNAME:-mqtt-admin}
if [ -z "${MQTT_ADMIN_PASSWORD:-}" ]; then
  printf 'MQTT admin username [%s]: ' "$admin_username" >&2
  IFS= read -r entered_admin
  if [ -n "$entered_admin" ]; then admin_username=$entered_admin; fi
  printf 'MQTT admin password: ' >&2
  stty -echo
  IFS= read -r MQTT_ADMIN_PASSWORD
  restore_tty
  printf '\n' >&2
fi

# mosquitto_ctrl exits 0 even when a command fails, so fail on its "Error" output.
ctrl() {
  ctrl_out=$(mosquitto_ctrl -h "${MQTT_HOST:-localhost}" -p 8883 \
    --cafile /mosquitto/certs/nm-root-ca.crt --insecure \
    -u "$admin_username" -P "$MQTT_ADMIN_PASSWORD" dynsec "$@" 2>&1) || return 1
  [ -z "$ctrl_out" ] || printf '%s\n' "$ctrl_out"
  case "$ctrl_out" in *Error*) return 1 ;; esac
}
