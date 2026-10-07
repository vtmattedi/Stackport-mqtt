#!/bin/sh
set -eu

# Creates the core role the admin API needs (`dynsec-admin`), and optionally the roles of a
# profile. Safe to run more than once.
#   sh /stackport-scripts/setup-roles.sh              core role only
#   sh /stackport-scripts/setup-roles.sh nightmare    core role + scripts/profiles/nightmare.sh
# Everything else (your own roles) is created in the admin console or API.
. "$(dirname "$0")/admin-lib.sh"

profile=${1:-}
if [ -n "$profile" ]; then
  if ! printf '%s' "$profile" | grep -Eq '^[a-z][a-z0-9-]{0,31}$' ||
     [ ! -f "$(dirname "$0")/profiles/$profile.sh" ]; then
    echo "Unknown profile '$profile'. Available:" >&2
    ls "$(dirname "$0")/profiles" 2>/dev/null | sed 's/\.sh$//; s/^/  /' >&2
    exit 1
  fi
fi

# dynsec-admin: only what the mqtt-admin API client needs: Dynamic Security plus read-only $SYS.
# It is not a general-purpose role; use it solely for the mqtt-admin-api user.
api_role=dynsec-admin
ctrl createRole "$api_role" || true
ctrl addRoleACL "$api_role" publishClientSend '$CONTROL/dynamic-security/v1' allow || true
ctrl addRoleACL "$api_role" publishClientReceive '$CONTROL/dynamic-security/v1/response' allow || true
ctrl addRoleACL "$api_role" subscribeLiteral '$CONTROL/dynamic-security/v1/response' allow || true
# Read-only broker statistics for the admin API's stats snapshot.
ctrl addRoleACL "$api_role" subscribePattern '$SYS/#' allow || true
ctrl addRoleACL "$api_role" publishClientReceive '$SYS/#' allow || true

echo "Role $api_role:"
ctrl getRole "$api_role"

if [ -n "$profile" ]; then
  . "$(dirname "$0")/profiles/$profile.sh"
fi
