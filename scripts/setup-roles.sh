#!/bin/sh
set -eu

# Creates the `nmnw` role (and the narrow `dynsec-admin` role for the mqtt-admin API): fully trusted NightMare Network access. It may publish,
# subscribe and receive on every topic (`#`), including Control/*. `#` does not match
# $-prefixed topics, so the Dynamic Security admin channel ($CONTROL) and $SYS stay
# reserved for the admin client. Safe to run more than once.
#   sh /stackport-scripts/setup-roles.sh
. "$(dirname "$0")/admin-lib.sh"

role=nmnw
ctrl createRole "$role" || true
for acl in publishClientSend publishClientReceive subscribePattern unsubscribePattern; do
  ctrl addRoleACL "$role" "$acl" '#' allow || true
done

echo "Role $role:"
ctrl getRole "$role"

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
