# NightMare profile (sourced by setup-roles.sh nightmare): the `nmnw` role, fully trusted
# NightMare Network access. It may publish, subscribe and receive on every topic (`#`),
# including Control/*. `#` does not match $-prefixed topics, so the Dynamic Security admin
# channel ($CONTROL) and $SYS stay reserved.
role=nmnw
ctrl createRole "$role" || true
for acl in publishClientSend publishClientReceive subscribePattern unsubscribePattern; do
  ctrl addRoleACL "$role" "$acl" '#' allow || true
done

echo "Role $role:"
ctrl getRole "$role"
