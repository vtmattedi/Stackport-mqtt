package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/dynsec"
)

// rolesBroker models a broker with three roles, two clients and the commands the roles API
// sends. Unknown commands succeed with no data; failOn makes one command fail.
type rolesBroker struct {
	*fakeBroker
}

func newRolesBroker(failOn map[string]error) *rolesBroker {
	b := &fakeBroker{}
	b.fn = func(cmd map[string]any) (json.RawMessage, error) {
		name, _ := cmd["command"].(string)
		if err := failOn[name]; err != nil {
			return nil, err
		}
		switch name {
		case "listRoles":
			return json.RawMessage(`{"roles":[
				{"rolename":"admin","acls":[{"acltype":"publishClientSend","topic":"$CONTROL/dynamic-security/#","allow":true,"priority":0}]},
				{"rolename":"dynsec-admin","acls":[]},
				{"rolename":"nmnw","textdescription":"Trusted","acls":[{"acltype":"publishClientSend","topic":"#","allow":true,"priority":0}]},
				{"rolename":"viewer","acls":[]}]}`), nil
		case "listClients":
			return json.RawMessage(`{"clients":[
				{"username":"mqtt-admin","roles":[{"rolename":"admin"}]},
				{"username":"gw1","roles":[{"rolename":"nmnw"}]},
				{"username":"gw2","roles":[{"rolename":"nmnw"},{"rolename":"viewer"}]}]}`), nil
		case "getRole":
			if cmd["rolename"] == "ghost" {
				return nil, &dynsec.Error{Message: "Role not found"}
			}
			return json.RawMessage(`{"role":{"rolename":"nmnw","textdescription":"Trusted","acls":[{"acltype":"publishClientSend","topic":"#","allow":true,"priority":0}]}}`), nil
		}
		return nil, nil
	}
	return &rolesBroker{b}
}

func (b *rolesBroker) commandNames() []string {
	var out []string
	for _, c := range b.commands {
		out = append(out, c["command"].(string))
	}
	return out
}

func rolesServer(t *testing.T, b *rolesBroker, mutate func(*Options)) (http.Handler, map[string]string) {
	t.Helper()
	// Reuse the token-mode server (read / write / admin tokens) with this broker. These tests
	// start from the new default, with no allow-list, so every non-reserved role is
	// assignable; a test that wants an allow-list sets one in mutate.
	return newTokenServerWith(t, b.fakeBroker, func(o *Options) {
		o.AllowedRoles = nil
		if mutate != nil {
			mutate(o)
		}
	})
}

func decodeBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("not JSON: %q", body)
	}
	return out
}

func TestListRolesFlagsReservedAssignableAndMembers(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)
	rec := do(h, "GET", "/admin/api/roles", tok["reader"], "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out struct {
		Roles      []roleDTO `json:"roles"`
		Assignable []string  `json:"assignable"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	byName := map[string]roleDTO{}
	for _, r := range out.Roles {
		byName[r.Name] = r
	}
	if !byName["admin"].Reserved || !byName["dynsec-admin"].Reserved || byName["nmnw"].Reserved {
		t.Errorf("reserved flags wrong: %+v", byName)
	}
	if byName["admin"].Assignable || !byName["nmnw"].Assignable || !byName["viewer"].Assignable {
		t.Errorf("assignable flags wrong: %+v", byName)
	}
	if byName["nmnw"].ClientCount != 2 || byName["viewer"].ClientCount != 1 || byName["admin"].ClientCount != 1 {
		t.Errorf("client counts wrong: %+v", byName)
	}
	if strings.Join(out.Assignable, ",") != "nmnw,viewer" {
		t.Errorf("assignable list = %v (reserved roles must never be offered)", out.Assignable)
	}
	if byName["nmnw"].Description != "Trusted" || len(byName["nmnw"].ACLs) != 1 || byName["nmnw"].ACLs[0].Topic != "#" {
		t.Errorf("role detail lost: %+v", byName["nmnw"])
	}
}

func TestAllowedRolesStillRestrictsWhenConfigured(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, func(o *Options) { o.AllowedRoles = []string{"nmnw"} })
	var out struct {
		Assignable []string `json:"assignable"`
	}
	_ = json.Unmarshal(do(h, "GET", "/admin/api/roles", tok["reader"], "").Body.Bytes(), &out)
	if strings.Join(out.Assignable, ",") != "nmnw" {
		t.Fatalf("an explicit allow-list must narrow the assignable roles: %v", out.Assignable)
	}
}

func TestGetRoleIncludesMembers(t *testing.T) {
	h, tok := rolesServer(t, newRolesBroker(nil), nil)
	rec := do(h, "GET", "/admin/api/roles/nmnw", tok["reader"], "")
	body := decodeBody(t, rec.Body.String())
	if rec.Code != 200 || body["name"] != "nmnw" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	clients, _ := body["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("members = %v", body["clients"])
	}
	if got := do(h, "GET", "/admin/api/roles/ghost", tok["reader"], "").Code; got != 404 {
		t.Errorf("unknown role: %d", got)
	}
	if got := do(h, "GET", "/admin/api/roles/bad%20name", tok["reader"], "").Code; got != 400 {
		t.Errorf("bad role name: %d", got)
	}
}

func TestCreateRoleValidatesEverythingBeforeTouchingTheBroker(t *testing.T) {
	cases := []struct {
		name, body string
		want       int
		code       string
	}{
		{"reserved name", `{"name":"admin"}`, 403, "reserved_role"},
		{"reserved name dynsec-admin", `{"name":"dynsec-admin"}`, 403, "reserved_role"},
		{"bad name", `{"name":"-x"}`, 400, "invalid_role"},
		{"empty name", `{"name":""}`, 400, "invalid_role"},
		{"control channel ACL", `{"name":"r1","acls":[{"type":"publishClientSend","topic":"$CONTROL/#"}]}`, 403, "forbidden_topic"},
		{"control channel among good ACLs", `{"name":"r1","acls":[{"type":"subscribePattern","topic":"a/#"},{"type":"subscribePattern","topic":"$CONTROL/dynamic-security/v1"}]}`, 403, "forbidden_topic"},
		{"publish into $SYS", `{"name":"r1","acls":[{"type":"publishClientSend","topic":"$SYS/x"}]}`, 403, "forbidden_topic"},
		{"unknown ACL type", `{"name":"r1","acls":[{"type":"all","topic":"#"}]}`, 400, "invalid_acl"},
		{"malformed filter", `{"name":"r1","acls":[{"type":"subscribePattern","topic":"a/#/b"}]}`, 400, "invalid_acl"},
		{"bad priority", `{"name":"r1","acls":[{"type":"subscribePattern","topic":"a","priority":99999}]}`, 400, "invalid_acl"},
		{"long description", `{"name":"r1","description":"` + strings.Repeat("a", 201) + `"}`, 400, "invalid_description"},
		{"unknown field", `{"name":"r1","superuser":true}`, 400, "invalid_body"},
	}
	for _, c := range cases {
		b := newRolesBroker(nil)
		h, tok := rolesServer(t, b, nil)
		rec := do(h, "POST", "/admin/api/roles", tok["admin"], c.body)
		if rec.Code != c.want || !strings.Contains(rec.Body.String(), c.code) {
			t.Errorf("%s: got %d %s, want %d %s", c.name, rec.Code, rec.Body, c.want, c.code)
		}
		if len(b.commands) != 0 {
			t.Errorf("%s: the broker was contacted: %v", c.name, b.commandNames())
		}
	}

	// More ACLs than allowed in one request.
	var many []string
	for i := 0; i < maxACLsPerCreate+1; i++ {
		many = append(many, `{"type":"subscribePattern","topic":"t`+itoa(i)+`"}`)
	}
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)
	if got := do(h, "POST", "/admin/api/roles", tok["admin"], `{"name":"r1","acls":[`+strings.Join(many, ",")+`]}`).Code; got != 400 || len(b.commands) != 0 {
		t.Errorf("too many ACLs: %d, commands %v", got, b.commandNames())
	}
}

func TestCreateRoleCreatesThenAddsEachACL(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)
	rec := do(h, "POST", "/admin/api/roles", tok["admin"],
		`{"name":"devices","description":"Per-client topics","acls":[
			{"type":"publishClientSend","topic":"devices/%u/#"},
			{"type":"subscribePattern","topic":"devices/%u/#","allow":true,"priority":5}]}`)
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got := strings.Join(b.commandNames(), ","); got != "createRole,addRoleACL,addRoleACL" {
		t.Fatalf("commands = %s", got)
	}
	create := b.commands[0]
	if create["rolename"] != "devices" || create["textdescription"] != "Per-client topics" {
		t.Errorf("createRole payload: %v", create)
	}
	second := b.commands[2]
	if second["acltype"] != "subscribePattern" || second["topic"] != "devices/%u/#" ||
		second["allow"] != true || second["priority"] != 5 || second["rolename"] != "devices" {
		t.Errorf("second addRoleACL payload: %v", second)
	}
}

func TestCreateRoleIsRolledBackWhenAnACLFails(t *testing.T) {
	b := newRolesBroker(map[string]error{"addRoleACL": &dynsec.Error{Message: "boom"}})
	h, tok := rolesServer(t, b, nil)
	rec := do(h, "POST", "/admin/api/roles", tok["admin"],
		`{"name":"half","acls":[{"type":"subscribePattern","topic":"a"}]}`)
	if rec.Code != 400 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got := strings.Join(b.commandNames(), ","); got != "createRole,addRoleACL,deleteRole" {
		t.Fatalf("a failed create must remove the role again, commands = %s", got)
	}
}

func TestCreateRoleReportsAnExistingRole(t *testing.T) {
	b := newRolesBroker(map[string]error{"createRole": &dynsec.Error{Message: "Role already exists"}})
	h, tok := rolesServer(t, b, nil)
	if got := do(h, "POST", "/admin/api/roles", tok["admin"], `{"name":"nmnw"}`).Code; got != 409 {
		t.Fatalf("got %d, want 409", got)
	}
}

func TestDeleteRoleProtectsRolesInUse(t *testing.T) {
	// A role clients still hold needs ?force=true.
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)
	rec := do(h, "DELETE", "/admin/api/roles/nmnw", tok["admin"], "")
	body := decodeBody(t, rec.Body.String())
	if rec.Code != 409 || body["error"] != "role_in_use" || body["clients"] != float64(2) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for _, name := range b.commandNames() {
		if name == "deleteRole" {
			t.Fatal("the role was deleted although clients hold it")
		}
	}

	b = newRolesBroker(nil)
	h, tok = rolesServer(t, b, nil)
	if got := do(h, "DELETE", "/admin/api/roles/nmnw?force=true", tok["admin"], "").Code; got != 204 {
		t.Fatalf("force: %d", got)
	}
	if last := b.commands[len(b.commands)-1]; last["command"] != "deleteRole" || last["rolename"] != "nmnw" {
		t.Fatalf("force must delete: %v", b.commands)
	}

	// An unused role is deleted without force.
	b = newRolesBroker(map[string]error{})
	b.fn = func(cmd map[string]any) (json.RawMessage, error) {
		if cmd["command"] == "listClients" {
			return json.RawMessage(`{"clients":[]}`), nil
		}
		return nil, nil
	}
	h, tok = rolesServer(t, b, nil)
	if got := do(h, "DELETE", "/admin/api/roles/viewer", tok["admin"], "").Code; got != 204 {
		t.Fatalf("unused: %d", got)
	}
}

func TestDeleteRoleRefusesReservedAndMalformedNames(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)
	for _, role := range []string{"admin", "dynsec-admin"} {
		for _, q := range []string{"", "?force=true"} {
			if got := do(h, "DELETE", "/admin/api/roles/"+role+q, tok["admin"], "").Code; got != 403 {
				t.Errorf("%s%s: %d, want 403", role, q, got)
			}
		}
	}
	if got := do(h, "DELETE", "/admin/api/roles/bad%20name", tok["admin"], "").Code; got != 400 {
		t.Errorf("bad name: %d", got)
	}
	if len(b.commands) != 0 {
		t.Fatalf("reserved deletes reached the broker: %v", b.commandNames())
	}
}

func TestACLEditingGuardrails(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)

	for _, role := range []string{"admin", "dynsec-admin"} {
		if got := do(h, "POST", "/admin/api/roles/"+role+"/acls", tok["admin"], `{"type":"subscribePattern","topic":"a"}`).Code; got != 403 {
			t.Errorf("adding an ACL to reserved role %s: %d", role, got)
		}
		if got := do(h, "POST", "/admin/api/roles/"+role+"/acls/remove", tok["admin"], `{"type":"subscribePattern","topic":"a"}`).Code; got != 403 {
			t.Errorf("removing an ACL from reserved role %s: %d", role, got)
		}
	}
	// Granting the control channel is refused for every ACL type, on any role.
	for _, typ := range []string{"publishClientSend", "publishClientReceive", "subscribeLiteral", "subscribePattern", "unsubscribeLiteral", "unsubscribePattern"} {
		body := `{"type":"` + typ + `","topic":"$CONTROL/dynamic-security/#"}`
		if rec := do(h, "POST", "/admin/api/roles/nmnw/acls", tok["admin"], body); rec.Code != 403 || !strings.Contains(rec.Body.String(), "forbidden_topic") {
			t.Errorf("%s on $CONTROL: %d %s", typ, rec.Code, rec.Body)
		}
	}
	for name, body := range map[string]string{
		"unknown type": `{"type":"x","topic":"a"}`, "empty topic": `{"type":"subscribePattern","topic":""}`,
		"bad wildcard": `{"type":"subscribePattern","topic":"a+/b"}`, "not json": `nope`,
	} {
		if got := do(h, "POST", "/admin/api/roles/nmnw/acls", tok["admin"], body).Code; got != 400 {
			t.Errorf("%s: %d", name, got)
		}
	}
	if len(b.commands) != 0 {
		t.Fatalf("a refused ACL reached the broker: %v", b.commandNames())
	}
}

func TestACLAddAndRemoveSendTheRightCommands(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)

	rec := do(h, "POST", "/admin/api/roles/nmnw/acls", tok["admin"], `{"type":"publishClientReceive","topic":"a/+/c","allow":false,"priority":-3}`)
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	add := b.commands[0]
	if add["command"] != "addRoleACL" || add["rolename"] != "nmnw" || add["acltype"] != "publishClientReceive" ||
		add["topic"] != "a/+/c" || add["allow"] != false || add["priority"] != -3 {
		t.Errorf("addRoleACL: %v", add)
	}

	if got := do(h, "POST", "/admin/api/roles/nmnw/acls/remove", tok["admin"], `{"type":"publishClientReceive","topic":"a/+/c"}`).Code; got != 204 {
		t.Fatalf("remove: %d", got)
	}
	rm := b.commands[1]
	if rm["command"] != "removeRoleACL" || rm["acltype"] != "publishClientReceive" || rm["topic"] != "a/+/c" {
		t.Errorf("removeRoleACL: %v", rm)
	}
	if got := do(h, "POST", "/admin/api/roles/nmnw/acls/remove", tok["admin"], `{"type":"bogus","topic":"a"}`).Code; got != 400 {
		t.Errorf("remove with a bad type: %d", got)
	}
}

func TestAssigningRoles(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)

	if got := do(h, "PUT", "/admin/api/clients/gw1/roles/viewer", tok["admin"], "").Code; got != 204 {
		t.Fatalf("assign: %d", got)
	}
	if c := b.commands[0]; c["command"] != "addClientRole" || c["username"] != "gw1" || c["rolename"] != "viewer" {
		t.Errorf("addClientRole: %v", c)
	}
	if got := do(h, "DELETE", "/admin/api/clients/gw1/roles/viewer", tok["admin"], "").Code; got != 204 {
		t.Fatalf("unassign: %d", got)
	}
	if c := b.commands[1]; c["command"] != "removeClientRole" || c["username"] != "gw1" || c["rolename"] != "viewer" {
		t.Errorf("removeClientRole: %v", c)
	}
	sent := len(b.commands)

	for name, tc := range map[string]struct {
		method, path string
		want         int
	}{
		"assign a reserved role":          {"PUT", "/admin/api/clients/gw1/roles/admin", 400},
		"assign dynsec-admin":             {"PUT", "/admin/api/clients/gw1/roles/dynsec-admin", 400},
		"remove a reserved role":          {"DELETE", "/admin/api/clients/gw1/roles/admin", 400},
		"change a protected client":       {"PUT", "/admin/api/clients/mqtt-admin/roles/viewer", 403},
		"change a protected client (del)": {"DELETE", "/admin/api/clients/mqtt-admin/roles/viewer", 403},
		"bad username":                    {"PUT", "/admin/api/clients/-x/roles/viewer", 400},
		"bad role":                        {"PUT", "/admin/api/clients/gw1/roles/bad%20role", 400},
	} {
		if got := do(h, tc.method, tc.path, tok["admin"], "").Code; got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
	if len(b.commands) != sent {
		t.Fatalf("a refused assignment reached the broker: %v", b.commandNames()[sent:])
	}
}

func TestAssignmentRespectsAnExplicitAllowList(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, func(o *Options) { o.AllowedRoles = []string{"nmnw"} })
	if got := do(h, "PUT", "/admin/api/clients/gw1/roles/viewer", tok["admin"], "").Code; got != 400 {
		t.Fatalf("a role outside the allow-list: %d", got)
	}
	if got := do(h, "PUT", "/admin/api/clients/gw1/roles/nmnw", tok["admin"], "").Code; got != 204 {
		t.Fatalf("a role inside it: %d", got)
	}
}

func TestEditingAccessNeedsTheRolesScopes(t *testing.T) {
	h, tok := rolesServer(t, newRolesBroker(nil), nil)
	type route struct{ method, path, body string }
	changes := []route{
		{"POST", "/admin/api/roles", `{"name":"r1"}`},
		{"POST", "/admin/api/roles/nmnw/acls", `{"type":"subscribePattern","topic":"a"}`},
		{"POST", "/admin/api/roles/nmnw/acls/remove", `{"type":"subscribePattern","topic":"a"}`},
		{"PUT", "/admin/api/clients/gw1/roles/viewer", ""},
		{"DELETE", "/admin/api/clients/gw1/roles/viewer", ""},
		{"DELETE", "/admin/api/roles/viewer", ""},
	}
	// reader and writer must be refused. In particular the `write` preset, which existed
	// before roles could be edited, must not gain that power.
	for _, who := range []string{"reader", "writer"} {
		for _, r := range changes {
			if got := do(h, r.method, r.path, tok[who], r.body).Code; got != 403 {
				t.Errorf("%s %s %s: got %d, want 403", who, r.method, r.path, got)
			}
		}
	}
	for _, r := range changes {
		if got := do(h, r.method, r.path, "", r.body).Code; got != 401 {
			t.Errorf("anonymous %s %s: got %d, want 401", r.method, r.path, got)
		}
	}
	// Reading roles stays available to the read preset.
	for _, p := range []string{"/admin/api/roles", "/admin/api/roles/nmnw"} {
		if got := do(h, "GET", p, tok["reader"], "").Code; got != 200 {
			t.Errorf("reader GET %s: %d", p, got)
		}
	}
}

func TestNewClientRoleSelection(t *testing.T) {
	pick := func(t *testing.T, mutate func(*Options), roleInBody string) (int, string) {
		t.Helper()
		b := newRolesBroker(nil)
		h, tok := rolesServer(t, b, mutate)
		body := `{"username":"new1"}`
		if roleInBody != "" {
			body = `{"username":"new1","role":"` + roleInBody + `"}`
		}
		rec := do(h, "POST", "/admin/api/clients", tok["writer"], body)
		role := ""
		for _, c := range b.commands {
			if c["command"] == "addClientRole" && c["username"] == "new1" {
				role, _ = c["rolename"].(string)
			}
		}
		return rec.Code, role
	}

	// Two assignable roles exist (nmnw, viewer): the caller must choose.
	if code, _ := pick(t, nil, ""); code != 400 {
		t.Errorf("ambiguous default: %d, want 400 role_required", code)
	}
	if code, role := pick(t, nil, "viewer"); code != 201 || role != "viewer" {
		t.Errorf("explicit role: %d %q", code, role)
	}
	// A configured default removes the ambiguity.
	if code, role := pick(t, func(o *Options) { o.DefaultRole = "nmnw" }, ""); code != 201 || role != "nmnw" {
		t.Errorf("configured default: %d %q", code, role)
	}
	// A single allowed role is the default, as before roles became manageable.
	if code, role := pick(t, func(o *Options) { o.AllowedRoles = []string{"nmnw"} }, ""); code != 201 || role != "nmnw" {
		t.Errorf("single allowed role: %d %q", code, role)
	}
	// Reserved and malformed roles are refused whatever the default is.
	if code, _ := pick(t, nil, "admin"); code != 400 {
		t.Errorf("reserved role: %d", code)
	}
	if code, _ := pick(t, nil, "bad role"); code != 400 {
		t.Errorf("malformed role: %d", code)
	}
}

func TestBrokerFailuresInRoleRoutesMapToStatuses(t *testing.T) {
	b := newRolesBroker(map[string]error{"listRoles": dynsec.ErrUnavailable})
	h, tok := rolesServer(t, b, nil)
	if got := do(h, "GET", "/admin/api/roles", tok["reader"], "").Code; got != 503 {
		t.Errorf("broker down: %d", got)
	}
	b = newRolesBroker(map[string]error{"listClients": errors.New("weird")})
	h, tok = rolesServer(t, b, nil)
	if got := do(h, "GET", "/admin/api/roles", tok["reader"], "").Code; got != 502 {
		t.Errorf("broker error: %d", got)
	}
}

// Mosquitto 2.1.2 links a role given inline in createClient so that deleting the role does
// not unlink the client: it keeps a dangling reference to freed memory and the broker can
// crash. These tests pin the two workarounds.

func TestCreateClientNeverGivesTheRoleInline(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)
	if got := do(h, "POST", "/admin/api/clients", tok["writer"], `{"username":"gw9","role":"nmnw"}`).Code; got != 201 {
		t.Fatalf("create: %d", got)
	}
	if got := strings.Join(b.commandNames(), ","); got != "createClient,addClientRole" {
		t.Fatalf("commands = %s", got)
	}
	if _, inline := b.commands[0]["roles"]; inline {
		t.Fatalf("createClient must not carry roles: %v", b.commands[0])
	}
}

func TestCreateClientIsRolledBackWhenTheRoleCannotBeAttached(t *testing.T) {
	b := newRolesBroker(map[string]error{"addClientRole": &dynsec.Error{Message: "Role not found"}})
	h, tok := rolesServer(t, b, nil)
	rec := do(h, "POST", "/admin/api/clients", tok["writer"], `{"username":"gw9","role":"nmnw"}`)
	if rec.Code != 404 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if got := strings.Join(b.commandNames(), ","); got != "createClient,addClientRole,deleteClient" {
		t.Fatalf("a client that could not get its role must not be left behind: %s", got)
	}
	if strings.Contains(rec.Body.String(), "password") {
		t.Fatal("no password may be returned for a client that was rolled back")
	}
}

func TestDeletingARoleUnlinksEveryMemberFirst(t *testing.T) {
	b := newRolesBroker(nil)
	h, tok := rolesServer(t, b, nil)
	if got := do(h, "DELETE", "/admin/api/roles/nmnw?force=true", tok["admin"], "").Code; got != 204 {
		t.Fatalf("force delete: %d", got)
	}
	// listClients, then one removeClientRole per member, and only then deleteRole.
	names := b.commandNames()
	if got := strings.Join(names, ","); got != "listClients,removeClientRole,removeClientRole,deleteRole" {
		t.Fatalf("commands = %s", got)
	}
	unlinked := []string{b.commands[1]["username"].(string), b.commands[2]["username"].(string)}
	if strings.Join(unlinked, ",") != "gw1,gw2" {
		t.Fatalf("members unlinked = %v", unlinked)
	}
	for _, c := range b.commands[1:3] {
		if c["rolename"] != "nmnw" {
			t.Fatalf("wrong role unlinked: %v", c)
		}
	}
}

func TestDeletingAnUnusedRoleNeedsNoUnlinking(t *testing.T) {
	b := newRolesBroker(nil)
	b.fn = func(cmd map[string]any) (json.RawMessage, error) {
		if cmd["command"] == "listClients" {
			return json.RawMessage(`{"clients":[]}`), nil
		}
		return nil, nil
	}
	h, tok := rolesServer(t, b, nil)
	if got := do(h, "DELETE", "/admin/api/roles/viewer", tok["admin"], "").Code; got != 204 {
		t.Fatalf("%d", got)
	}
	if got := strings.Join(b.commandNames(), ","); got != "listClients,deleteRole" {
		t.Fatalf("commands = %s", got)
	}
}

func TestTheRoleIsNotDeletedWhenUnlinkingFails(t *testing.T) {
	b := newRolesBroker(map[string]error{"removeClientRole": &dynsec.Error{Message: "boom"}})
	h, tok := rolesServer(t, b, nil)
	if got := do(h, "DELETE", "/admin/api/roles/nmnw?force=true", tok["admin"], "").Code; got == 204 {
		t.Fatal("a failed unlink must fail the request")
	}
	for _, name := range b.commandNames() {
		if name == "deleteRole" {
			t.Fatal("deleteRole must never run while clients may still be linked")
		}
	}
}

func TestDanglingRoleReferencesAreHiddenFromClients(t *testing.T) {
	b := &fakeBroker{reply: json.RawMessage(`{"clients":[{"username":"gw1","roles":[{"rolename":""},{"rolename":"nmnw"}]}]}`)}
	h, tok := newTokenServer(t, b)
	var out struct {
		Clients []clientDTO `json:"clients"`
	}
	_ = json.Unmarshal(do(h, "GET", "/admin/api/clients", tok["reader"], "").Body.Bytes(), &out)
	if len(out.Clients) != 1 || strings.Join(out.Clients[0].Roles, ",") != "nmnw" {
		t.Fatalf("an empty role name is a broker artefact, not a role: %+v", out.Clients)
	}
}

func TestAssigningARoleTheClientAlreadyHoldsSucceeds(t *testing.T) {
	b := newRolesBroker(map[string]error{"addClientRole": &dynsec.Error{Message: "Client is already in this role"}})
	h, tok := rolesServer(t, b, nil)
	if got := do(h, "PUT", "/admin/api/clients/gw1/roles/nmnw", tok["admin"], "").Code; got != 204 {
		t.Fatalf("PUT must be idempotent: %d", got)
	}
}
