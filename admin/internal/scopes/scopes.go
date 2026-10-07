// Package scopes defines the permission names of the admin API and the presets used to
// grant them to static tokens. Both authentication modes use the same names.
package scopes

import "sort"

const (
	ClientsRead       = "mqtt.clients.read"
	ClientsWrite      = "mqtt.clients.write"
	ClientsDelete     = "mqtt.clients.delete"
	CredentialsRotate = "mqtt.credentials.rotate"
	RolesRead         = "mqtt.roles.read"
	ServerRead        = "mqtt.server.read"
)

// All lists every scope the API knows.
func All() []string {
	return []string{ClientsRead, ClientsWrite, ClientsDelete, CredentialsRotate, RolesRead, ServerRead}
}

// presets are convenience names for token configuration. They only exist at
// configuration time; a token ends up holding plain scope names.
var presets = map[string][]string{
	// read: look at everything, change nothing.
	"read": {ClientsRead, RolesRead, ServerRead},
	// write: read, plus create, disable/enable and rotate passwords. No delete.
	"write": {ClientsRead, RolesRead, ServerRead, ClientsWrite, CredentialsRotate},
	// admin: everything, including deleting clients.
	"admin": All(),
}

// Presets returns the preset names, sorted.
func Presets() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Expand turns a preset name or a scope name into scope names. The second result is false
// when the word is neither.
func Expand(word string) ([]string, bool) {
	if scopes, ok := presets[word]; ok {
		return append([]string(nil), scopes...), true
	}
	for _, scope := range All() {
		if scope == word {
			return []string{word}, true
		}
	}
	return nil, false
}
