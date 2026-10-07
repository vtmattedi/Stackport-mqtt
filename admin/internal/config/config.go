// Package config reads the mqtt-admin runtime configuration from the environment.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/tokenauth"
)

// Authentication modes (ADMIN_AUTH_MODE).
const (
	ModeToken     = "token"
	ModeFederated = "federated"
)

type Config struct {
	Port string

	// AuthMode is how callers authenticate: ModeToken (default) or ModeFederated.
	AuthMode string
	// Tokens are the configured admin tokens (ModeToken only).
	Tokens []tokenauth.Entry

	BrokerURL     string
	TLSServerName string
	RootCAPEM     []byte
	APIUsername   string
	APIPassword   string

	// AllowedRoles optionally restricts the roles the API may assign. Empty (the default)
	// means every role that is not reserved.
	AllowedRoles []string
	// ReservedRoles can never be created, edited, deleted or assigned through the API.
	ReservedRoles []string
	// DefaultRole is given to a new client when the caller names none.
	DefaultRole string
	// ProtectedUsers can never be disabled, rotated or deleted through the API.
	ProtectedUsers []string
	// AuthFailureLimit caps failed-auth responses per client address per minute (0 = off).
	AuthFailureLimit int

	IdentityBaseURL      string
	IdentityClientID     string
	IdentityClientSecret string
	IdentityAudience     string
	IdentityTimeout      time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Port:                 get("PORT", "8090"),
		BrokerURL:            get("MQTT_BROKER_URL", "ssl://mqtt:8883"),
		TLSServerName:        get("MQTT_TLS_SERVER_NAME", "mqtt.mattediworks.com"),
		APIUsername:          get("MQTT_API_USERNAME", "mqtt-admin-api"),
		APIPassword:          os.Getenv("MQTT_API_PASSWORD"),
		AllowedRoles:         list(os.Getenv("MQTT_ALLOWED_ROLES")),
		ReservedRoles:        list(get("MQTT_RESERVED_ROLES", "admin,dynsec-admin")),
		DefaultRole:          strings.TrimSpace(os.Getenv("MQTT_DEFAULT_ROLE")),
		IdentityBaseURL:      strings.TrimSpace(os.Getenv("MW_IDENTITY_INTERNAL_BASE_URL")),
		IdentityClientID:     get("MW_IDENTITY_INTROSPECTION_CLIENT_ID", "mw-mqtt"),
		IdentityClientSecret: os.Getenv("MW_IDENTITY_INTROSPECTION_CLIENT_SECRET"),
		IdentityAudience:     get("MW_IDENTITY_AUDIENCE", "mw-mqtt"),
		IdentityTimeout:      5 * time.Second,
	}
	cfg.AuthFailureLimit = 20
	if raw := strings.TrimSpace(os.Getenv("MQTT_AUTH_FAIL_LIMIT")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 10000 {
			return Config{}, fmt.Errorf("invalid MQTT_AUTH_FAIL_LIMIT %q", raw)
		}
		cfg.AuthFailureLimit = n
	}
	cfg.ProtectedUsers = append(list(get("MQTT_PROTECTED_USERS", "mqtt-admin")), cfg.APIUsername)

	if raw := strings.TrimSpace(os.Getenv("MW_IDENTITY_HTTP_TIMEOUT_SECONDS")); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds <= 0 || seconds > 60 {
			return Config{}, fmt.Errorf("invalid MW_IDENTITY_HTTP_TIMEOUT_SECONDS %q", raw)
		}
		cfg.IdentityTimeout = time.Duration(seconds) * time.Second
	}

	encoded := strings.TrimSpace(os.Getenv("MQTT_ROOT_CA_B64"))
	if encoded == "" {
		return Config{}, fmt.Errorf("MQTT_ROOT_CA_B64 is required")
	}
	pem, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		return Config{}, fmt.Errorf("MQTT_ROOT_CA_B64 is not a base64 PEM certificate")
	}
	cfg.RootCAPEM = pem

	required := map[string]string{"MQTT_API_PASSWORD": cfg.APIPassword}

	cfg.AuthMode = strings.ToLower(get("ADMIN_AUTH_MODE", ModeToken))
	switch cfg.AuthMode {
	case ModeToken:
		tokens, err := tokenauth.ParseEntries(os.Getenv("MQTT_ADMIN_TOKENS"))
		if err != nil {
			return Config{}, fmt.Errorf("MQTT_ADMIN_TOKENS: %w", err)
		}
		if len(tokens) == 0 {
			return Config{}, errors.New("ADMIN_AUTH_MODE=token (the default) needs at least one token in " +
				"MQTT_ADMIN_TOKENS: generate one with `mqtt-admin token new`, or set ADMIN_AUTH_MODE=federated " +
				"to authenticate with MW Identity instead")
		}
		cfg.Tokens = tokens
	case ModeFederated:
		required["MW_IDENTITY_INTERNAL_BASE_URL"] = cfg.IdentityBaseURL
		required["MW_IDENTITY_INTROSPECTION_CLIENT_SECRET"] = cfg.IdentityClientSecret
	default:
		return Config{}, fmt.Errorf("invalid ADMIN_AUTH_MODE %q (use %q or %q)", cfg.AuthMode, ModeToken, ModeFederated)
	}

	var missing []string
	for name, value := range required {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return Config{}, fmt.Errorf("missing required environment: %s", strings.Join(missing, ", "))
	}
	if cfg.DefaultRole != "" {
		for _, reserved := range cfg.ReservedRoles {
			if reserved == cfg.DefaultRole {
				return Config{}, fmt.Errorf("MQTT_DEFAULT_ROLE %q is a reserved role", cfg.DefaultRole)
			}
		}
	}
	return cfg, nil
}

func get(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func list(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
