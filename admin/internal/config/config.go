// Package config reads the mqtt-admin runtime configuration from the environment.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port string

	BrokerURL     string
	TLSServerName string
	RootCAPEM     []byte
	APIUsername   string
	APIPassword   string

	// AllowedRoles are the only roles the API may assign. Roles themselves are not
	// managed here: this service administers clients, not the broker's access model.
	AllowedRoles []string
	// ProtectedUsers can never be disabled, rotated or deleted through the API.
	ProtectedUsers []string

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
		AllowedRoles:         list(get("MQTT_ALLOWED_ROLES", "nmnw")),
		IdentityBaseURL:      strings.TrimSpace(os.Getenv("MW_IDENTITY_INTERNAL_BASE_URL")),
		IdentityClientID:     get("MW_IDENTITY_INTROSPECTION_CLIENT_ID", "mw-mqtt"),
		IdentityClientSecret: os.Getenv("MW_IDENTITY_INTROSPECTION_CLIENT_SECRET"),
		IdentityAudience:     get("MW_IDENTITY_AUDIENCE", "mw-mqtt"),
		IdentityTimeout:      5 * time.Second,
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

	var missing []string
	for name, value := range map[string]string{
		"MQTT_API_PASSWORD":                       cfg.APIPassword,
		"MW_IDENTITY_INTERNAL_BASE_URL":           cfg.IdentityBaseURL,
		"MW_IDENTITY_INTROSPECTION_CLIENT_SECRET": cfg.IdentityClientSecret,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment: %s", strings.Join(missing, ", "))
	}
	if len(cfg.AllowedRoles) == 0 {
		return Config{}, fmt.Errorf("MQTT_ALLOWED_ROLES must not be empty")
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
