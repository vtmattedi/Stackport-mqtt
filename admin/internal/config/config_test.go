package config

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/tokenauth"
)

// baseEnv sets what every mode needs and clears everything else Load reads.
func baseEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"ADMIN_AUTH_MODE", "MQTT_ADMIN_TOKENS", "MW_IDENTITY_INTERNAL_BASE_URL",
		"MW_IDENTITY_INTROSPECTION_CLIENT_SECRET", "MQTT_AUTH_FAIL_LIMIT",
		"MW_IDENTITY_HTTP_TIMEOUT_SECONDS",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("MQTT_API_PASSWORD", "broker-password")
	t.Setenv("MQTT_ROOT_CA_B64", base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")))
}

func TestDefaultModeIsTokenAndNeedsAToken(t *testing.T) {
	baseEnv(t)
	_, err := Load()
	if err == nil {
		t.Fatal("token mode with no tokens must refuse to start")
	}
	for _, want := range []string{"ADMIN_AUTH_MODE=token", "MQTT_ADMIN_TOKENS", "mqtt-admin token new", "federated"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should mention %q: %v", want, err)
		}
	}

	t.Setenv("MQTT_ADMIN_TOKENS", "ci:"+tokenauth.Hash("t")+":read")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthMode != ModeToken || len(cfg.Tokens) != 1 || cfg.Tokens[0].Name != "ci" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestTokenModeDoesNotNeedIdentity(t *testing.T) {
	baseEnv(t)
	t.Setenv("MQTT_ADMIN_TOKENS", "ci:"+tokenauth.Hash("t")+":read")
	if _, err := Load(); err != nil {
		t.Fatalf("standalone mode must not require MW Identity: %v", err)
	}
}

func TestInvalidTokenConfigurationFailsClosed(t *testing.T) {
	baseEnv(t)
	t.Setenv("MQTT_ADMIN_TOKENS", "ci:not-a-hash:read")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MQTT_ADMIN_TOKENS") {
		t.Fatalf("expected a token configuration error, got %v", err)
	}
}

func TestFederatedModeNeedsIdentityButNotTokens(t *testing.T) {
	baseEnv(t)
	t.Setenv("ADMIN_AUTH_MODE", "federated")
	_, err := Load()
	if err == nil {
		t.Fatal("federated mode without Identity settings must refuse to start")
	}
	for _, want := range []string{"MW_IDENTITY_INTERNAL_BASE_URL", "MW_IDENTITY_INTROSPECTION_CLIENT_SECRET"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %s: %v", want, err)
		}
	}

	t.Setenv("MW_IDENTITY_INTERNAL_BASE_URL", "https://identity.example.com")
	t.Setenv("MW_IDENTITY_INTROSPECTION_CLIENT_SECRET", "s3cret")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthMode != ModeFederated || len(cfg.Tokens) != 0 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestModeIsCaseInsensitiveAndValidated(t *testing.T) {
	baseEnv(t)
	t.Setenv("MW_IDENTITY_INTERNAL_BASE_URL", "https://identity.example.com")
	t.Setenv("MW_IDENTITY_INTROSPECTION_CLIENT_SECRET", "s3cret")
	t.Setenv("ADMIN_AUTH_MODE", "Federated")
	if cfg, err := Load(); err != nil || cfg.AuthMode != ModeFederated {
		t.Fatalf("got %v, %v", cfg.AuthMode, err)
	}

	for _, bad := range []string{"none", "hybrid", "local", "off", "true"} {
		t.Setenv("ADMIN_AUTH_MODE", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ADMIN_AUTH_MODE") {
			t.Errorf("mode %q must be rejected, got %v", bad, err)
		}
	}
}

func TestBrokerPasswordAndCAStayRequiredInEveryMode(t *testing.T) {
	baseEnv(t)
	t.Setenv("MQTT_ADMIN_TOKENS", "ci:"+tokenauth.Hash("t")+":read")
	t.Setenv("MQTT_API_PASSWORD", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MQTT_API_PASSWORD") {
		t.Fatalf("got %v", err)
	}
	t.Setenv("MQTT_API_PASSWORD", "x")
	t.Setenv("MQTT_ROOT_CA_B64", "")
	if _, err := Load(); err == nil {
		t.Fatal("the root CA is required")
	}
}

func TestTLSServerNameDefaultsToTheBrokerHost(t *testing.T) {
	baseEnv(t)
	t.Setenv("MQTT_ADMIN_TOKENS", "ci:"+tokenauth.Hash("t")+":read")
	t.Setenv("MQTT_BROKER_URL", "ssl://broker.example.org:8883")
	t.Setenv("MQTT_TLS_SERVER_NAME", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSServerName != "broker.example.org" {
		t.Errorf("server name %q", cfg.TLSServerName)
	}
	t.Setenv("MQTT_TLS_SERVER_NAME", "mqtt.example.org")
	cfg, _ = Load()
	if cfg.TLSServerName != "mqtt.example.org" {
		t.Errorf("explicit name ignored: %q", cfg.TLSServerName)
	}
}
