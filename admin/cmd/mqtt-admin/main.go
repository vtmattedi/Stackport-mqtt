// mqtt-admin is the broker administration API behind mw-bff. It validates MW Identity
// delegated tokens and applies client changes to Mosquitto through Dynamic Security.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/api"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/auth"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/config"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/dynsec"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/identity"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/scopes"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/stats"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/tokenauth"
)

func main() {
	// `mqtt-admin token ...` manages tokens and never starts the server or reads the
	// server configuration, so it works anywhere the binary does.
	if len(os.Args) > 1 && os.Args[1] == "token" {
		os.Exit(tokenauth.RunCLI(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	authorizer := newAuthorizer(cfg)
	brokerStats := stats.New()
	broker, err := dynsec.New(dynsec.Options{
		URL:        cfg.BrokerURL,
		Username:   cfg.APIUsername,
		Password:   cfg.APIPassword,
		ServerName: cfg.TLSServerName,
		RootCAPEM:  cfg.RootCAPEM,
		ClientID:   "mqtt-admin-api",
		Watch:      map[string]func(string, []byte){"$SYS/#": brokerStats.Handle},
	})
	if err != nil {
		slog.Error("broker client", "error", err)
		os.Exit(1)
	}
	defer broker.Close()

	srv := &http.Server{
		Addr: ":" + cfg.Port,
		Handler: api.New(api.Options{
			Broker:           broker,
			Stats:            brokerStats,
			Auth:             authorizer,
			AllowedRoles:     cfg.AllowedRoles,
			ReservedRoles:    cfg.ReservedRoles,
			DefaultRole:      cfg.DefaultRole,
			ProtectedUsers:   cfg.ProtectedUsers,
			AuthFailureLimit: cfg.AuthFailureLimit,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		slog.Info("mqtt-admin listening", "addr", srv.Addr, "auth_mode", cfg.AuthMode)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}

// newAuthorizer builds the authentication mode selected by ADMIN_AUTH_MODE.
func newAuthorizer(cfg config.Config) auth.Authorizer {
	if cfg.AuthMode == config.ModeFederated {
		introspector, err := identity.NewClient(cfg.IdentityBaseURL, cfg.IdentityClientID, cfg.IdentityClientSecret, cfg.IdentityTimeout)
		if err != nil {
			slog.Error("identity client", "error", err)
			os.Exit(1)
		}
		return identity.NewAuthenticator(cfg.IdentityAudience, introspector)
	}

	for _, t := range cfg.Tokens {
		slog.Info("admin token configured", "token", t.Name, "scopes", t.Scopes, "expires", expiry(t))
		if t.ExpiresAt.IsZero() && canChange(t.Scopes) {
			slog.Warn("admin token can change clients and never expires; consider an expiry date", "token", t.Name)
		}
	}
	return tokenauth.New(cfg.Tokens)
}

func expiry(t tokenauth.Entry) string {
	if t.ExpiresAt.IsZero() {
		return "never"
	}
	return t.ExpiresAt.Format("2006-01-02T15:04:05Z")
}

// canChange reports whether a token holds any scope beyond the read-only ones.
func canChange(granted []string) bool {
	for _, scope := range granted {
		switch scope {
		case scopes.ClientsWrite, scopes.ClientsDelete, scopes.CredentialsRotate:
			return true
		}
	}
	return false
}
