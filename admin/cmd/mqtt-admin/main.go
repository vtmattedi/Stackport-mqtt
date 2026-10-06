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
	"github.com/vtmattedi/stackport-mqtt/admin/internal/config"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/dynsec"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/identity"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	introspector, err := identity.NewClient(cfg.IdentityBaseURL, cfg.IdentityClientID, cfg.IdentityClientSecret, cfg.IdentityTimeout)
	if err != nil {
		slog.Error("identity client", "error", err)
		os.Exit(1)
	}
	broker, err := dynsec.New(dynsec.Options{
		URL:        cfg.BrokerURL,
		Username:   cfg.APIUsername,
		Password:   cfg.APIPassword,
		ServerName: cfg.TLSServerName,
		RootCAPEM:  cfg.RootCAPEM,
		ClientID:   "mqtt-admin-api",
	})
	if err != nil {
		slog.Error("broker client", "error", err)
		os.Exit(1)
	}
	defer broker.Close()

	srv := &http.Server{
		Addr: ":" + cfg.Port,
		Handler: api.New(api.Options{
			Broker:         broker,
			Auth:           identity.NewAuthenticator(cfg.IdentityAudience, introspector),
			AllowedRoles:   cfg.AllowedRoles,
			ProtectedUsers: cfg.ProtectedUsers,
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
		slog.Info("mqtt-admin listening", "addr", srv.Addr, "audience", cfg.IdentityAudience)
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
