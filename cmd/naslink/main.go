package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"naslink/internal/config"
	"naslink/internal/license"
	"naslink/internal/oidc"
	"naslink/internal/server"
	appstate "naslink/internal/state"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:17890", "HTTP listen address")
	dataDir := flag.String("data-dir", "./data", "persistent data directory")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	manager, err := config.NewManager(*dataDir)
	if err != nil {
		fatal(err)
	}
	store, err := appstate.Open(*dataDir)
	if err != nil {
		fatal(err)
	}
	provider, err := oidc.NewProvider(manager, store, *dataDir)
	if err != nil {
		fatal(err)
	}
	snapshot := store.Snapshot()
	licenseManager, err := license.NewManager(*dataDir, snapshot.InstallID, snapshot.CreatedAt)
	if err != nil {
		fatal(err)
	}
	app := server.New(manager, provider, store, licenseManager, logger)
	appContext, stopApp := context.WithCancel(context.Background())
	defer stopApp()
	app.StartScheduler(appContext)
	app.StartIdentityEvents(appContext)
	app.StartLicenseValidation(appContext)
	httpServer := &http.Server{
		Addr: *listen, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 12 * time.Minute, IdleTimeout: 90 * time.Second,
	}
	go func() {
		logger.Info("NASLink started", "listen", *listen, "data_dir", *dataDir)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatal(err)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	stopApp()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("shutdown failed", "error", err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "naslink:", err)
	os.Exit(1)
}
