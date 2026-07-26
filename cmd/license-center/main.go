package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"naslink/internal/license"
	"naslink/internal/licensecenter"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:17900", "HTTP listen address")
	dataDir := flag.String("data-dir", "./license-center-data", "persistent data directory")
	privateKeyPath := flag.String("private-key", "", "Ed25519 private key PEM path")
	adminToken := flag.String("admin-token", os.Getenv("NASLINK_LICENSE_ADMIN_TOKEN"), "admin bearer token (or NASLINK_LICENSE_ADMIN_TOKEN)")
	flag.Parse()
	if *privateKeyPath == "" {
		fatal("必须通过 -private-key 指定 Ed25519 私钥")
	}
	raw, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		fatal(err.Error())
	}
	privateKey, err := license.LoadPrivateKey(raw)
	if err != nil {
		fatal(err.Error())
	}
	store, err := licensecenter.Open(*dataDir)
	if err != nil {
		fatal(err.Error())
	}
	app, err := licensecenter.NewServer(store, privateKey, *adminToken)
	if err != nil {
		fatal(err.Error())
	}
	server := &http.Server{Addr: *listen, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second}
	log.Printf("NASLink License Center listening on %s", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}
func fatal(message string) { fmt.Fprintln(os.Stderr, "license-center:", message); os.Exit(1) }
