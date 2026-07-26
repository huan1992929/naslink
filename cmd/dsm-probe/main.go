package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"naslink/internal/dsm"
)

func main() {
	baseURL := flag.String("url", "", "DSM base URL, for example https://192.168.1.10:5001")
	account := flag.String("account", "", "temporary DSM administrator account")
	insecure := flag.Bool("insecure", false, "allow a self-signed DSM certificate")
	flag.Parse()
	password := os.Getenv("NASLINK_DSM_PASSWORD")
	if *baseURL == "" || *account == "" || password == "" {
		fmt.Fprintln(os.Stderr, "用法: NASLINK_DSM_PASSWORD=... dsm-probe --url https://nas:5001 --account naslink_poc_admin [--insecure]")
		os.Exit(2)
	}
	client, err := dsm.New(dsm.Config{BaseURL: *baseURL, Account: *account, Password: password, InsecureTLS: *insecure})
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	report, err := client.Probe(ctx)
	if err != nil {
		fatal(err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "dsm-probe:", err)
	os.Exit(1)
}
