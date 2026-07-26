package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"naslink/internal/dsm"
)

func main() {
	baseURL := flag.String("url", "", "DSM base URL")
	account := flag.String("account", "", "DSM administrator account")
	spk := flag.String("spk", "", "local SPK file")
	insecure := flag.Bool("insecure", false, "allow a self-signed DSM certificate")
	flag.Parse()
	password := os.Getenv("NASLINK_DSM_PASSWORD")
	if *baseURL == "" || *account == "" || *spk == "" || password == "" {
		fmt.Fprintln(os.Stderr, "用法: NASLINK_DSM_PASSWORD=... dsm-spk-upgrade --url https://nas:5001 --account admin --spk NASLink.spk [--insecure]")
		os.Exit(2)
	}
	client, err := dsm.New(dsm.Config{
		BaseURL: *baseURL, Account: *account, Password: password, InsecureTLS: *insecure, Timeout: 3 * time.Minute,
	})
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if _, err := client.Discover(ctx); err != nil {
		fatal(err)
	}
	if err := client.Login(ctx); err != nil {
		fatal(err)
	}
	defer client.Logout(context.Background())
	confirmToken, err := client.ConfirmPassword(ctx)
	if err != nil {
		fatal(err)
	}
	fmt.Println("password confirmation: passed")
	taskID, err := client.UploadPackage(ctx, *spk)
	if err != nil {
		fatal(err)
	}
	fmt.Println("upload: passed")
	if err := client.UpgradePackage(ctx, taskID, confirmToken); err != nil {
		fatal(err)
	}
	fmt.Println("upgrade: accepted")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "dsm-spk-upgrade:", err)
	os.Exit(1)
}
