package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"naslink/internal/dsm"
)

const (
	uatPrefix = "naslink_poc_"
	uatUser   = "naslink_poc_uat_001"
	uatGroup  = "naslink_poc_uat"
)

func main() {
	baseURL := flag.String("url", "https://127.0.0.1:5001", "DSM base URL")
	account := flag.String("account", "", "DSM administrator account")
	insecure := flag.Bool("insecure", false, "allow a self-signed DSM certificate")
	flag.Parse()
	password := os.Getenv("NASLINK_DSM_PASSWORD")
	if *account == "" || password == "" {
		fmt.Fprintln(os.Stderr, "用法: NASLINK_DSM_PASSWORD=... dsm-uat --url https://nas:5001 --account naslink_service [--insecure]")
		os.Exit(2)
	}
	client, err := dsm.New(dsm.Config{
		BaseURL: *baseURL, Account: *account, Password: password, InsecureTLS: *insecure,
	})
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := client.Discover(ctx); err != nil {
		fatal(err)
	}
	if err := client.Login(ctx); err != nil {
		fatal(err)
	}
	defer client.Logout(context.Background())
	passed("login")

	users, err := client.ListUsers(ctx)
	if err != nil {
		fatal(err)
	}
	passed("list users")
	groups, err := client.ListGroups(ctx)
	if err != nil {
		fatal(err)
	}
	passed("list groups")

	if !groupExists(groups, uatGroup) {
		if err := client.CreateGroup(ctx, uatGroup, "NASLink isolated UAT group"); err != nil {
			fatal(err)
		}
		passed("create UAT group")
	} else {
		skipped("create UAT group")
	}

	if !userExists(users, uatUser) {
		randomPassword := make([]byte, 30)
		if _, err := rand.Read(randomPassword); err != nil {
			fatal(err)
		}
		if err := client.CreateTestUser(ctx, uatPrefix, dsm.CreateUserInput{
			Name: uatUser, Password: base64.RawURLEncoding.EncodeToString(randomPassword),
			Description: "NASLink isolated UAT account",
		}); err != nil {
			fatal(err)
		}
		passed("create UAT user")
	} else {
		skipped("create UAT user")
	}

	if err := client.SetTestUserEnabled(ctx, uatPrefix, uatUser, false); err != nil {
		fatal(err)
	}
	passed("disable UAT user")
	if err := client.SetTestUserEnabled(ctx, uatPrefix, uatUser, true); err != nil {
		fatal(err)
	}
	passed("restore UAT user")
	if err := client.SetTestUserGroups(ctx, uatPrefix, uatUser, []string{uatGroup}, nil); err != nil {
		fatal(err)
	}
	passed("join UAT group")
	if err := client.SetTestUserGroups(ctx, uatPrefix, uatUser, nil, []string{uatGroup}); err != nil {
		fatal(err)
	}
	passed("leave UAT group")
	fmt.Println("UAT completed; the isolated account remains active and no existing account or file was changed.")
}

func userExists(users []dsm.User, name string) bool {
	for _, user := range users {
		if user.Name == name {
			return true
		}
	}
	return false
}

func groupExists(groups []dsm.Group, name string) bool {
	for _, group := range groups {
		if group.Name == name {
			return true
		}
	}
	return false
}

func passed(label string)  { fmt.Println(label + ": passed") }
func skipped(label string) { fmt.Println(label + ": skipped (already exists)") }

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "dsm-uat:", err)
	os.Exit(1)
}
