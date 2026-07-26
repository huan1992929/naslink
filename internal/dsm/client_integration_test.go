//go:build integration

package dsm

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveMembershipReconcile is an opt-in release check for DSM's private
// group-member API. It only adds the explicitly supplied user to the explicitly
// supplied group and requires a separate confirmation environment variable.
func TestLiveMembershipReconcile(t *testing.T) {
	if os.Getenv("NASLINK_LIVE_APPLY") != "APPLY" {
		t.Skip("set NASLINK_LIVE_APPLY=APPLY for the live membership release check")
	}
	baseURL, account, password := os.Getenv("NASLINK_LIVE_DSM_URL"), os.Getenv("NASLINK_LIVE_DSM_ACCOUNT"), os.Getenv("NASLINK_DSM_PASSWORD")
	username, group := os.Getenv("NASLINK_LIVE_DSM_USER"), os.Getenv("NASLINK_LIVE_DSM_GROUP")
	if baseURL == "" || account == "" || password == "" || username == "" || group == "" {
		t.Fatal("live DSM URL, account, password, user and group are required")
	}
	client, err := New(Config{BaseURL: baseURL, Account: account, Password: password, InsecureTLS: true, Timeout: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := client.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatal(err)
	}
	defer client.Logout(context.Background())
	if err := client.SetUserGroups(ctx, username, []string{group}, nil); err != nil {
		t.Fatal(err)
	}
	members, err := client.ListGroupMembers(ctx, group)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range members {
		if member == username {
			return
		}
	}
	t.Fatalf("DSM accepted the write but %s is not a member of %s", username, group)
}
