package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"naslink/internal/license"
)

func main() {
	keyPath := flag.String("key", ".owner/license-private.pem", "Ed25519 private key path")
	output := flag.String("out", "license.json", "output license file")
	licenseID := flag.String("id", "", "license ID")
	customer := flag.String("customer", "", "customer name")
	device := flag.String("device", "", "device ID shown by NASLink")
	edition := flag.String("edition", "professional", "edition")
	maxUsers := flag.Int("max-users", 300, "maximum source users")
	features := flag.String("features", "sso,directory,matching,sync", "comma separated features")
	expires := flag.String("expires", "", "optional expiry YYYY-MM-DD")
	maintenance := flag.String("maintenance-until", "", "optional maintenance expiry YYYY-MM-DD")
	flag.Parse()
	if *licenseID == "" || *customer == "" || *device == "" {
		fatal("id, customer and device are required")
	}
	privateRaw, err := os.ReadFile(*keyPath)
	if err != nil {
		fatal(err.Error())
	}
	privateKey, err := license.LoadPrivateKey(privateRaw)
	if err != nil {
		fatal(err.Error())
	}
	claims := license.Claims{LicenseID: *licenseID, Customer: *customer, DeviceID: *device, Edition: *edition, MaxUsers: *maxUsers, Features: split(*features), IssuedAt: time.Now().UTC()}
	if *expires != "" {
		claims.ExpiresAt = parseDate(*expires)
	}
	if *maintenance != "" {
		claims.MaintenanceUntil = parseDate(*maintenance)
	}
	raw, err := license.Sign(claims, privateKey)
	if err != nil {
		fatal(err.Error())
	}
	if err := os.WriteFile(*output, raw, 0o600); err != nil {
		fatal(err.Error())
	}
	fmt.Println("License written to", *output)
}

func parseDate(value string) time.Time {
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		fatal("invalid date " + value)
	}
	return parsed.UTC().Add(24*time.Hour - time.Second)
}

func split(value string) []string {
	values := []string{}
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	return values
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "licensegen:", message)
	os.Exit(1)
}
