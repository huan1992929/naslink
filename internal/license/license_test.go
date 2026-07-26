package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims{LicenseID: "LIC-1", Customer: "测试客户", Edition: "professional", DeviceID: "device", MaxUsers: 300, Features: []string{"sync"}, IssuedAt: time.Now()}
	raw, err := Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(raw, publicKey)
	if err != nil || got.MaxUsers != 300 {
		t.Fatalf("verify failed: %#v %v", got, err)
	}
	raw[len(raw)-2] ^= 1
	if _, err := Verify(raw, publicKey); err == nil {
		t.Fatal("tampered license should fail")
	}
}

func TestRemoteRevocationOverridesSignedLicense(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manager := &Manager{path: filepath.Join(dir, "license.json"), remotePath: filepath.Join(dir, "remote.json"), deviceID: "device", createdAt: time.Now(), publicKey: publicKey}
	raw, err := Sign(Claims{LicenseID: "LIC-REMOTE", Customer: "客户", Edition: "standard", DeviceID: "device", MaxUsers: 100, Features: []string{"sync"}, IssuedAt: time.Now()}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Install(raw); err != nil {
		t.Fatal(err)
	}
	if err := manager.RecordRemoteValidation("LIC-REMOTE", true, "已吊销"); err != nil {
		t.Fatal(err)
	}
	status := manager.Status(time.Now())
	if status.Valid || status.Reason != "已吊销" {
		t.Fatalf("unexpected status: %#v", status)
	}
	if err := manager.RecordRemoteValidation("LIC-REMOTE", false, ""); err != nil {
		t.Fatal(err)
	}
	if status = manager.Status(time.Now()); !status.Valid {
		t.Fatalf("expected restored status: %#v", status)
	}
}
