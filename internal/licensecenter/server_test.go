package licensecenter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"naslink/internal/license"
)

func TestActivationLifecycle(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	customer, err := store.AddCustomer("测试客户", "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, code, err := store.CreateActivation(customer.ID, "professional", 300, 365, 1, []string{"sso", "directory", "sync"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app, err := NewServer(store, privateKey, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/activate", bytes.NewBufferString(`{"activation_code":"`+code+`","device_id":"dev1","version":"0.3.0"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		License   license.Envelope `json:"license"`
		LicenseID string           `json:"license_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(body.License)
	claims, err := license.Verify(raw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != "dev1" || claims.MaxUsers != 300 {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	bad := httptest.NewRequest(http.MethodGet, "/api/v1/admin/data", nil)
	badResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusUnauthorized {
		t.Fatalf("admin endpoint status %d", badResponse.Code)
	}
}
