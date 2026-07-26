package licensecenter

import (
	"crypto/ed25519"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"naslink/internal/license"
)

//go:embed web/*
var webAssets embed.FS

type Server struct {
	store      *Store
	privateKey ed25519.PrivateKey
	adminToken string
}

func NewServer(store *Store, privateKey ed25519.PrivateKey, adminToken string) (*Server, error) {
	if store == nil || len(privateKey) != ed25519.PrivateKeySize || len(strings.TrimSpace(adminToken)) < 16 {
		return nil, errors.New("授权中心需要数据存储、Ed25519 私钥和至少 16 位管理令牌")
	}
	return &Server{store: store, privateKey: privateKey, adminToken: adminToken}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"service": "naslink-license-center", "version": "0.3.0-rc2", "time": time.Now().UTC()})
	})
	mux.HandleFunc("POST /api/v1/activate", s.activate)
	mux.HandleFunc("POST /api/v1/validate", s.validate)
	mux.HandleFunc("GET /api/v1/admin/data", s.requireAdmin(s.data))
	mux.HandleFunc("POST /api/v1/admin/customers", s.requireAdmin(s.createCustomer))
	mux.HandleFunc("POST /api/v1/admin/activation-codes", s.requireAdmin(s.createActivation))
	mux.HandleFunc("POST /api/v1/admin/licenses/{id}/renew", s.requireAdmin(s.renew))
	mux.HandleFunc("POST /api/v1/admin/licenses/{id}/revoke", s.requireAdmin(s.revoke))
	mux.HandleFunc("POST /api/v1/admin/licenses/{id}/migrate", s.requireAdmin(s.migrate))
	assets, _ := fs.Sub(webAssets, "web")
	mux.Handle("/", http.FileServer(http.FS(assets)))
	return securityHeaders(mux)
}

func (s *Server) activate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ActivationCode string `json:"activation_code"`
		DeviceID       string `json:"device_id"`
		Version        string `json:"version"`
	}
	if err := decode(r, &body); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	_, customer, _, record, err := s.store.Activate(body.ActivationCode, body.DeviceID, body.Version)
	if err != nil {
		apiError(w, 403, err.Error())
		return
	}
	envelope, err := s.sign(customer, record)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	var value license.Envelope
	_ = json.Unmarshal(envelope, &value)
	writeJSON(w, 200, map[string]any{"license": value, "license_id": record.ID, "customer": customer.Name})
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LicenseID string `json:"license_id"`
		DeviceID  string `json:"device_id"`
	}
	if err := decode(r, &body); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	data := s.store.Snapshot()
	for _, item := range data.Licenses {
		if item.ID == body.LicenseID && item.DeviceID == body.DeviceID {
			valid := !item.Revoked && (item.ExpiresAt.IsZero() || time.Now().Before(item.ExpiresAt))
			writeJSON(w, 200, map[string]any{"valid": valid, "revoked": item.Revoked, "expires_at": item.ExpiresAt})
			return
		}
	}
	apiError(w, 404, "License 或设备不存在")
}

func (s *Server) data(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.store.Snapshot()) }
func (s *Server) createCustomer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string `json:"name"`
		Contact string `json:"contact"`
	}
	if err := decode(r, &body); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	value, err := s.store.AddCustomer(body.Name, body.Contact)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, value)
}
func (s *Server) createActivation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CustomerID     string   `json:"customer_id"`
		Edition        string   `json:"edition"`
		MaxUsers       int      `json:"max_users"`
		ValidDays      int      `json:"valid_days"`
		MaxActivations int      `json:"max_activations"`
		Features       []string `json:"features"`
	}
	if err := decode(r, &body); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	value, code, err := s.store.CreateActivation(body.CustomerID, body.Edition, body.MaxUsers, body.ValidDays, body.MaxActivations, body.Features)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"activation": value, "activation_code": code})
}
func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Days int `json:"days"`
	}
	if err := decode(r, &body); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	record, err := s.store.Renew(r.PathValue("id"), body.Days)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	customer, _ := findCustomer(s.store.Snapshot().Customers, record.CustomerID)
	envelope, err := s.sign(customer, record)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	var value license.Envelope
	_ = json.Unmarshal(envelope, &value)
	writeJSON(w, 200, map[string]any{"record": record, "license": value})
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Revoke(r.PathValue("id")); err != nil {
		apiError(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) migrate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceID string `json:"device_id"`
	}
	if err := decode(r, &body); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	record, err := s.store.Migrate(r.PathValue("id"), body.DeviceID)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	customer, _ := findCustomer(s.store.Snapshot().Customers, record.CustomerID)
	envelope, err := s.sign(customer, record)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	var value license.Envelope
	_ = json.Unmarshal(envelope, &value)
	writeJSON(w, 200, map[string]any{"record": record, "license": value})
}

func (s *Server) sign(customer Customer, record LicenseRecord) ([]byte, error) {
	return license.Sign(license.Claims{LicenseID: record.ID, Customer: customer.Name, Edition: record.Edition, DeviceID: record.DeviceID, MaxUsers: record.MaxUsers, Features: record.Features, IssuedAt: record.IssuedAt, ExpiresAt: record.ExpiresAt, MaintenanceUntil: record.MaintenanceUntil}, s.privateKey)
}
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if len(provided) != len(s.adminToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.adminToken)) != 1 {
			apiError(w, 401, "管理令牌无效")
			return
		}
		next(w, r)
	}
}
func decode(r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("JSON 请求无效: %w", err)
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func apiError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"message": message}})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
