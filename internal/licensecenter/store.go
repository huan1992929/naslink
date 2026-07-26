package licensecenter

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Customer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Contact   string    `json:"contact,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
type ActivationCode struct {
	ID             string    `json:"id"`
	CodeHash       string    `json:"code_hash"`
	CodeHint       string    `json:"code_hint"`
	CustomerID     string    `json:"customer_id"`
	Edition        string    `json:"edition"`
	MaxUsers       int       `json:"max_users"`
	Features       []string  `json:"features"`
	ValidDays      int       `json:"valid_days"`
	MaxActivations int       `json:"max_activations"`
	Activations    int       `json:"activations"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
}
type Device struct {
	ID         string    `json:"id"`
	CustomerID string    `json:"customer_id"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Version    string    `json:"version,omitempty"`
	Revoked    bool      `json:"revoked"`
}
type LicenseRecord struct {
	ID               string    `json:"id"`
	ActivationID     string    `json:"activation_id"`
	CustomerID       string    `json:"customer_id"`
	DeviceID         string    `json:"device_id"`
	Edition          string    `json:"edition"`
	MaxUsers         int       `json:"max_users"`
	Features         []string  `json:"features"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	MaintenanceUntil time.Time `json:"maintenance_until,omitempty"`
	Revoked          bool      `json:"revoked"`
	ReplacedBy       string    `json:"replaced_by,omitempty"`
}
type Data struct {
	Version         int              `json:"version"`
	Customers       []Customer       `json:"customers"`
	ActivationCodes []ActivationCode `json:"activation_codes"`
	Devices         []Device         `json:"devices"`
	Licenses        []LicenseRecord  `json:"licenses"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	data Data
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dataDir, "license-center.json"), data: Data{Version: 1}}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("decode license center data: %w", err)
	}
	return s, nil
}

func (s *Store) Snapshot() Data {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, _ := json.Marshal(s.data)
	var out Data
	_ = json.Unmarshal(raw, &out)
	return out
}

func (s *Store) AddCustomer(name, contact string) (Customer, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Customer{}, errors.New("客户名称不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	customer := Customer{ID: randomID("cus"), Name: name, Contact: strings.TrimSpace(contact), CreatedAt: time.Now().UTC()}
	s.data.Customers = append(s.data.Customers, customer)
	return customer, s.saveLocked()
}

func (s *Store) CreateActivation(customerID, edition string, maxUsers, validDays, maxActivations int, features []string) (ActivationCode, string, error) {
	if customerID == "" || edition == "" || maxUsers <= 0 || validDays < 0 || maxActivations <= 0 {
		return ActivationCode{}, "", errors.New("激活码参数不完整")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !hasCustomer(s.data.Customers, customerID) {
		return ActivationCode{}, "", errors.New("客户不存在")
	}
	rawCode := "NASL-" + strings.ToUpper(randomHex(4)) + "-" + strings.ToUpper(randomHex(4)) + "-" + strings.ToUpper(randomHex(4))
	activation := ActivationCode{ID: randomID("act"), CodeHash: hashCode(rawCode), CodeHint: rawCode[len(rawCode)-4:], CustomerID: customerID, Edition: edition, MaxUsers: maxUsers, Features: clean(features), ValidDays: validDays, MaxActivations: maxActivations, Enabled: true, CreatedAt: time.Now().UTC()}
	s.data.ActivationCodes = append(s.data.ActivationCodes, activation)
	return activation, rawCode, s.saveLocked()
}

func (s *Store) Activate(code, deviceID, version string) (ActivationCode, Customer, Device, LicenseRecord, error) {
	if strings.TrimSpace(code) == "" || strings.TrimSpace(deviceID) == "" {
		return ActivationCode{}, Customer{}, Device{}, LicenseRecord{}, errors.New("激活码和设备指纹不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	activationIndex := -1
	for i := range s.data.ActivationCodes {
		if s.data.ActivationCodes[i].CodeHash == hashCode(code) {
			activationIndex = i
			break
		}
	}
	if activationIndex < 0 {
		return ActivationCode{}, Customer{}, Device{}, LicenseRecord{}, errors.New("激活码不存在")
	}
	activation := &s.data.ActivationCodes[activationIndex]
	if !activation.Enabled {
		return ActivationCode{}, Customer{}, Device{}, LicenseRecord{}, errors.New("激活码已停用")
	}
	for _, existing := range s.data.Licenses {
		if existing.ActivationID == activation.ID && existing.DeviceID == deviceID && !existing.Revoked {
			customer, _ := findCustomer(s.data.Customers, activation.CustomerID)
			device, _ := findDevice(s.data.Devices, deviceID)
			return *activation, customer, device, existing, nil
		}
	}
	if activation.Activations >= activation.MaxActivations {
		return ActivationCode{}, Customer{}, Device{}, LicenseRecord{}, errors.New("激活次数已用完")
	}
	now := time.Now().UTC()
	customer, _ := findCustomer(s.data.Customers, activation.CustomerID)
	device, found := findDevice(s.data.Devices, deviceID)
	if !found {
		device = Device{ID: deviceID, CustomerID: activation.CustomerID, FirstSeen: now}
		s.data.Devices = append(s.data.Devices, device)
	}
	for i := range s.data.Devices {
		if s.data.Devices[i].ID == deviceID {
			s.data.Devices[i].LastSeen = now
			s.data.Devices[i].Version = version
			s.data.Devices[i].Revoked = false
			device = s.data.Devices[i]
		}
	}
	license := LicenseRecord{ID: randomID("lic"), ActivationID: activation.ID, CustomerID: activation.CustomerID, DeviceID: deviceID, Edition: activation.Edition, MaxUsers: activation.MaxUsers, Features: append([]string(nil), activation.Features...), IssuedAt: now, MaintenanceUntil: now.AddDate(1, 0, 0)}
	if activation.ValidDays > 0 {
		license.ExpiresAt = now.Add(time.Duration(activation.ValidDays) * 24 * time.Hour)
	}
	activation.Activations++
	s.data.Licenses = append(s.data.Licenses, license)
	return *activation, customer, device, license, s.saveLocked()
}

func (s *Store) Renew(licenseID string, days int) (LicenseRecord, error) {
	if days <= 0 {
		return LicenseRecord{}, errors.New("续期天数必须大于 0")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Licenses {
		if s.data.Licenses[i].ID == licenseID {
			base := s.data.Licenses[i].ExpiresAt
			if base.Before(time.Now()) {
				base = time.Now().UTC()
			}
			s.data.Licenses[i].ExpiresAt = base.Add(time.Duration(days) * 24 * time.Hour)
			s.data.Licenses[i].MaintenanceUntil = s.data.Licenses[i].ExpiresAt
			return s.data.Licenses[i], s.saveLocked()
		}
	}
	return LicenseRecord{}, errors.New("License 不存在")
}

func (s *Store) Revoke(licenseID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Licenses {
		if s.data.Licenses[i].ID == licenseID {
			s.data.Licenses[i].Revoked = true
			return s.saveLocked()
		}
	}
	return errors.New("License 不存在")
}

func (s *Store) Migrate(licenseID, newDeviceID string) (LicenseRecord, error) {
	if newDeviceID == "" {
		return LicenseRecord{}, errors.New("新设备指纹不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Licenses {
		if s.data.Licenses[i].ID == licenseID && !s.data.Licenses[i].Revoked {
			old := &s.data.Licenses[i]
			replacement := *old
			replacement.ID = randomID("lic")
			replacement.DeviceID = newDeviceID
			replacement.IssuedAt = time.Now().UTC()
			replacement.Revoked = false
			replacement.ReplacedBy = ""
			old.Revoked = true
			old.ReplacedBy = replacement.ID
			s.data.Licenses = append(s.data.Licenses, replacement)
			return replacement, s.saveLocked()
		}
	}
	return LicenseRecord{}, errors.New("可迁移 License 不存在")
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
func hashCode(value string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(value))))
	return hex.EncodeToString(sum[:])
}
func hasCustomer(values []Customer, id string) bool { _, ok := findCustomer(values, id); return ok }
func findCustomer(values []Customer, id string) (Customer, bool) {
	for _, v := range values {
		if v.ID == id {
			return v, true
		}
	}
	return Customer{}, false
}
func findDevice(values []Device, id string) (Device, bool) {
	for _, v := range values {
		if v.ID == id {
			return v, true
		}
	}
	return Device{}, false
}
func clean(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
func randomID(prefix string) string { return prefix + "_" + randomHex(8) }
func randomHex(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}
