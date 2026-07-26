package license

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed public.pem
var embeddedPublicKey []byte

type Claims struct {
	LicenseID        string    `json:"license_id"`
	Customer         string    `json:"customer"`
	Edition          string    `json:"edition"`
	DeviceID         string    `json:"device_id"`
	MaxUsers         int       `json:"max_users"`
	Features         []string  `json:"features"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	MaintenanceUntil time.Time `json:"maintenance_until,omitempty"`
}

type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type Status struct {
	Mode             string    `json:"mode"`
	Valid            bool      `json:"valid"`
	Reason           string    `json:"reason,omitempty"`
	DeviceID         string    `json:"device_id"`
	LicenseID        string    `json:"license_id,omitempty"`
	Customer         string    `json:"customer,omitempty"`
	Edition          string    `json:"edition"`
	MaxUsers         int       `json:"max_users"`
	Features         []string  `json:"features"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	MaintenanceUntil time.Time `json:"maintenance_until,omitempty"`
}

type Manager struct {
	path       string
	remotePath string
	deviceID   string
	createdAt  time.Time
	publicKey  ed25519.PublicKey
}

func NewManager(dataDir, installID string, createdAt time.Time) (*Manager, error) {
	key, err := parsePublicKey(embeddedPublicKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte("naslink-device-v1:" + installID))
	return &Manager{path: filepath.Join(dataDir, "license.json"), remotePath: filepath.Join(dataDir, "license-remote-status.json"), deviceID: hex.EncodeToString(digest[:16]), createdAt: createdAt, publicKey: key}, nil
}

func (m *Manager) DeviceID() string { return m.deviceID }

func (m *Manager) Status(now time.Time) Status {
	raw, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		expires := m.createdAt.Add(30 * 24 * time.Hour)
		valid := now.Before(expires)
		reason := ""
		if !valid {
			reason = "30 天试用期已结束"
		}
		return Status{Mode: "trial", Valid: valid, Reason: reason, DeviceID: m.deviceID, Edition: "trial", MaxUsers: 50, Features: []string{"sso", "directory", "matching", "sync"}, ExpiresAt: expires}
	}
	if err != nil {
		return Status{Mode: "license", Valid: false, Reason: err.Error(), DeviceID: m.deviceID}
	}
	claims, err := Verify(raw, m.publicKey)
	if err != nil {
		return Status{Mode: "license", Valid: false, Reason: err.Error(), DeviceID: m.deviceID}
	}
	status := Status{Mode: "license", Valid: true, DeviceID: m.deviceID, LicenseID: claims.LicenseID, Customer: claims.Customer, Edition: claims.Edition, MaxUsers: claims.MaxUsers, Features: claims.Features, ExpiresAt: claims.ExpiresAt, MaintenanceUntil: claims.MaintenanceUntil}
	if claims.DeviceID != m.deviceID {
		status.Valid, status.Reason = false, "License 与当前安装实例不匹配"
	} else if !claims.ExpiresAt.IsZero() && now.After(claims.ExpiresAt) {
		status.Valid, status.Reason = false, "License 已过期"
	} else if claims.MaxUsers <= 0 {
		status.Valid, status.Reason = false, "License 用户上限无效"
	}
	if status.Valid {
		var remote struct {
			LicenseID string    `json:"license_id"`
			Revoked   bool      `json:"revoked"`
			Reason    string    `json:"reason"`
			CheckedAt time.Time `json:"checked_at"`
		}
		if raw, readErr := os.ReadFile(m.remotePath); readErr == nil && json.Unmarshal(raw, &remote) == nil && remote.LicenseID == claims.LicenseID && remote.Revoked {
			status.Valid = false
			status.Reason = valueOr(remote.Reason, "License 已被授权中心吊销")
		}
	}
	return status
}

func (m *Manager) Install(raw []byte) (Status, error) {
	claims, err := Verify(raw, m.publicKey)
	if err != nil {
		return Status{}, err
	}
	if claims.DeviceID != m.deviceID {
		return Status{}, errors.New("License 设备指纹不匹配")
	}
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Status{}, err
	}
	normalized, _ := json.MarshalIndent(envelope, "", "  ")
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, normalized, 0o600); err != nil {
		return Status{}, err
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return Status{}, err
	}
	_ = m.RecordRemoteValidation(claims.LicenseID, false, "")
	return m.Status(time.Now()), nil
}

func (m *Manager) RecordRemoteValidation(licenseID string, revoked bool, reason string) error {
	if licenseID == "" {
		return errors.New("License ID 不能为空")
	}
	raw, err := json.MarshalIndent(map[string]any{"license_id": licenseID, "revoked": revoked, "reason": reason, "checked_at": time.Now().UTC()}, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.remotePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.remotePath)
}

func Verify(raw []byte, publicKey ed25519.PublicKey) (Claims, error) {
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Claims{}, errors.New("License 文件格式无效")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return Claims{}, errors.New("License payload 无效")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return Claims{}, errors.New("License 数字签名无效")
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, errors.New("License 声明无效")
	}
	if claims.LicenseID == "" || claims.DeviceID == "" || claims.Edition == "" {
		return Claims{}, errors.New("License 缺少必要字段")
	}
	return claims, nil
}

func Sign(claims Claims, privateKey ed25519.PrivateKey) ([]byte, error) {
	if claims.LicenseID == "" || claims.DeviceID == "" || claims.Edition == "" || claims.MaxUsers <= 0 {
		return nil, errors.New("License 参数不完整")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	signature, err := privateKey.Sign(nil, payload, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(Envelope{Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(signature)}, "", "  ")
}

func LoadPrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("无法解析 Ed25519 私钥")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("私钥不是 Ed25519")
	}
	return privateKey, nil
}

func parsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("无法解析 License 公钥")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("License 公钥类型无效: %T", key)
	}
	return publicKey, nil
}

func HasFeature(status Status, feature string) bool {
	for _, value := range status.Features {
		if strings.EqualFold(value, feature) || value == "*" {
			return true
		}
	}
	return false
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
