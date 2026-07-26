package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const passwordIterations = 210_000

type DSM struct {
	BaseURL        string `json:"base_url"`
	Account        string `json:"account"`
	Password       string `json:"password_encrypted,omitempty"`
	InsecureTLS    bool   `json:"insecure_tls"`
	MutationPrefix string `json:"mutation_prefix"`
}

type DingTalk struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret_encrypted,omitempty"`
	AuthURL      string `json:"auth_url"`
	APIBaseURL   string `json:"api_base_url"`
	EventToken   string `json:"event_token_encrypted,omitempty"`
}

type WeCom struct {
	CorpID         string `json:"corp_id"`
	AgentID        string `json:"agent_id"`
	Secret         string `json:"secret_encrypted,omitempty"`
	AuthURL        string `json:"auth_url"` // Desktop QR authorization.
	InAppAuthURL   string `json:"in_app_auth_url"`
	DriveWebURL    string `json:"drive_web_url"`
	APIBaseURL     string `json:"api_base_url"`
	CallbackToken  string `json:"callback_token_encrypted,omitempty"`
	CallbackAESKey string `json:"callback_aes_key_encrypted,omitempty"`
}

type LicenseCenter struct {
	URL            string `json:"url"`
	ActivationCode string `json:"activation_code_encrypted,omitempty"`
}

type OIDC struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret_encrypted,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}

type Binding struct {
	SourceType      string    `json:"source_type,omitempty"`
	SourceSubject   string    `json:"source_subject,omitempty"`
	DingTalkSubject string    `json:"dingtalk_subject,omitempty"` // v1 migration compatibility
	DSMUsername     string    `json:"dsm_username"`
	DisplayName     string    `json:"display_name,omitempty"`
	Email           string    `json:"email,omitempty"`
	ConfirmedAt     time.Time `json:"confirmed_at"`
}

type Settings struct {
	Version           int           `json:"version"`
	AdminPasswordHash string        `json:"admin_password_hash,omitempty"`
	AdminSalt         string        `json:"admin_salt,omitempty"`
	DSM               DSM           `json:"dsm"`
	IdentitySource    string        `json:"identity_source"`
	DingTalk          DingTalk      `json:"dingtalk"`
	WeCom             WeCom         `json:"wecom"`
	OIDC              OIDC          `json:"oidc"`
	LicenseCenter     LicenseCenter `json:"license_center"`
	Bindings          []Binding     `json:"bindings"`
}

type PublicSettings struct {
	SetupComplete  bool                `json:"setup_complete"`
	DSM            PublicDSM           `json:"dsm"`
	IdentitySource string              `json:"identity_source"`
	DingTalk       PublicDingTalk      `json:"dingtalk"`
	WeCom          PublicWeCom         `json:"wecom"`
	OIDC           PublicOIDC          `json:"oidc"`
	LicenseCenter  PublicLicenseCenter `json:"license_center"`
	Bindings       []Binding           `json:"bindings"`
}

type PublicDSM struct {
	BaseURL        string `json:"base_url"`
	Account        string `json:"account"`
	HasPassword    bool   `json:"has_password"`
	InsecureTLS    bool   `json:"insecure_tls"`
	MutationPrefix string `json:"mutation_prefix"`
}

type PublicDingTalk struct {
	ClientID        string `json:"client_id"`
	HasClientSecret bool   `json:"has_client_secret"`
	AuthURL         string `json:"auth_url"`
	APIBaseURL      string `json:"api_base_url"`
	HasEventToken   bool   `json:"has_event_token"`
}

type PublicWeCom struct {
	CorpID            string `json:"corp_id"`
	AgentID           string `json:"agent_id"`
	HasSecret         bool   `json:"has_secret"`
	AuthURL           string `json:"auth_url"`
	InAppAuthURL      string `json:"in_app_auth_url"`
	DriveWebURL       string `json:"drive_web_url"`
	LaunchURL         string `json:"launch_url,omitempty"`
	APIBaseURL        string `json:"api_base_url"`
	HasCallbackToken  bool   `json:"has_callback_token"`
	HasCallbackAESKey bool   `json:"has_callback_aes_key"`
}

type PublicLicenseCenter struct {
	URL               string `json:"url"`
	HasActivationCode bool   `json:"has_activation_code"`
}

type PublicOIDC struct {
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	HasClientSecret bool     `json:"has_client_secret"`
	RedirectURIs    []string `json:"redirect_uris"`
	DiscoveryURL    string   `json:"discovery_url,omitempty"`
}

type Update struct {
	IdentitySource string `json:"identity_source"`
	DSM            struct {
		BaseURL        string `json:"base_url"`
		Account        string `json:"account"`
		Password       string `json:"password"`
		InsecureTLS    bool   `json:"insecure_tls"`
		MutationPrefix string `json:"mutation_prefix"`
	} `json:"dsm"`
	DingTalk struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		AuthURL      string `json:"auth_url"`
		APIBaseURL   string `json:"api_base_url"`
		EventToken   string `json:"event_token"`
	} `json:"dingtalk"`
	WeCom struct {
		CorpID         string `json:"corp_id"`
		AgentID        string `json:"agent_id"`
		Secret         string `json:"secret"`
		AuthURL        string `json:"auth_url"`
		InAppAuthURL   string `json:"in_app_auth_url"`
		DriveWebURL    string `json:"drive_web_url"`
		APIBaseURL     string `json:"api_base_url"`
		CallbackToken  string `json:"callback_token"`
		CallbackAESKey string `json:"callback_aes_key"`
	} `json:"wecom"`
	OIDC struct {
		Issuer       string   `json:"issuer"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
	} `json:"oidc"`
	LicenseCenter struct {
		URL            string `json:"url"`
		ActivationCode string `json:"activation_code"`
	} `json:"license_center"`
}

type Manager struct {
	mu       sync.RWMutex
	path     string
	keyPath  string
	key      []byte
	settings Settings
}

func NewManager(dataDir string) (*Manager, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	m := &Manager{
		path:    filepath.Join(dataDir, "config.json"),
		keyPath: filepath.Join(dataDir, "secrets.key"),
	}
	if err := m.loadKey(); err != nil {
		return nil, err
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) loadKey() error {
	key, err := os.ReadFile(m.keyPath)
	if err == nil {
		if len(key) != 32 {
			return errors.New("invalid secrets.key length")
		}
		m.key = key
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read encryption key: %w", err)
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generate encryption key: %w", err)
	}
	if err := os.WriteFile(m.keyPath, key, 0o600); err != nil {
		return fmt.Errorf("write encryption key: %w", err)
	}
	m.key = key
	return nil
}

func (m *Manager) load() error {
	raw, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		m.settings = defaults()
		return m.saveLocked()
	}
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(raw, &m.settings); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	if m.settings.DSM.MutationPrefix == "" {
		m.settings.DSM.MutationPrefix = "naslink_poc_"
	}
	if m.settings.DSM.BaseURL == "" {
		m.settings.DSM.BaseURL = "https://127.0.0.1:5001"
		m.settings.DSM.InsecureTLS = true
	}
	if m.settings.IdentitySource == "" {
		m.settings.IdentitySource = "dingtalk"
	}
	if m.settings.WeCom.AuthURL == "" {
		m.settings.WeCom.AuthURL = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"
	}
	if m.settings.WeCom.InAppAuthURL == "" {
		m.settings.WeCom.InAppAuthURL = "https://open.weixin.qq.com/connect/oauth2/authorize"
	}
	if m.settings.WeCom.APIBaseURL == "" {
		m.settings.WeCom.APIBaseURL = "https://qyapi.weixin.qq.com"
	}
	if m.settings.Version < 3 {
		m.settings.Version = 3
	}
	for i := range m.settings.Bindings {
		m.settings.Bindings[i].normalize()
	}
	return nil
}

func defaults() Settings {
	return Settings{
		Version:        3,
		IdentitySource: "dingtalk",
		DSM:            DSM{BaseURL: "https://127.0.0.1:5001", InsecureTLS: true, MutationPrefix: "naslink_poc_"},
		DingTalk: DingTalk{
			AuthURL:    "https://login.dingtalk.com/oauth2/auth",
			APIBaseURL: "https://api.dingtalk.com",
		},
		WeCom: WeCom{AuthURL: "https://open.work.weixin.qq.com/wwopen/sso/qrConnect", InAppAuthURL: "https://open.weixin.qq.com/connect/oauth2/authorize", APIBaseURL: "https://qyapi.weixin.qq.com"},
	}
}

func (m *Manager) saveLocked() error {
	raw, err := json.MarshalIndent(m.settings, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

func (m *Manager) IsSetup() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.settings.AdminPasswordHash != ""
}

func (m *Manager) SetupAdmin(password string) error {
	if len(password) < 12 {
		return errors.New("管理员密码至少需要 12 个字符")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.settings.AdminPasswordHash != "" {
		return errors.New("管理员已经初始化")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	hash := derivePassword([]byte(password), salt, passwordIterations, 32)
	m.settings.AdminSalt = hex.EncodeToString(salt)
	m.settings.AdminPasswordHash = hex.EncodeToString(hash)
	return m.saveLocked()
}

func (m *Manager) VerifyAdmin(password string) bool {
	m.mu.RLock()
	saltHex := m.settings.AdminSalt
	hashHex := m.settings.AdminPasswordHash
	m.mu.RUnlock()
	if saltHex == "" || hashHex == "" {
		return false
	}
	salt, err1 := hex.DecodeString(saltHex)
	want, err2 := hex.DecodeString(hashHex)
	if err1 != nil || err2 != nil {
		return false
	}
	got := derivePassword([]byte(password), salt, passwordIterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func derivePassword(password, salt []byte, iterations, length int) []byte {
	hLen := sha256.Size
	blocks := (length + hLen - 1) / hLen
	result := make([]byte, 0, blocks*hLen)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:length]
}

func (m *Manager) Public() PublicSettings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.settings
	discovery := ""
	launchURL := ""
	if s.OIDC.Issuer != "" {
		discovery = strings.TrimRight(s.OIDC.Issuer, "/") + "/.well-known/openid-configuration"
		launchURL = strings.TrimRight(s.OIDC.Issuer, "/") + "/launch/wecom/drive"
	}
	return PublicSettings{
		SetupComplete:  s.AdminPasswordHash != "",
		IdentitySource: s.IdentitySource,
		DSM: PublicDSM{
			BaseURL: s.DSM.BaseURL, Account: s.DSM.Account,
			HasPassword: s.DSM.Password != "", InsecureTLS: s.DSM.InsecureTLS,
			MutationPrefix: s.DSM.MutationPrefix,
		},
		DingTalk: PublicDingTalk{
			ClientID: s.DingTalk.ClientID, HasClientSecret: s.DingTalk.ClientSecret != "",
			AuthURL: s.DingTalk.AuthURL, APIBaseURL: s.DingTalk.APIBaseURL,
			HasEventToken: s.DingTalk.EventToken != "",
		},
		WeCom: PublicWeCom{CorpID: s.WeCom.CorpID, AgentID: s.WeCom.AgentID, HasSecret: s.WeCom.Secret != "", AuthURL: s.WeCom.AuthURL, InAppAuthURL: s.WeCom.InAppAuthURL, DriveWebURL: s.WeCom.DriveWebURL, LaunchURL: launchURL, APIBaseURL: s.WeCom.APIBaseURL, HasCallbackToken: s.WeCom.CallbackToken != "", HasCallbackAESKey: s.WeCom.CallbackAESKey != ""},
		OIDC: PublicOIDC{
			Issuer: s.OIDC.Issuer, ClientID: s.OIDC.ClientID,
			HasClientSecret: s.OIDC.ClientSecret != "", RedirectURIs: append([]string(nil), s.OIDC.RedirectURIs...),
			DiscoveryURL: discovery,
		},
		LicenseCenter: PublicLicenseCenter{URL: s.LicenseCenter.URL, HasActivationCode: s.LicenseCenter.ActivationCode != ""},
		Bindings:      append([]Binding(nil), s.Bindings...),
	}
}

func (m *Manager) Update(update Update) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if update.DSM.MutationPrefix == "" || !strings.HasSuffix(update.DSM.MutationPrefix, "_") {
		return errors.New("UAT 安全前缀不能为空且必须以下划线结尾")
	}
	if update.IdentitySource == "" {
		update.IdentitySource = m.settings.IdentitySource
	}
	if update.IdentitySource != "dingtalk" && update.IdentitySource != "wecom" {
		return errors.New("身份源必须是 dingtalk 或 wecom")
	}
	inAppAuthURL := valueOr(update.WeCom.InAppAuthURL, "https://open.weixin.qq.com/connect/oauth2/authorize")
	driveWebURL := strings.TrimSpace(update.WeCom.DriveWebURL)
	if err := validateOptionalHTTPURL(driveWebURL, "Synology Drive Web 地址"); err != nil {
		return err
	}
	if err := validateOptionalHTTPURL(inAppAuthURL, "企业微信应用内授权地址"); err != nil {
		return err
	}
	m.settings.DSM.BaseURL = strings.TrimRight(update.DSM.BaseURL, "/")
	m.settings.DSM.Account = update.DSM.Account
	m.settings.DSM.InsecureTLS = update.DSM.InsecureTLS
	m.settings.DSM.MutationPrefix = update.DSM.MutationPrefix
	m.settings.IdentitySource = update.IdentitySource
	m.settings.DingTalk.ClientID = update.DingTalk.ClientID
	m.settings.DingTalk.AuthURL = valueOr(update.DingTalk.AuthURL, "https://login.dingtalk.com/oauth2/auth")
	m.settings.DingTalk.APIBaseURL = strings.TrimRight(valueOr(update.DingTalk.APIBaseURL, "https://api.dingtalk.com"), "/")
	m.settings.WeCom.CorpID = strings.TrimSpace(update.WeCom.CorpID)
	m.settings.WeCom.AgentID = strings.TrimSpace(update.WeCom.AgentID)
	m.settings.WeCom.AuthURL = valueOr(update.WeCom.AuthURL, "https://open.work.weixin.qq.com/wwopen/sso/qrConnect")
	m.settings.WeCom.InAppAuthURL = inAppAuthURL
	m.settings.WeCom.DriveWebURL = driveWebURL
	m.settings.WeCom.APIBaseURL = strings.TrimRight(valueOr(update.WeCom.APIBaseURL, "https://qyapi.weixin.qq.com"), "/")
	m.settings.OIDC.Issuer = strings.TrimRight(update.OIDC.Issuer, "/")
	m.settings.OIDC.ClientID = update.OIDC.ClientID
	m.settings.OIDC.RedirectURIs = cleanStrings(update.OIDC.RedirectURIs)
	m.settings.LicenseCenter.URL = strings.TrimRight(strings.TrimSpace(update.LicenseCenter.URL), "/")
	var err error
	if update.DSM.Password != "" {
		m.settings.DSM.Password, err = m.encrypt(update.DSM.Password)
		if err != nil {
			return err
		}
	}
	if update.DingTalk.ClientSecret != "" {
		m.settings.DingTalk.ClientSecret, err = m.encrypt(update.DingTalk.ClientSecret)
		if err != nil {
			return err
		}
	}
	if update.DingTalk.EventToken != "" {
		m.settings.DingTalk.EventToken, err = m.encrypt(update.DingTalk.EventToken)
		if err != nil {
			return err
		}
	}
	if update.WeCom.Secret != "" {
		m.settings.WeCom.Secret, err = m.encrypt(update.WeCom.Secret)
		if err != nil {
			return err
		}
	}
	if update.WeCom.CallbackToken != "" {
		m.settings.WeCom.CallbackToken, err = m.encrypt(update.WeCom.CallbackToken)
		if err != nil {
			return err
		}
	}
	if update.WeCom.CallbackAESKey != "" {
		m.settings.WeCom.CallbackAESKey, err = m.encrypt(update.WeCom.CallbackAESKey)
		if err != nil {
			return err
		}
	}
	if update.OIDC.ClientSecret != "" {
		m.settings.OIDC.ClientSecret, err = m.encrypt(update.OIDC.ClientSecret)
		if err != nil {
			return err
		}
	}
	if update.LicenseCenter.ActivationCode != "" {
		m.settings.LicenseCenter.ActivationCode, err = m.encrypt(update.LicenseCenter.ActivationCode)
		if err != nil {
			return err
		}
	}
	return m.saveLocked()
}

// UpdateOnboardingDSM saves only the fields a first-time operator is asked to
// provide. Advanced settings remain untouched, and an empty password keeps a
// previously encrypted value rather than clearing it.
func (m *Manager) UpdateOnboardingDSM(baseURL, account, password string, insecureTLS bool) error {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	account = strings.TrimSpace(account)
	if err := validateOptionalHTTPURL(baseURL, "DSM 地址"); err != nil || baseURL == "" {
		if err != nil {
			return err
		}
		return errors.New("DSM 地址不能为空")
	}
	if account == "" {
		return errors.New("DSM 管理账号不能为空")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings.DSM.BaseURL = baseURL
	m.settings.DSM.Account = account
	m.settings.DSM.InsecureTLS = insecureTLS
	if password != "" {
		encoded, err := m.encrypt(password)
		if err != nil {
			return err
		}
		m.settings.DSM.Password = encoded
	}
	if m.settings.DSM.Password == "" {
		return errors.New("DSM 管理密码不能为空")
	}
	return m.saveLocked()
}

// UpdateOnboardingIdentity intentionally exposes just the required business
// credentials. Protocol endpoints and callback settings stay under Advanced
// Settings and are never reset by the setup wizard.
func (m *Manager) UpdateOnboardingIdentity(source, clientID, clientSecret, corpID, agentID, secret string) error {
	source = strings.TrimSpace(source)
	if source != "dingtalk" && source != "wecom" {
		return errors.New("身份源必须是 dingtalk 或 wecom")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings.IdentitySource = source
	if source == "dingtalk" {
		m.settings.DingTalk.ClientID = strings.TrimSpace(clientID)
		if clientSecret != "" {
			encoded, err := m.encrypt(clientSecret)
			if err != nil {
				return err
			}
			m.settings.DingTalk.ClientSecret = encoded
		}
		if m.settings.DingTalk.ClientID == "" || m.settings.DingTalk.ClientSecret == "" {
			return errors.New("请填写钉钉 Client ID 和 Client Secret")
		}
	} else {
		m.settings.WeCom.CorpID = strings.TrimSpace(corpID)
		m.settings.WeCom.AgentID = strings.TrimSpace(agentID)
		if secret != "" {
			encoded, err := m.encrypt(secret)
			if err != nil {
				return err
			}
			m.settings.WeCom.Secret = encoded
		}
		if m.settings.WeCom.CorpID == "" || m.settings.WeCom.AgentID == "" || m.settings.WeCom.Secret == "" {
			return errors.New("请填写企业微信 Corp ID、Agent ID 和 Secret")
		}
	}
	return m.saveLocked()
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func validateOptionalHTTPURL(value, label string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil {
		return fmt.Errorf("%s必须是完整的 http(s) 地址", label)
	}
	return nil
}

func (m *Manager) DSMCredentials() (DSM, error) {
	m.mu.RLock()
	dsm := m.settings.DSM
	m.mu.RUnlock()
	if dsm.Password != "" {
		plain, err := m.decrypt(dsm.Password)
		if err != nil {
			return DSM{}, err
		}
		dsm.Password = plain
	}
	return dsm, nil
}

func (m *Manager) DingTalkCredentials() (DingTalk, error) {
	m.mu.RLock()
	dt := m.settings.DingTalk
	m.mu.RUnlock()
	if dt.ClientSecret != "" {
		plain, err := m.decrypt(dt.ClientSecret)
		if err != nil {
			return DingTalk{}, err
		}
		dt.ClientSecret = plain
	}
	if dt.EventToken != "" {
		plain, err := m.decrypt(dt.EventToken)
		if err != nil {
			return DingTalk{}, err
		}
		dt.EventToken = plain
	}
	return dt, nil
}

func (m *Manager) WeComCredentials() (WeCom, error) {
	m.mu.RLock()
	wc := m.settings.WeCom
	m.mu.RUnlock()
	for target, value := range map[string]string{"secret": wc.Secret, "token": wc.CallbackToken, "aes": wc.CallbackAESKey} {
		if value == "" {
			continue
		}
		plain, err := m.decrypt(value)
		if err != nil {
			return WeCom{}, err
		}
		switch target {
		case "secret":
			wc.Secret = plain
		case "token":
			wc.CallbackToken = plain
		case "aes":
			wc.CallbackAESKey = plain
		}
	}
	return wc, nil
}

func (m *Manager) ActiveIdentitySource() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.settings.IdentitySource == "wecom" {
		return "wecom"
	}
	return "dingtalk"
}

func (m *Manager) LicenseCenterCredentials() (LicenseCenter, error) {
	m.mu.RLock()
	lc := m.settings.LicenseCenter
	m.mu.RUnlock()
	if lc.ActivationCode != "" {
		plain, err := m.decrypt(lc.ActivationCode)
		if err != nil {
			return LicenseCenter{}, err
		}
		lc.ActivationCode = plain
	}
	return lc, nil
}

func (m *Manager) OIDCCredentials() (OIDC, error) {
	m.mu.RLock()
	oidc := m.settings.OIDC
	m.mu.RUnlock()
	if oidc.ClientSecret != "" {
		plain, err := m.decrypt(oidc.ClientSecret)
		if err != nil {
			return OIDC{}, err
		}
		oidc.ClientSecret = plain
	}
	return oidc, nil
}

func (m *Manager) UpsertBinding(binding Binding) error {
	binding.normalize()
	if binding.SourceSubject == "" || binding.DSMUsername == "" {
		return errors.New("身份源稳定标识和 DSM 用户名均不能为空")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	binding.ConfirmedAt = time.Now().UTC()
	for i := range m.settings.Bindings {
		m.settings.Bindings[i].normalize()
		if m.settings.Bindings[i].SourceType == binding.SourceType && m.settings.Bindings[i].SourceSubject == binding.SourceSubject {
			m.settings.Bindings[i] = binding
			return m.saveLocked()
		}
	}
	m.settings.Bindings = append(m.settings.Bindings, binding)
	return m.saveLocked()
}

func (m *Manager) FindBinding(sourceType, subject string) (Binding, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, binding := range m.settings.Bindings {
		binding.normalize()
		if binding.SourceType == sourceType && binding.SourceSubject == subject {
			return binding, true
		}
	}
	return Binding{}, false
}

func (b *Binding) normalize() {
	if b.SourceSubject == "" && b.DingTalkSubject != "" {
		b.SourceSubject = b.DingTalkSubject
		b.SourceType = "dingtalk"
	}
	if b.SourceType == "" {
		b.SourceType = "dingtalk"
	}
	if b.SourceType == "dingtalk" && b.DingTalkSubject == "" {
		b.DingTalkSubject = b.SourceSubject
	}
}

func (m *Manager) encrypt(plain string) (string, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), []byte("naslink-config-v1"))
	return "enc:v1:" + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (m *Manager) decrypt(encoded string) (string, error) {
	if !strings.HasPrefix(encoded, "enc:v1:") {
		return "", errors.New("unsupported encrypted value")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, "enc:v1:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("encrypted value is truncated")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte("naslink-config-v1"))
	if err != nil {
		return "", errors.New("cannot decrypt stored secret")
	}
	return string(plain), nil
}
