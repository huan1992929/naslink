package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"naslink/internal/config"
	"naslink/internal/dingtalk"
	appstate "naslink/internal/state"
	"naslink/internal/wecom"
)

const weComLoginCookie = "naslink_wecom_login"

type pendingAuthorization struct {
	SourceType  string
	ClientID    string
	RedirectURI string
	State       string
	Nonce       string
	CreatedAt   time.Time
}

type codeGrant struct {
	ClientID    string
	RedirectURI string
	Subject     string
	Username    string
	DisplayName string
	Email       string
	Nonce       string
	CreatedAt   time.Time
}

type driveLaunch struct {
	CreatedAt time.Time
}

type loginTicket struct {
	Subject   string
	Name      string
	Email     string
	CreatedAt time.Time
}

type userInfo struct {
	Subject     string `json:"sub"`
	Username    string `json:"username"`
	DisplayName string `json:"name,omitempty"`
	Email       string `json:"email,omitempty"`
}

type Provider struct {
	manager *config.Manager
	store   *appstate.Store
	key     *rsa.PrivateKey
	kid     string

	mu       sync.Mutex
	pending  map[string]pendingAuthorization
	launches map[string]driveLaunch
	tickets  map[string]loginTicket
	codes    map[string]codeGrant
	tokens   map[string]struct {
		User      userInfo
		ExpiresAt time.Time
	}
}

func NewProvider(manager *config.Manager, store *appstate.Store, dataDir string) (*Provider, error) {
	key, err := loadOrCreateKey(filepath.Join(dataDir, "oidc-private.pem"))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	return &Provider{
		manager: manager, store: store, key: key, kid: base64.RawURLEncoding.EncodeToString(digest[:8]),
		pending: map[string]pendingAuthorization{}, launches: map[string]driveLaunch{}, tickets: map[string]loginTicket{}, codes: map[string]codeGrant{},
		tokens: map[string]struct {
			User      userInfo
			ExpiresAt time.Time
		}{},
	}, nil
}

func (p *Provider) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /oidc/jwks.json", p.jwks)
	mux.HandleFunc("GET /oidc/authorize", p.authorize)
	mux.HandleFunc("GET /launch/wecom/drive", p.launchWeComDrive)
	mux.HandleFunc("GET /auth/dingtalk/callback", p.dingTalkCallback)
	mux.HandleFunc("GET /auth/wecom/callback", p.weComCallback)
	mux.HandleFunc("GET /auth/wecom/drive/callback", p.weComDriveCallback)
	mux.HandleFunc("POST /oidc/token", p.token)
	mux.HandleFunc("GET /oidc/userinfo", p.userinfo)
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	settings, err := p.manager.OIDCCredentials()
	if err != nil || settings.Issuer == "" {
		oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "OIDC 尚未配置")
		return
	}
	issuer := strings.TrimRight(settings.Issuer, "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oidc/authorize",
		"token_endpoint":                        issuer + "/oidc/token",
		"userinfo_endpoint":                     issuer + "/oidc/userinfo",
		"jwks_uri":                              issuer + "/oidc/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nonce", "username", "preferred_username", "name", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes())
	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(p.key.PublicKey.E))
	eBytes = bytesTrimLeftZero(eBytes)
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": p.kid,
		"n": n, "e": base64.RawURLEncoding.EncodeToString(eBytes),
	}}})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	settings, err := p.manager.OIDCCredentials()
	if err != nil {
		oidcError(w, http.StatusServiceUnavailable, "server_error", "无法读取 OIDC 配置")
		return
	}
	query := r.URL.Query()
	if query.Get("response_type") != "code" {
		oidcError(w, http.StatusBadRequest, "unsupported_response_type", "仅支持 authorization code")
		return
	}
	if query.Get("client_id") != settings.ClientID || settings.ClientID == "" {
		oidcError(w, http.StatusBadRequest, "unauthorized_client", "未知 OIDC Client")
		return
	}
	redirectURI := query.Get("redirect_uri")
	if !contains(settings.RedirectURIs, redirectURI) {
		oidcError(w, http.StatusBadRequest, "invalid_request", "redirect_uri 未登记")
		return
	}
	if !scopeContains(query.Get("scope"), "openid") {
		oidcError(w, http.StatusBadRequest, "invalid_scope", "scope 必须包含 openid")
		return
	}
	sourceType := p.manager.ActiveIdentitySource()
	tx := pendingAuthorization{
		SourceType: sourceType,
		ClientID:   settings.ClientID, RedirectURI: redirectURI, State: query.Get("state"),
		Nonce: query.Get("nonce"), CreatedAt: time.Now(),
	}
	issuer := strings.TrimRight(settings.Issuer, "/")
	if sourceType == "wecom" {
		if ticket, ok := p.takeLoginTicket(r); ok {
			p.clearLoginTicketCookie(w, r)
			p.completeLogin(w, r, tx, "wecom", ticket.Subject, ticket.Name, ticket.Email)
			return
		}
		cfg, cfgErr := p.manager.WeComCredentials()
		if cfgErr != nil {
			oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable", cfgErr.Error())
			return
		}
		client, cfgErr := wecom.New(wecom.Config{CorpID: cfg.CorpID, AgentID: cfg.AgentID, Secret: cfg.Secret, AuthURL: cfg.AuthURL, InAppAuthURL: cfg.InAppAuthURL, APIBaseURL: cfg.APIBaseURL})
		if cfgErr != nil {
			oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable", cfgErr.Error())
			return
		}
		txID, createErr := p.saveTransaction(tx)
		if createErr != nil {
			oidcError(w, http.StatusInternalServerError, "server_error", "无法创建登录事务")
			return
		}
		callback := issuer + "/auth/wecom/callback"
		if wecom.IsInAppBrowser(r.UserAgent()) {
			http.Redirect(w, r, client.InAppAuthorizationURL(callback, txID), http.StatusFound)
		} else {
			http.Redirect(w, r, client.QRAuthorizationURL(callback, txID), http.StatusFound)
		}
		return
	}
	cfg, cfgErr := p.manager.DingTalkCredentials()
	if cfgErr != nil {
		oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable", cfgErr.Error())
		return
	}
	client, cfgErr := dingtalk.New(dingtalk.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, AuthURL: cfg.AuthURL, APIBaseURL: cfg.APIBaseURL})
	if cfgErr != nil {
		oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable", cfgErr.Error())
		return
	}
	txID, createErr := p.saveTransaction(tx)
	if createErr != nil {
		oidcError(w, http.StatusInternalServerError, "server_error", "无法创建登录事务")
		return
	}
	http.Redirect(w, r, client.AuthorizationURL(issuer+"/auth/dingtalk/callback", txID), http.StatusFound)
}

func (p *Provider) saveTransaction(tx pendingAuthorization) (string, error) {
	txID, err := randomToken(32)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupLocked(time.Now())
	p.pending[txID] = tx
	return txID, nil
}

func (p *Provider) launchWeComDrive(w http.ResponseWriter, r *http.Request) {
	if p.manager.ActiveIdentitySource() != "wecom" {
		renderError(w, "企业微信免登入口未启用", "请管理员先在 NASLink 中将主身份源切换为企业微信。")
		return
	}
	oidcSettings, err := p.manager.OIDCCredentials()
	if err != nil || strings.TrimSpace(oidcSettings.Issuer) == "" {
		renderError(w, "OIDC 尚未配置", "请管理员先配置 NASLink Issuer 公共地址。")
		return
	}
	cfg, err := p.manager.WeComCredentials()
	if err != nil {
		renderError(w, "读取企业微信配置失败", err.Error())
		return
	}
	if _, err := safeDriveURL(cfg.DriveWebURL); err != nil {
		renderError(w, "Synology Drive 入口尚未配置", err.Error())
		return
	}
	client, err := wecom.New(wecom.Config{CorpID: cfg.CorpID, AgentID: cfg.AgentID, Secret: cfg.Secret, AuthURL: cfg.AuthURL, InAppAuthURL: cfg.InAppAuthURL, APIBaseURL: cfg.APIBaseURL})
	if err != nil {
		renderError(w, "企业微信配置无效", err.Error())
		return
	}
	state, err := randomToken(32)
	if err != nil {
		renderError(w, "创建免登事务失败", "请稍后重试。")
		return
	}
	p.mu.Lock()
	p.cleanupLocked(time.Now())
	p.launches[state] = driveLaunch{CreatedAt: time.Now()}
	p.mu.Unlock()
	callback := strings.TrimRight(oidcSettings.Issuer, "/") + "/auth/wecom/drive/callback"
	http.Redirect(w, r, client.InAppAuthorizationURL(callback, state), http.StatusFound)
}

func (p *Provider) weComDriveCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	p.mu.Lock()
	launch, ok := p.launches[state]
	delete(p.launches, state)
	p.mu.Unlock()
	if !ok || time.Since(launch.CreatedAt) > 10*time.Minute {
		renderError(w, "企业微信免登请求已过期", "请返回企业微信工作台，重新打开企业网盘。")
		return
	}
	if remoteError := r.URL.Query().Get("error"); remoteError != "" {
		renderError(w, "企业微信未完成授权", remoteError)
		return
	}
	cfg, err := p.manager.WeComCredentials()
	if err != nil {
		renderError(w, "读取企业微信配置失败", err.Error())
		return
	}
	driveURL, err := safeDriveURL(cfg.DriveWebURL)
	if err != nil {
		renderError(w, "Synology Drive 入口无效", err.Error())
		return
	}
	client, err := wecom.New(wecom.Config{CorpID: cfg.CorpID, AgentID: cfg.AgentID, Secret: cfg.Secret, AuthURL: cfg.AuthURL, InAppAuthURL: cfg.InAppAuthURL, APIBaseURL: cfg.APIBaseURL})
	if err != nil {
		renderError(w, "企业微信配置无效", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	user, err := client.ExchangeCode(ctx, r.URL.Query().Get("code"))
	if err != nil {
		p.audit("wecom_drive_launch", "", false, map[string]any{"error": err.Error()})
		renderError(w, "企业微信身份验证失败", err.Error())
		return
	}
	if _, err := p.eligibleBinding("wecom", user.Subject()); err != nil {
		p.audit("wecom_drive_launch", user.Subject(), false, map[string]any{"error": err.Error()})
		renderError(w, "无法进入企业网盘", err.Error())
		return
	}
	ticketID, err := randomToken(32)
	if err != nil {
		renderError(w, "创建免登票据失败", "请稍后重试。")
		return
	}
	p.mu.Lock()
	p.cleanupLocked(time.Now())
	p.tickets[ticketID] = loginTicket{Subject: user.Subject(), Name: user.Name, Email: user.Email, CreatedAt: time.Now()}
	p.mu.Unlock()
	p.setLoginTicketCookie(w, r, ticketID)
	p.audit("wecom_drive_launch", user.Subject(), true, map[string]any{"target": driveURL.String()})
	http.Redirect(w, r, driveURL.String(), http.StatusFound)
}

func (p *Provider) dingTalkCallback(w http.ResponseWriter, r *http.Request) {
	tx, ok := p.takeTransaction(r.URL.Query().Get("state"), "dingtalk")
	if !ok {
		renderError(w, "登录请求已过期", "请从 DSM 登录页重新选择 SSO 登录。")
		return
	}
	if remoteError := r.URL.Query().Get("error"); remoteError != "" {
		renderError(w, "钉钉取消了授权", remoteError)
		return
	}
	dingCfg, err := p.manager.DingTalkCredentials()
	if err != nil {
		renderError(w, "读取钉钉配置失败", err.Error())
		return
	}
	ding, err := dingtalk.New(dingtalk.Config{ClientID: dingCfg.ClientID, ClientSecret: dingCfg.ClientSecret, AuthURL: dingCfg.AuthURL, APIBaseURL: dingCfg.APIBaseURL})
	if err != nil {
		renderError(w, "钉钉配置无效", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	user, err := ding.ExchangeCode(ctx, r.URL.Query().Get("code"))
	if err != nil {
		renderError(w, "钉钉身份验证失败", err.Error())
		return
	}
	p.completeLogin(w, r, tx, "dingtalk", user.Subject(), user.Nick, user.Email)
}

func (p *Provider) weComCallback(w http.ResponseWriter, r *http.Request) {
	tx, ok := p.takeTransaction(r.URL.Query().Get("state"), "wecom")
	if !ok {
		renderError(w, "登录请求已过期", "请从 DSM 登录页重新选择 SSO 登录。")
		return
	}
	cfg, err := p.manager.WeComCredentials()
	if err != nil {
		renderError(w, "读取企业微信配置失败", err.Error())
		return
	}
	client, err := wecom.New(wecom.Config{CorpID: cfg.CorpID, AgentID: cfg.AgentID, Secret: cfg.Secret, AuthURL: cfg.AuthURL, InAppAuthURL: cfg.InAppAuthURL, APIBaseURL: cfg.APIBaseURL})
	if err != nil {
		renderError(w, "企业微信配置无效", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	user, err := client.ExchangeCode(ctx, r.URL.Query().Get("code"))
	if err != nil {
		renderError(w, "企业微信身份验证失败", err.Error())
		return
	}
	p.completeLogin(w, r, tx, "wecom", user.Subject(), user.Name, user.Email)
}

func (p *Provider) takeTransaction(txID, sourceType string) (pendingAuthorization, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tx, ok := p.pending[txID]
	delete(p.pending, txID)
	return tx, ok && tx.SourceType == sourceType && time.Since(tx.CreatedAt) <= 10*time.Minute
}

func (p *Provider) completeLogin(w http.ResponseWriter, r *http.Request, tx pendingAuthorization, sourceType, subject, name, email string) {
	binding, err := p.eligibleBinding(sourceType, subject)
	if err != nil {
		p.audit("oidc_login", subject, false, map[string]any{"source_type": sourceType, "error": err.Error()})
		renderError(w, "账号无法登录", err.Error())
		return
	}
	code, err := randomToken(32)
	if err != nil {
		renderError(w, "创建登录凭证失败", "请稍后重试")
		return
	}
	p.mu.Lock()
	p.codes[code] = codeGrant{ClientID: tx.ClientID, RedirectURI: tx.RedirectURI, Subject: sourceType + ":" + subject, Username: binding.DSMUsername, DisplayName: valueOr(binding.DisplayName, name), Email: valueOr(binding.Email, email), Nonce: tx.Nonce, CreatedAt: time.Now()}
	p.mu.Unlock()
	p.audit("oidc_login", subject, true, map[string]any{"source_type": sourceType, "dsm_username": binding.DSMUsername})
	redirect, _ := url.Parse(tx.RedirectURI)
	query := redirect.Query()
	query.Set("code", code)
	if tx.State != "" {
		query.Set("state", tx.State)
	}
	redirect.RawQuery = query.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *Provider) eligibleBinding(sourceType, subject string) (config.Binding, error) {
	binding, found := p.manager.FindBinding(sourceType, subject)
	if !found {
		return config.Binding{}, fmt.Errorf("%s 标识 %s 尚未绑定 DSM 账号，请管理员在 NASLink 中确认", sourceLabel(sourceType), subject)
	}
	if p.store == nil {
		return binding, nil
	}
	snapshot := p.store.Snapshot()
	hasSourceDirectory := false
	for _, user := range snapshot.Users {
		userSource := user.SourceType
		if userSource == "" {
			userSource = "dingtalk"
		}
		if userSource != sourceType {
			continue
		}
		hasSourceDirectory = true
		if user.Subject != subject {
			continue
		}
		if !user.Active {
			return config.Binding{}, fmt.Errorf("员工 %s 已停用或离职，NASLink 已拒绝登录", valueOr(user.Name, subject))
		}
		return binding, nil
	}
	if !hasSourceDirectory {
		return config.Binding{}, fmt.Errorf("尚未同步%s通讯录，请管理员先完成通讯录同步", sourceLabel(sourceType))
	}
	return config.Binding{}, fmt.Errorf("该员工已不在当前%s通讯录中，请管理员核对人员状态", sourceLabel(sourceType))
}

func sourceLabel(sourceType string) string {
	if sourceType == "wecom" {
		return "企业微信"
	}
	return "钉钉"
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oidcError(w, http.StatusBadRequest, "invalid_request", "请求体无效")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		oidcError(w, http.StatusBadRequest, "unsupported_grant_type", "仅支持 authorization_code")
		return
	}
	settings, err := p.manager.OIDCCredentials()
	if err != nil {
		oidcError(w, http.StatusServiceUnavailable, "server_error", "无法读取 OIDC 配置")
		return
	}
	clientID, clientSecret := r.Form.Get("client_id"), r.Form.Get("client_secret")
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		clientID, clientSecret = basicID, basicSecret
	}
	if !constantEqual(clientID, settings.ClientID) || !constantEqual(clientSecret, settings.ClientSecret) {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc-token"`)
		oidcError(w, http.StatusUnauthorized, "invalid_client", "Client 凭据无效")
		return
	}
	code := r.Form.Get("code")
	p.mu.Lock()
	grant, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	if !ok || time.Since(grant.CreatedAt) > 5*time.Minute {
		oidcError(w, http.StatusBadRequest, "invalid_grant", "授权码无效或已使用")
		return
	}
	if grant.ClientID != clientID || grant.RedirectURI != r.Form.Get("redirect_uri") {
		oidcError(w, http.StatusBadRequest, "invalid_grant", "授权码与 Client 或 redirect_uri 不匹配")
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": settings.Issuer, "sub": grant.Subject, "aud": clientID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": grant.CreatedAt.Unix(),
		"username": grant.Username, "preferred_username": grant.Username,
		"name": grant.DisplayName, "email": grant.Email,
	}
	if grant.Nonce != "" {
		claims["nonce"] = grant.Nonce
	}
	idToken, err := p.signJWT(claims)
	if err != nil {
		oidcError(w, http.StatusInternalServerError, "server_error", "签发 ID Token 失败")
		return
	}
	accessToken, err := randomToken(32)
	if err != nil {
		oidcError(w, http.StatusInternalServerError, "server_error", "签发 Access Token 失败")
		return
	}
	p.mu.Lock()
	p.tokens[accessToken] = struct {
		User      userInfo
		ExpiresAt time.Time
	}{
		User:      userInfo{Subject: grant.Subject, Username: grant.Username, DisplayName: grant.DisplayName, Email: grant.Email},
		ExpiresAt: now.Add(5 * time.Minute),
	}
	p.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken, "token_type": "Bearer", "expires_in": 300,
		"scope": "openid profile email", "id_token": idToken,
	})
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
		oidcError(w, http.StatusUnauthorized, "invalid_token", "缺少 Bearer token")
		return
	}
	token := strings.TrimSpace(authorization[len("Bearer "):])
	p.mu.Lock()
	stored, ok := p.tokens[token]
	if ok && time.Now().After(stored.ExpiresAt) {
		delete(p.tokens, token)
		ok = false
	}
	p.mu.Unlock()
	if !ok {
		oidcError(w, http.StatusUnauthorized, "invalid_token", "Access token 无效或已过期")
		return
	}
	writeJSON(w, http.StatusOK, stored.User)
}

func (p *Provider) signJWT(claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": p.kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	unsigned := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func loadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("OIDC private key PEM is invalid")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("OIDC private key is not RSA")
		}
		return rsaKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func safeDriveURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil {
		return nil, errors.New("请在 NASLink 中填写完整的 Synology Drive Web http(s) 地址")
	}
	return parsed, nil
}

func (p *Provider) takeLoginTicket(r *http.Request) (loginTicket, bool) {
	cookie, err := r.Cookie(weComLoginCookie)
	if err != nil || cookie.Value == "" {
		return loginTicket{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ticket, ok := p.tickets[cookie.Value]
	delete(p.tickets, cookie.Value)
	return ticket, ok && time.Since(ticket.CreatedAt) <= 5*time.Minute
}

func (p *Provider) setLoginTicketCookie(w http.ResponseWriter, r *http.Request, ticketID string) {
	secure := r.TLS != nil
	if settings, err := p.manager.OIDCCredentials(); err == nil && strings.HasPrefix(strings.ToLower(settings.Issuer), "https://") {
		secure = true
	}
	http.SetCookie(w, &http.Cookie{
		Name: weComLoginCookie, Value: ticketID, Path: "/", MaxAge: 300,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

func (p *Provider) clearLoginTicketCookie(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil
	if settings, err := p.manager.OIDCCredentials(); err == nil && strings.HasPrefix(strings.ToLower(settings.Issuer), "https://") {
		secure = true
	}
	http.SetCookie(w, &http.Cookie{Name: weComLoginCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

func (p *Provider) audit(action, target string, success bool, metadata map[string]any) {
	if p.store == nil {
		return
	}
	_ = p.store.AddAudit(appstate.AuditEvent{Actor: "identity-gateway", Action: action, Target: target, Success: success, Metadata: metadata})
}

func (p *Provider) cleanupLocked(now time.Time) {
	for id, tx := range p.pending {
		if now.Sub(tx.CreatedAt) > 10*time.Minute {
			delete(p.pending, id)
		}
	}
	for code, grant := range p.codes {
		if now.Sub(grant.CreatedAt) > 5*time.Minute {
			delete(p.codes, code)
		}
	}
	for id, launch := range p.launches {
		if now.Sub(launch.CreatedAt) > 10*time.Minute {
			delete(p.launches, id)
		}
	}
	for id, ticket := range p.tickets {
		if now.Sub(ticket.CreatedAt) > 5*time.Minute {
			delete(p.tickets, id)
		}
	}
	for token, stored := range p.tokens {
		if now.After(stored.ExpiresAt) {
			delete(p.tokens, token)
		}
	}
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func constantEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func scopeContains(scope, target string) bool {
	for _, item := range strings.Fields(scope) {
		if item == target {
			return true
		}
	}
	return false
}

func bytesTrimLeftZero(value []byte) []byte {
	return new(big.Int).SetBytes(value).Bytes()
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func oidcError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

var errorPage = template.Must(template.New("error").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{{.Title}}</title><style>body{margin:0;background:#0e1618;color:#e9f0ec;font:16px/1.7 ui-sans-serif,sans-serif;display:grid;min-height:100vh;place-items:center}.card{width:min(560px,calc(100% - 48px));padding:40px;border:1px solid #2b3a3d;background:#142124;box-shadow:0 30px 80px #0007}.mark{color:#f0a94b;font-size:13px;letter-spacing:.18em;text-transform:uppercase}h1{font-size:30px;margin:10px 0}p{color:#aebcba;word-break:break-word}</style><main class="card"><div class="mark">NASLink identity gate</div><h1>{{.Title}}</h1><p>{{.Detail}}</p></main></html>`))

func renderError(w http.ResponseWriter, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	errorPage.Execute(w, map[string]string{"Title": title, "Detail": detail})
}
