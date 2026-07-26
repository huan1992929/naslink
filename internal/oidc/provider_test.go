package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"naslink/internal/config"
	appstate "naslink/internal/state"
)

func TestAuthorizationCodeFlow(t *testing.T) {
	ding := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1.0/oauth2/userAccessToken":
			json.NewEncoder(w).Encode(map[string]any{"accessToken": "token", "expireIn": 300})
		case "/v1.0/contact/users/me":
			json.NewEncoder(w).Encode(map[string]any{"openId": "open-1", "unionId": "union-1", "nick": "测试用户"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ding.Close()

	dataDir := t.TempDir()
	manager, err := config.NewManager(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetupAdmin("a-strong-admin-password1"); err != nil {
		t.Fatal(err)
	}
	var update config.Update
	update.DSM.MutationPrefix = "naslink_poc_"
	update.DingTalk.ClientID = "ding-id"
	update.DingTalk.ClientSecret = "ding-secret"
	update.DingTalk.AuthURL = "https://login.example/oauth2/auth"
	update.DingTalk.APIBaseURL = ding.URL
	update.OIDC.Issuer = "https://naslink.example"
	update.OIDC.ClientID = "dsm-client"
	update.OIDC.ClientSecret = "dsm-secret"
	update.OIDC.RedirectURIs = []string{"https://dsm.example/callback"}
	if err := manager.Update(update); err != nil {
		t.Fatal(err)
	}
	if err := manager.UpsertBinding(config.Binding{DingTalkSubject: "union:union-1", DSMUsername: "alice"}); err != nil {
		t.Fatal(err)
	}
	store, err := appstate.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceDirectory(nil, []appstate.SourceUser{{SourceType: "dingtalk", Subject: "union:union-1", Name: "测试用户", Active: true}}); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(manager, store, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	provider.Register(mux)

	authReq := httptest.NewRequest(http.MethodGet, "/oidc/authorize?response_type=code&client_id=dsm-client&redirect_uri=https%3A%2F%2Fdsm.example%2Fcallback&scope=openid&state=dsm-state&nonce=n1", nil)
	authRes := httptest.NewRecorder()
	mux.ServeHTTP(authRes, authReq)
	if authRes.Code != http.StatusFound {
		t.Fatalf("authorize status %d: %s", authRes.Code, authRes.Body.String())
	}
	authLocation, _ := url.Parse(authRes.Header().Get("Location"))
	txID := authLocation.Query().Get("state")
	if txID == "" {
		t.Fatal("missing transaction state")
	}

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/dingtalk/callback?code=ding-code&state="+url.QueryEscape(txID), nil)
	callbackRes := httptest.NewRecorder()
	mux.ServeHTTP(callbackRes, callbackReq)
	if callbackRes.Code != http.StatusFound {
		t.Fatalf("callback status %d: %s", callbackRes.Code, callbackRes.Body.String())
	}
	callbackLocation, _ := url.Parse(callbackRes.Header().Get("Location"))
	code := callbackLocation.Query().Get("code")
	if code == "" || callbackLocation.Query().Get("state") != "dsm-state" {
		t.Fatalf("bad callback %s", callbackLocation)
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://dsm.example/callback"}}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth("dsm-client", "dsm-secret")
	tokenRes := httptest.NewRecorder()
	mux.ServeHTTP(tokenRes, tokenReq)
	if tokenRes.Code != http.StatusOK {
		t.Fatalf("token status %d: %s", tokenRes.Code, tokenRes.Body.String())
	}
	var tokens map[string]any
	if err := json.Unmarshal(tokenRes.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	idToken, _ := tokens["id_token"].(string)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid id token %q", idToken)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&provider.key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("invalid RS256 signature: %v", err)
	}
}

func TestWeComAuthorizationFlow(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			w.Write([]byte(`{"errcode":0,"access_token":"token","expires_in":7200}`))
		case "/cgi-bin/user/getuserinfo":
			w.Write([]byte(`{"errcode":0,"UserId":"alice"}`))
		case "/cgi-bin/user/get":
			w.Write([]byte(`{"errcode":0,"userid":"alice","name":"爱丽丝","email":"alice@example.com"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	dataDir := t.TempDir()
	manager, err := config.NewManager(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	var update config.Update
	update.IdentitySource = "wecom"
	update.DSM.MutationPrefix = "naslink_poc_"
	update.WeCom.CorpID = "ww1"
	update.WeCom.AgentID = "1001"
	update.WeCom.Secret = "secret"
	update.WeCom.AuthURL = "https://wecom.example/login"
	update.WeCom.APIBaseURL = api.URL
	update.OIDC.Issuer = "https://naslink.example"
	update.OIDC.ClientID = "dsm-client"
	update.OIDC.ClientSecret = "dsm-secret"
	update.OIDC.RedirectURIs = []string{"https://dsm.example/callback"}
	if err := manager.Update(update); err != nil {
		t.Fatal(err)
	}
	if err := manager.UpsertBinding(config.Binding{SourceType: "wecom", SourceSubject: "userid:alice", DSMUsername: "alice"}); err != nil {
		t.Fatal(err)
	}
	store, err := appstate.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceDirectory(nil, []appstate.SourceUser{{SourceType: "wecom", Subject: "userid:alice", Name: "爱丽丝", Active: true}}); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(manager, store, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	provider.Register(mux)
	auth := httptest.NewRecorder()
	mux.ServeHTTP(auth, httptest.NewRequest(http.MethodGet, "/oidc/authorize?response_type=code&client_id=dsm-client&redirect_uri=https%3A%2F%2Fdsm.example%2Fcallback&scope=openid", nil))
	if auth.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", auth.Code, auth.Body.String())
	}
	location, _ := url.Parse(auth.Header().Get("Location"))
	tx := location.Query().Get("state")
	if location.Host != "wecom.example" || tx == "" {
		t.Fatalf("redirect %s", location)
	}
	callback := httptest.NewRecorder()
	mux.ServeHTTP(callback, httptest.NewRequest(http.MethodGet, "/auth/wecom/callback?code=code&state="+url.QueryEscape(tx), nil))
	if callback.Code != http.StatusFound {
		t.Fatalf("callback: %d %s", callback.Code, callback.Body.String())
	}
}

func TestWeComDriveLaunchBridgesIntoOIDCOnce(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			w.Write([]byte(`{"errcode":0,"access_token":"token","expires_in":7200}`))
		case "/cgi-bin/user/getuserinfo":
			w.Write([]byte(`{"errcode":0,"UserId":"alice"}`))
		case "/cgi-bin/user/get":
			w.Write([]byte(`{"errcode":0,"userid":"alice","name":"爱丽丝","email":"alice@example.com"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	dataDir := t.TempDir()
	manager, err := config.NewManager(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	var update config.Update
	update.IdentitySource = "wecom"
	update.DSM.MutationPrefix = "naslink_poc_"
	update.WeCom.CorpID = "ww1"
	update.WeCom.AgentID = "1001"
	update.WeCom.Secret = "secret"
	update.WeCom.AuthURL = "https://qr.wecom.example/login"
	update.WeCom.InAppAuthURL = "https://inapp.wecom.example/authorize"
	update.WeCom.DriveWebURL = "https://drive.example.com/"
	update.WeCom.APIBaseURL = api.URL
	update.OIDC.Issuer = "http://naslink.example"
	update.OIDC.ClientID = "dsm-client"
	update.OIDC.ClientSecret = "dsm-secret"
	update.OIDC.RedirectURIs = []string{"https://dsm.example/callback"}
	if err := manager.Update(update); err != nil {
		t.Fatal(err)
	}
	if err := manager.UpsertBinding(config.Binding{SourceType: "wecom", SourceSubject: "userid:alice", DSMUsername: "alice"}); err != nil {
		t.Fatal(err)
	}
	store, err := appstate.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceDirectory(nil, []appstate.SourceUser{{SourceType: "wecom", Subject: "userid:alice", Name: "爱丽丝", Active: true}}); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(manager, store, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	provider.Register(mux)

	launch := httptest.NewRecorder()
	mux.ServeHTTP(launch, httptest.NewRequest(http.MethodGet, "/launch/wecom/drive", nil))
	if launch.Code != http.StatusFound {
		t.Fatalf("launch: %d %s", launch.Code, launch.Body.String())
	}
	launchLocation, _ := url.Parse(launch.Header().Get("Location"))
	launchState := launchLocation.Query().Get("state")
	if launchLocation.Host != "inapp.wecom.example" || launchLocation.Query().Get("scope") != "snsapi_base" || launchState == "" {
		t.Fatalf("unexpected launch redirect %s", launchLocation)
	}

	callback := httptest.NewRecorder()
	mux.ServeHTTP(callback, httptest.NewRequest(http.MethodGet, "/auth/wecom/drive/callback?code=wecom-code&state="+url.QueryEscape(launchState), nil))
	if callback.Code != http.StatusFound || callback.Header().Get("Location") != "https://drive.example.com/" {
		t.Fatalf("callback: %d %s %s", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	var loginCookie *http.Cookie
	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == weComLoginCookie {
			loginCookie = cookie
		}
	}
	if loginCookie == nil || loginCookie.Value == "" || !loginCookie.HttpOnly || loginCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("missing secure login ticket cookie: %#v", loginCookie)
	}

	authorizeURL := "/oidc/authorize?response_type=code&client_id=dsm-client&redirect_uri=https%3A%2F%2Fdsm.example%2Fcallback&scope=openid&state=dsm-state"
	authorizeRequest := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	authorizeRequest.AddCookie(loginCookie)
	authorize := httptest.NewRecorder()
	mux.ServeHTTP(authorize, authorizeRequest)
	if authorize.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", authorize.Code, authorize.Body.String())
	}
	dsmCallback, _ := url.Parse(authorize.Header().Get("Location"))
	if dsmCallback.Host != "dsm.example" || dsmCallback.Query().Get("code") == "" || dsmCallback.Query().Get("state") != "dsm-state" {
		t.Fatalf("ticket did not bridge directly to DSM: %s", dsmCallback)
	}

	reuseRequest := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	reuseRequest.AddCookie(loginCookie)
	reuse := httptest.NewRecorder()
	mux.ServeHTTP(reuse, reuseRequest)
	reuseLocation, _ := url.Parse(reuse.Header().Get("Location"))
	if reuseLocation.Host != "qr.wecom.example" {
		t.Fatalf("one-time ticket was unexpectedly reusable: %s", reuseLocation)
	}

	expiredID := "expired-ticket"
	provider.mu.Lock()
	provider.tickets[expiredID] = loginTicket{Subject: "userid:alice", CreatedAt: time.Now().Add(-6 * time.Minute)}
	provider.mu.Unlock()
	expiredRequest := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	expiredRequest.AddCookie(&http.Cookie{Name: weComLoginCookie, Value: expiredID})
	expired := httptest.NewRecorder()
	mux.ServeHTTP(expired, expiredRequest)
	expiredLocation, _ := url.Parse(expired.Header().Get("Location"))
	if expiredLocation.Host != "qr.wecom.example" {
		t.Fatalf("expired ticket was accepted: %s", expiredLocation)
	}

	if len(store.Snapshot().AuditEvents) < 2 {
		t.Fatal("launch and OIDC login were not audited")
	}
}

func TestWeComDriveLaunchRejectsInactiveEmployee(t *testing.T) {
	dataDir := t.TempDir()
	manager, _ := config.NewManager(dataDir)
	if err := manager.UpsertBinding(config.Binding{SourceType: "wecom", SourceSubject: "userid:alice", DSMUsername: "alice"}); err != nil {
		t.Fatal(err)
	}
	store, _ := appstate.Open(dataDir)
	if err := store.ReplaceDirectory(nil, []appstate.SourceUser{{SourceType: "wecom", Subject: "userid:alice", Name: "爱丽丝", Active: false}}); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(manager, store, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.eligibleBinding("wecom", "userid:alice"); err == nil || !strings.Contains(err.Error(), "离职") {
		t.Fatalf("inactive employee should be rejected: %v", err)
	}
}
