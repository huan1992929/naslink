package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"naslink/internal/config"
	"naslink/internal/license"
	"naslink/internal/oidc"
	appstate "naslink/internal/state"
)

func newTestServer(t *testing.T) (*httptest.Server, *appstate.Store) {
	t.Helper()
	dataDir := t.TempDir()
	manager, err := config.NewManager(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := appstate.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oidc.NewProvider(manager, store, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	licenseManager, err := license.NewManager(dataDir, snapshot.InstallID, snapshot.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	app := New(manager, provider, store, licenseManager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return httptest.NewServer(app.Handler()), store
}

func TestOnboardingRequiresPasswordConfirmationSessionAndCSRF(t *testing.T) {
	server, store := newTestServer(t)
	defer server.Close()

	mismatch, err := http.Post(server.URL+"/api/v1/setup", "application/json", bytes.NewBufferString(`{"password":"a-strong-test-password","password_confirmation":"different-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer mismatch.Body.Close()
	if mismatch.StatusCode != http.StatusBadRequest {
		t.Fatalf("password mismatch status: %d", mismatch.StatusCode)
	}

	setup, err := http.Post(server.URL+"/api/v1/setup", "application/json", bytes.NewBufferString(`{"password":"a-strong-test-password","password_confirmation":"a-strong-test-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Body.Close()
	if setup.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(setup.Body)
		t.Fatalf("setup failed: %d %s", setup.StatusCode, raw)
	}
	var setupBody struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(setup.Body).Decode(&setupBody); err != nil {
		t.Fatal(err)
	}
	cookie := setup.Cookies()[0]

	unauthenticated, err := http.Post(server.URL+"/api/v1/onboarding/start", "application/json", bytes.NewBufferString(`{"identity_source":"wecom"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected session rejection, got %d", unauthenticated.StatusCode)
	}

	withoutCSRF, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/onboarding/start", bytes.NewBufferString(`{"identity_source":"wecom"}`))
	withoutCSRF.Header.Set("Content-Type", "application/json")
	withoutCSRF.AddCookie(cookie)
	response, err := http.DefaultClient.Do(withoutCSRF)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected CSRF rejection, got %d", response.StatusCode)
	}

	start, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/onboarding/start", bytes.NewBufferString(`{"identity_source":"wecom"}`))
	start.Header.Set("Content-Type", "application/json")
	start.Header.Set("X-CSRF-Token", setupBody.CSRF)
	start.AddCookie(cookie)
	response, err = http.DefaultClient.Do(start)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("start failed: %d %s", response.StatusCode, raw)
	}
	if got := store.Snapshot().Onboarding; got.CurrentStep != "dsm" || got.IdentitySource != "wecom" || got.StartedAt.IsZero() {
		t.Fatalf("onboarding state was not saved: %#v", got)
	}

	repeat, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/setup", bytes.NewBufferString(`{"password":"a-strong-test-password","password_confirmation":"a-strong-test-password"}`))
	repeat.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(repeat)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("expected setup replay rejection, got %d", response.StatusCode)
	}
}

func TestOnboardingScopeAndSafeMatchesNeverAcceptProtectedAccount(t *testing.T) {
	server, store := newTestServer(t)
	defer server.Close()
	setup, err := http.Post(server.URL+"/api/v1/setup", "application/json", bytes.NewBufferString(`{"password":"a-strong-test-password","password_confirmation":"a-strong-test-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Body.Close()
	var setupBody struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(setup.Body).Decode(&setupBody); err != nil {
		t.Fatal(err)
	}
	cookie := setup.Cookies()[0]
	if err := store.ReplaceDirectory([]appstate.Department{{ID: "1", Name: "设计"}, {ID: "2", Name: "财务"}}, []appstate.SourceUser{{Subject: "u1", Name: "张三", Active: true}, {Subject: "u2", Name: "管理员", Active: true}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceMatches([]appstate.Match{{Subject: "u1", DSMUsername: "zhangsan", Status: "auto", Score: 100}, {Subject: "u2", DSMUsername: "admin", Status: "auto", Score: 100}}); err != nil {
		t.Fatal(err)
	}

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/onboarding/scope", bytes.NewBufferString(`{"mode":"selected","department_ids":["1"]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", setupBody.CSRF)
	request.AddCookie(cookie)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("scope save failed: %d", response.StatusCode)
	}
	snapshot := store.Snapshot()
	if !snapshot.Departments[0].Managed || snapshot.Departments[1].Managed || snapshot.Departments[0].DSMGroup == "" {
		t.Fatalf("unexpected managed scope: %#v", snapshot.Departments)
	}

	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/onboarding/matches/accept-safe", bytes.NewBufferString(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", setupBody.CSRF)
	request.AddCookie(cookie)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("safe match acceptance failed: %d", response.StatusCode)
	}
	matched := store.Snapshot().Matches
	if !matched[0].Confirmed || matched[1].Confirmed {
		t.Fatalf("protected account was accepted: %#v", matched)
	}
}

func TestDiagnosticsAreSanitizedAndSyncEnableRejectsWrongPassword(t *testing.T) {
	server, store := newTestServer(t)
	defer server.Close()
	setup, err := http.Post(server.URL+"/api/v1/setup", "application/json", bytes.NewBufferString(`{"password":"a-strong-test-password","password_confirmation":"a-strong-test-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Body.Close()
	var setupBody struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(setup.Body).Decode(&setupBody); err != nil {
		t.Fatal(err)
	}
	cookie := setup.Cookies()[0]
	if err := store.ReplaceDirectory([]appstate.Department{{ID: "secret-department", Name: "保密部门"}}, []appstate.SourceUser{{Subject: "user-1", Name: "张三", Email: "zhangsan@example.com", Mobile: "13800138000", Active: true}}); err != nil {
		t.Fatal(err)
	}

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/support/diagnostics", nil)
	request.AddCookie(cookie)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || bytes.Contains(raw, []byte("张三")) || bytes.Contains(raw, []byte("zhangsan@example.com")) || bytes.Contains(raw, []byte("13800138000")) || bytes.Contains(raw, []byte("secret-department")) {
		t.Fatalf("diagnostics leaked private data: %d %s", response.StatusCode, raw)
	}

	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/onboarding/sync/enable", bytes.NewBufferString(`{"plan_id":"missing","admin_password":"wrong-password"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", setupBody.CSRF)
	request.AddCookie(cookie)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password must be rejected before DSM access: %d", response.StatusCode)
	}
}

func TestDrivePreflightBlocksMissingDriveServerAndUnboundUser(t *testing.T) {
	server, store := newTestServer(t)
	defer server.Close()
	setup, err := http.Post(server.URL+"/api/v1/setup", "application/json", bytes.NewBufferString(`{"password":"a-strong-test-password","password_confirmation":"a-strong-test-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Body.Close()
	var setupBody struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(setup.Body).Decode(&setupBody); err != nil {
		t.Fatal(err)
	}
	cookie := setup.Cookies()[0]
	if err := store.SetDriveServerStatus("not_installed"); err != nil {
		t.Fatal(err)
	}

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/drive/preflight", bytes.NewBufferString(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", setupBody.CSRF)
	request.AddCookie(cookie)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte("未安装 Synology Drive Server")) || !bytes.Contains(raw, []byte("固定 DSM 账号绑定")) {
		t.Fatalf("missing Drive Server and unbound user were not actionable blockers: %d %s", response.StatusCode, raw)
	}
}

func TestStalePlanComparisonRejectsChangedActionsBeforeWrites(t *testing.T) {
	preview := []appstate.Action{{ID: "a1", Type: "create_user", Subject: "u1", DSMUsername: "alice"}}
	changed := []appstate.Action{{ID: "a2", Type: "create_user", Subject: "u1", DSMUsername: "alice"}, {ID: "a3", Type: "disable_user", Subject: "u2", DSMUsername: "bob"}}
	if sameSyncActions(preview, changed) {
		t.Fatal("changed DSM plan must be rejected before executeRun is reachable")
	}
	if !sameSyncActions(preview, append([]appstate.Action(nil), preview...)) {
		t.Fatal("equivalent plan should remain executable")
	}
}

func TestAuthenticatedDirectoryImport(t *testing.T) {
	dataDir := t.TempDir()
	manager, err := config.NewManager(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := appstate.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oidc.NewProvider(manager, store, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	licenseManager, err := license.NewManager(dataDir, snapshot.InstallID, snapshot.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	app := New(manager, provider, store, licenseManager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	setupBody := bytes.NewBufferString(`{"password":"a-strong-test-password","password_confirmation":"a-strong-test-password"}`)
	setupRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/setup", setupBody)
	setupRequest.Header.Set("Content-Type", "application/json")
	setupResponse, err := http.DefaultClient.Do(setupRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer setupResponse.Body.Close()
	var setup map[string]any
	json.NewDecoder(setupResponse.Body).Decode(&setup)
	if setupResponse.StatusCode != http.StatusCreated {
		t.Fatalf("setup failed: %#v", setup)
	}
	cookie := setupResponse.Cookies()[0]
	csrf, _ := setup["csrf_token"].(string)

	importBody := bytes.NewBufferString(`{"departments":[{"id":"1","name":"设计中心"}],"users":[{"subject":"union:1","name":"张三","active":true}]}`)
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/directory/import", importBody)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(cookie)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("import failed: %d %s", response.StatusCode, raw)
	}
	if len(store.Snapshot().Users) != 1 {
		t.Fatal("directory was not persisted")
	}
}

func TestIdentityTestUsesUnsavedDingTalkCredentials(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.0/oauth2/accessToken" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["appKey"] != "draft-client" || payload["appSecret"] != "draft-secret" {
			t.Fatalf("unexpected credentials: %#v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"accessToken": "app-token", "expireIn": 7200})
	}))
	defer tokenServer.Close()

	dataDir := t.TempDir()
	manager, err := config.NewManager(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := appstate.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oidc.NewProvider(manager, store, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	licenseManager, err := license.NewManager(dataDir, snapshot.InstallID, snapshot.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	app := New(manager, provider, store, licenseManager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	setupRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/setup", bytes.NewBufferString(`{"password":"a-strong-test-password","password_confirmation":"a-strong-test-password"}`))
	setupRequest.Header.Set("Content-Type", "application/json")
	setupResponse, err := http.DefaultClient.Do(setupRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer setupResponse.Body.Close()
	var setup map[string]any
	if err := json.NewDecoder(setupResponse.Body).Decode(&setup); err != nil {
		t.Fatal(err)
	}

	body := bytes.NewBufferString(fmt.Sprintf(`{"source_type":"dingtalk","dingtalk":{"client_id":"draft-client","client_secret":"draft-secret","api_base_url":%q}}`, tokenServer.URL))
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/identity/test", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", setup["csrf_token"].(string))
	request.AddCookie(setupResponse.Cookies()[0])
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("identity test failed: %d %s", response.StatusCode, raw)
	}
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["source_type"] != "dingtalk" || result["token_expires_in"] != float64(7200) {
		t.Fatalf("unexpected response: %#v", result)
	}
	if manager.Public().DingTalk.HasClientSecret {
		t.Fatal("validation must not persist draft credentials")
	}
}

func TestDingTalkDiagnosisUsesDraftCredentialsAndReturnsVisibility(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1.0/oauth2/accessToken":
			json.NewEncoder(w).Encode(map[string]any{"accessToken": "app-token", "expireIn": 7200})
		case "/topapi/v2/department/listsub":
			json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok", "result": []any{}})
		case "/topapi/v2/user/list":
			json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok", "result": map[string]any{"has_more": false, "list": []map[string]any{{"unionid": "u1", "userid": "001", "name": "张三", "job_number": "A001", "active": true, "dept_id_list": []int{1}}}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer apiServer.Close()

	dataDir := t.TempDir()
	manager, err := config.NewManager(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := appstate.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oidc.NewProvider(manager, store, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	licenseManager, err := license.NewManager(dataDir, snapshot.InstallID, snapshot.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	app := New(manager, provider, store, licenseManager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	setupRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/setup", bytes.NewBufferString(`{"password":"a-strong-test-password","password_confirmation":"a-strong-test-password"}`))
	setupRequest.Header.Set("Content-Type", "application/json")
	setupResponse, err := http.DefaultClient.Do(setupRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer setupResponse.Body.Close()
	var setup map[string]any
	if err := json.NewDecoder(setupResponse.Body).Decode(&setup); err != nil {
		t.Fatal(err)
	}

	body := bytes.NewBufferString(fmt.Sprintf(`{"source_type":"dingtalk","dingtalk":{"client_id":"draft-client","client_secret":"draft-secret","api_base_url":%q,"directory_api_base_url":%q}}`, apiServer.URL, apiServer.URL))
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/dingtalk/diagnose", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", setup["csrf_token"].(string))
	request.AddCookie(setupResponse.Cookies()[0])
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("diagnosis failed: %d %s", response.StatusCode, raw)
	}
	var result struct {
		Diagnostics struct {
			OK                 bool `json:"ok"`
			DepartmentsVisible int  `json:"departments_visible"`
			UsersVisible       int  `json:"users_visible"`
		} `json:"diagnostics"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.Diagnostics.OK || result.Diagnostics.DepartmentsVisible != 1 || result.Diagnostics.UsersVisible != 1 {
		t.Fatalf("unexpected diagnosis: %#v", result)
	}
	if manager.Public().DingTalk.HasClientSecret {
		t.Fatal("diagnosis must not persist draft credentials")
	}
}
