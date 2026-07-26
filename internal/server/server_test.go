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

	setupBody := bytes.NewBufferString(`{"password":"a-strong-test-password"}`)
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

	setupRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/setup", bytes.NewBufferString(`{"password":"a-strong-test-password"}`))
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

	setupRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/setup", bytes.NewBufferString(`{"password":"a-strong-test-password"}`))
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
