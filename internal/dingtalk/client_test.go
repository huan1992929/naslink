package dingtalk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationURL(t *testing.T) {
	c, err := New(Config{ClientID: "ding-client", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(c.AuthorizationURL("https://nas.test/callback", "state-value"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("client_id") != "ding-client" || parsed.Query().Get("scope") != "openid" {
		t.Fatalf("unexpected URL %s", parsed)
	}
}

func TestFetchDirectory(t *testing.T) {
	departmentCalls := map[int]bool{}
	userCalls := map[int]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1.0/oauth2/accessToken":
			json.NewEncoder(w).Encode(map[string]any{"accessToken": "app-token", "expireIn": 7200})
		case "/topapi/v2/department/listsub":
			if r.URL.Query().Get("access_token") != "app-token" {
				t.Error("missing directory access token")
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			departmentID := int(body["dept_id"].(float64))
			departmentCalls[departmentID] = true
			if departmentID == 1 {
				json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok", "result": []map[string]any{{"dept_id": 2, "parent_id": 1, "name": "设计中心"}}})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok", "result": []any{}})
			}
		case "/topapi/v2/user/list":
			if r.URL.Query().Get("access_token") != "app-token" {
				t.Error("missing directory access token")
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			departmentID := int(body["dept_id"].(float64))
			userCalls[departmentID] = true
			if departmentID == 2 {
				json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok", "result": map[string]any{"has_more": false, "list": []map[string]any{{"unionid": "u1", "userid": "001", "name": "张三", "job_number": "A001", "org_email": "zhangsan@example.com", "active": true, "dept_id_list": []int{2}, "leader_in_dept": []bool{true}}}}})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok", "result": map[string]any{"has_more": false, "list": []any{}}})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New(Config{ClientID: "id", ClientSecret: "secret", APIBaseURL: server.URL, DirectoryAPIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := client.FetchDirectory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Departments) != 2 || len(directory.Users) != 1 || directory.Users[0].JobNumber != "A001" || directory.Users[0].Email != "zhangsan@example.com" || len(directory.Users[0].LeaderInDept) != 1 || !directory.Users[0].LeaderInDept[0] {
		t.Fatalf("unexpected directory: %#v", directory)
	}
	if !departmentCalls[1] || !departmentCalls[2] || !userCalls[1] || !userCalls[2] {
		t.Fatalf("directory tree was not traversed: departments=%v users=%v", departmentCalls, userCalls)
	}
}

func TestFetchDirectoryReportsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.0/oauth2/accessToken" {
			json.NewEncoder(w).Encode(map[string]any{"accessToken": "app-token", "expireIn": 7200})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"errcode": 60011, "errmsg": "no permission"})
	}))
	defer server.Close()
	client, err := New(Config{ClientID: "id", ClientSecret: "secret", APIBaseURL: server.URL, DirectoryAPIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.FetchDirectory(context.Background())
	if err == nil || !strings.Contains(err.Error(), "60011 no permission") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDiagnoseDirectoryReportsVisibleScopeAndMatchingFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1.0/oauth2/accessToken":
			json.NewEncoder(w).Encode(map[string]any{"accessToken": "app-token", "expireIn": 7200})
		case "/topapi/v2/department/listsub":
			json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok", "result": []any{}})
		case "/topapi/v2/user/list":
			json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok", "result": map[string]any{"has_more": false, "list": []map[string]any{{"unionid": "u1", "userid": "001", "name": "张三", "job_number": "A001", "org_email": "zhangsan@example.com", "active": true, "dept_id_list": []int{1}}}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New(Config{ClientID: "id", ClientSecret: "secret", APIBaseURL: server.URL, DirectoryAPIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := client.DiagnoseDirectory(context.Background())
	if !diagnostics.OK || diagnostics.DepartmentsVisible != 1 || diagnostics.UsersVisible != 1 || diagnostics.ActiveUsers != 1 || diagnostics.JobNumberUsers != 1 || diagnostics.EmailUsers != 1 {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
	if diagnostics.Checks[3].Status != "pass" {
		t.Fatalf("matching fields should pass: %#v", diagnostics.Checks)
	}
}

func TestDiagnoseDirectorySeparatesPermissionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.0/oauth2/accessToken" {
			json.NewEncoder(w).Encode(map[string]any{"accessToken": "app-token", "expireIn": 7200})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"errcode": 60011, "errmsg": "no permission"})
	}))
	defer server.Close()
	client, err := New(Config{ClientID: "id", ClientSecret: "secret", APIBaseURL: server.URL, DirectoryAPIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := client.DiagnoseDirectory(context.Background())
	if diagnostics.OK || diagnostics.Checks[0].Status != "pass" || diagnostics.Checks[1].Status != "error" || !strings.Contains(diagnostics.Checks[1].Message, "60011 no permission") {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
}

func TestExchangeCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1.0/oauth2/userAccessToken":
			json.NewEncoder(w).Encode(map[string]any{"accessToken": "user-token", "expireIn": 7200})
		case "/v1.0/contact/users/me":
			if r.Header.Get("x-acs-dingtalk-access-token") != "user-token" {
				t.Error("missing user token")
			}
			json.NewEncoder(w).Encode(User{OpenID: "open-1", UnionID: "union-1", Nick: "测试用户", Email: "test@example.com"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c, err := New(Config{ClientID: "id", ClientSecret: "secret", APIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	user, err := c.ExchangeCode(context.Background(), "auth-code")
	if err != nil {
		t.Fatal(err)
	}
	if user.Subject() != "union:union-1" {
		t.Fatalf("unexpected subject %s", user.Subject())
	}
}
