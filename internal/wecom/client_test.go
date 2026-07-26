package wecom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientFetchDirectoryAndExchangeCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			w.Write([]byte(`{"errcode":0,"access_token":"token","expires_in":7200}`))
		case "/cgi-bin/department/list":
			w.Write([]byte(`{"errcode":0,"department":[{"id":1,"name":"总部","parentid":0}]}`))
		case "/cgi-bin/user/list":
			w.Write([]byte(`{"errcode":0,"userlist":[{"userid":"zhangsan","name":"张三","department":[1],"is_leader_in_dept":[1],"email":"z@example.com","status":1}]}`))
		case "/cgi-bin/user/getuserinfo":
			w.Write([]byte(`{"errcode":0,"UserId":"zhangsan"}`))
		case "/cgi-bin/user/get":
			w.Write([]byte(`{"errcode":0,"userid":"zhangsan","name":"张三","email":"z@example.com"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New(Config{CorpID: "ww1", AgentID: "1001", Secret: "secret", APIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := client.FetchDirectory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Departments) != 1 || len(directory.Users) != 1 || directory.Users[0].UserID != "zhangsan" || len(directory.Users[0].IsLeaderInDept) != 1 || directory.Users[0].IsLeaderInDept[0] != 1 {
		t.Fatalf("unexpected directory: %#v", directory)
	}
	user, err := client.ExchangeCode(context.Background(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if user.Subject() != "userid:zhangsan" || user.Name != "张三" {
		t.Fatalf("unexpected user: %#v", user)
	}
}

func TestAuthorizationURL(t *testing.T) {
	client, _ := New(Config{CorpID: "ww corp", AgentID: "1001", Secret: "secret"})
	value := client.AuthorizationURL("https://example.com/callback", "state")
	if value == "" || value[:len(DefaultAuthURL)] != DefaultAuthURL {
		t.Fatal(value)
	}
}

func TestInAppAuthorizationURL(t *testing.T) {
	client, _ := New(Config{CorpID: "ww corp", AgentID: "1001", Secret: "secret"})
	value := client.InAppAuthorizationURL("https://example.com/auth/wecom/drive/callback", "launch-state")
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != DefaultInAppAuthURL {
		t.Fatalf("unexpected endpoint %s", parsed)
	}
	if parsed.Query().Get("appid") != "ww corp" || parsed.Query().Get("agentid") != "" || parsed.Query().Get("scope") != "snsapi_base" || parsed.Query().Get("response_type") != "code" || parsed.Query().Get("state") != "launch-state" {
		t.Fatalf("unexpected query %s", parsed.RawQuery)
	}
	if parsed.Fragment != "wechat_redirect" {
		t.Fatalf("missing WeCom fragment: %s", parsed.Fragment)
	}
	if !IsInAppBrowser("Mozilla/5.0 wxwork/4.1.0") || IsInAppBrowser("Mozilla/5.0 Chrome/140") {
		t.Fatal("in-app browser detection failed")
	}
	if !strings.Contains(value, "redirect_uri=") {
		t.Fatal(value)
	}
}
