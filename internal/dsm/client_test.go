package dsm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/flynn/noise"
)

func TestProbeDiscoversAndReadsDirectory(t *testing.T) {
	coreCallsWithToken := 0
	drivePackages := []map[string]any{{"id": "SynologyDrive", "name": "Synology Drive Server", "status": "running"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		api, method := r.Form.Get("api"), r.Form.Get("method")
		w.Header().Set("Content-Type", "application/json")
		switch api + "." + method {
		case "SYNO.API.Info.query":
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{
				"SYNO.API.Auth":          map[string]any{"path": "entry.cgi", "minVersion": 1, "maxVersion": 6},
				"SYNO.Core.Group":        map[string]any{"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
				"SYNO.Core.Group.Member": map[string]any{"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
				"SYNO.Core.User":         map[string]any{"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
				"SYNO.Core.User.Group":   map[string]any{"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
				"SYNO.Core.Package":      map[string]any{"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
			}})
		case "SYNO.API.Auth.login":
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"sid": "sid", "synotoken": "token"}})
		case "SYNO.API.Auth.logout":
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{}})
		case "SYNO.Core.User.list":
			if r.Header.Get("X-SYNO-TOKEN") != "token" || r.Form.Get("SynoToken") != "" {
				json.NewEncoder(w).Encode(map[string]any{"success": false, "error": map[string]any{"code": 119}})
				return
			}
			coreCallsWithToken++
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"users": []map[string]any{{"name": "alice", "uid": 1026}}}})
		case "SYNO.Core.Group.list":
			if r.Header.Get("X-SYNO-TOKEN") != "token" || r.Form.Get("SynoToken") != "" {
				json.NewEncoder(w).Encode(map[string]any{"success": false, "error": map[string]any{"code": 119}})
				return
			}
			coreCallsWithToken++
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"groups": []map[string]any{{"name": "users", "gid": 100}}}})
		case "SYNO.Core.Group.Member.list":
			coreCallsWithToken++
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"users": []map[string]any{{"name": "alice"}}}})
		case "SYNO.Core.Package.list":
			coreCallsWithToken++
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"packages": drivePackages}})
		default:
			json.NewEncoder(w).Encode(map[string]any{"success": false, "error": map[string]any{"code": 103}})
		}
	}))
	defer server.Close()
	c, err := New(Config{BaseURL: server.URL, Account: "admin", Password: "secret", InsecureTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	report, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !report.ReadOnlyPassed || report.UserCount != 1 || report.GroupCount != 1 || report.DriveServerStatus != "installed" || len(report.Users[0].Groups) != 1 || report.Users[0].Groups[0] != "users" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if coreCallsWithToken != 4 {
		t.Fatalf("expected four authenticated Core calls, got %d", coreCallsWithToken)
	}
	drivePackages = nil
	report, err = c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.DriveServerStatus != "not_installed" {
		t.Fatalf("missing Drive package was not reported: %+v", report)
	}
}

func TestDSM7LoginAddsNoiseRequestHash(t *testing.T) {
	cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	serverStatic, err := cipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var responder *noise.HandshakeState
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		api, method := r.Form.Get("api"), r.Form.Get("method")
		w.Header().Set("Content-Type", "application/json")
		switch api + "." + method {
		case "SYNO.API.Auth.UIConfig.get":
			http.SetCookie(w, &http.Cookie{Name: "_SSID", Value: base64.RawURLEncoding.EncodeToString(serverStatic.Public)})
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{}})
		case "SYNO.API.Auth.login":
			responder, err = noise.NewHandshakeState(noise.Config{
				CipherSuite: cipherSuite, Pattern: noise.HandshakeIK, Initiator: false, StaticKeypair: serverStatic,
			})
			if err != nil {
				t.Fatal(err)
			}
			message, decodeErr := base64.RawURLEncoding.DecodeString(r.Form.Get("ik_message"))
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if _, _, _, err = responder.ReadMessage(nil, message); err != nil {
				t.Fatal(err)
			}
			reply, _, _, writeErr := responder.WriteMessage(nil, nil)
			if writeErr != nil {
				t.Fatal(writeErr)
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{
				"sid": "sid", "synotoken": "token", "ik_message": base64.RawURLEncoding.EncodeToString(reply),
			}})
		case "SYNO.Core.User.list":
			if r.Header.Get("X-SYNO-TOKEN") != "token" || r.Header.Get("X-SYNO-HASH") == "" {
				json.NewEncoder(w).Encode(map[string]any{"success": false, "error": map[string]any{"code": 105}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"users": []map[string]any{}}})
		default:
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{}})
		}
	}))
	defer server.Close()
	c, err := New(Config{BaseURL: server.URL, Account: "admin", Password: "secret", InsecureTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	c.apis = map[string]APIInfo{
		"SYNO.API.Auth":  {Path: "entry.cgi", MinVersion: 1, MaxVersion: 7},
		"SYNO.Core.User": {Path: "entry.cgi", MinVersion: 1, MaxVersion: 1},
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestMutationsRejectNonPOCAccounts(t *testing.T) {
	c := &Client{apis: map[string]APIInfo{"SYNO.Core.User": {Path: "entry.cgi", MinVersion: 1, MaxVersion: 1}}}
	err := c.CreateTestUser(context.Background(), "naslink_poc_", CreateUserInput{Name: "alice", Password: "strong-password"})
	if err == nil {
		t.Fatal("expected safety error")
	}
}

func TestCreateUserRequestShape(t *testing.T) {
	var form url.Values
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		form = r.Form
		json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{}})
	}))
	defer server.Close()
	c, err := New(Config{BaseURL: server.URL, Account: "admin", Password: "secret", InsecureTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	c.apis = map[string]APIInfo{"SYNO.Core.User": {Path: "entry.cgi", MinVersion: 1, MaxVersion: 1}}
	if err := c.CreateTestUser(context.Background(), "naslink_poc_", CreateUserInput{Name: "naslink_poc_001", Password: "strong-password"}); err != nil {
		t.Fatal(err)
	}
	if form.Get("method") != "create" || form.Get("expired") != "normal" {
		t.Fatalf("unexpected form: %v", form)
	}
}

func TestGroupMembershipRequestShape(t *testing.T) {
	var forms []url.Values
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		forms = append(forms, r.Form)
		json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{}})
	}))
	defer server.Close()
	c, err := New(Config{BaseURL: server.URL, Account: "admin", Password: "secret", InsecureTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	c.apis = map[string]APIInfo{"SYNO.Core.Group.Member": {Path: "entry.cgi", MinVersion: 1, MaxVersion: 1}}
	if err := c.SetTestUserGroups(context.Background(), "naslink_poc_", "naslink_poc_001", []string{"naslink_poc_uat"}, []string{"legacy"}); err != nil {
		t.Fatal(err)
	}
	if len(forms) != 2 {
		t.Fatalf("expected add and remove calls, got %d", len(forms))
	}
	if forms[0].Get("api") != "SYNO.Core.Group.Member" || forms[0].Get("method") != "add" || forms[0].Get("group") != "naslink_poc_uat" || forms[0].Get("name") != `["naslink_poc_001"]` {
		t.Fatalf("unexpected add membership form: %v", forms[0])
	}
	if forms[1].Get("api") != "SYNO.Core.Group.Member" || forms[1].Get("method") != "remove" || forms[1].Get("group") != "legacy" || forms[1].Get("name") != `["naslink_poc_001"]` {
		t.Fatalf("unexpected remove membership form: %v", forms[1])
	}
}
