// mockdsm is a stateful, local-only DSM WebAPI simulator used for NASLink
// integration testing. It never connects to a real Synology device.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type user struct {
	Name        string   `json:"name"`
	UID         int      `json:"uid"`
	Description string   `json:"description,omitempty"`
	Email       string   `json:"email,omitempty"`
	Expired     string   `json:"expired,omitempty"`
	Groups      []string `json:"groups,omitempty"`
}

type group struct {
	Name        string `json:"name"`
	GID         int    `json:"gid"`
	Description string `json:"description,omitempty"`
}

type server struct {
	mu     sync.Mutex
	users  map[string]user
	groups map[string]group
	events []map[string]any
	nextID int
}

func main() {
	listen := flag.String("listen", "127.0.0.1:15001", "listen address")
	flag.Parse()

	s := newServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/webapi/entry.cgi", s.webAPI)
	mux.HandleFunc("/webapi/auth.cgi", s.webAPI)
	mux.HandleFunc("/webapi/", s.webAPI)
	mux.HandleFunc("/__mock/state", s.state)
	mux.HandleFunc("/__mock/health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, map[string]any{"ok": true}) })
	log.Printf("mock DSM listening on http://%s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func newServer() *server {
	users := []user{
		{Name: "admin", UID: 1024, Description: "系统管理员", Expired: "normal", Groups: []string{"administrators"}},
		{Name: "guest", UID: 1025, Description: "访客", Expired: "now", Groups: []string{"users"}},
		{Name: "naslink_poc_admin", UID: 1026, Description: "NASLink API", Expired: "normal", Groups: []string{"administrators"}},
		{Name: "zhangsan", UID: 1101, Description: "张三", Email: "zhangsan@example.com", Expired: "normal", Groups: []string{"users", "dept_design"}},
		{Name: "lisi", UID: 1102, Description: "李四", Email: "lisi@example.com", Expired: "normal", Groups: []string{"users", "dept_marketing"}},
		{Name: "wangwu", UID: 1103, Description: "王五", Email: "wangwu@example.com", Expired: "normal", Groups: []string{"users", "dept_design"}},
		{Name: "zhaoliu", UID: 1104, Description: "赵六", Email: "zhaoliu@example.com", Expired: "now", Groups: []string{"users", "dept_sales"}},
	}
	groups := []group{
		{Name: "administrators", GID: 101, Description: "system administrators"},
		{Name: "users", GID: 100, Description: "local users"},
		{Name: "dept_design", GID: 1201, Description: "设计中心"},
		{Name: "dept_sales", GID: 1202, Description: "市场销售"},
		{Name: "dept_marketing", GID: 1203, Description: "市场部"},
	}
	s := &server{users: map[string]user{}, groups: map[string]group{}, nextID: 2000}
	for _, value := range users {
		s.users[value.Name] = value
	}
	for _, value := range groups {
		s.groups[value.Name] = value
	}
	return s
}

func (s *server) webAPI(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, 400)
		return
	}
	api, method := r.Form.Get("api"), r.Form.Get("method")
	if api == "SYNO.API.Info" && method == "query" {
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{
			// The local mock deliberately models the pre-Noise API shape so
			// browser/UAT exercises can run without real DSM credentials.
			"SYNO.API.Auth":         apiInfo("entry.cgi", 1, 6),
			"SYNO.Core.User":        apiInfo("entry.cgi", 1, 1),
			"SYNO.Core.User.Group":  apiInfo("entry.cgi", 1, 1),
			"SYNO.Core.Package":     apiInfo("entry.cgi", 1, 1),
			"SYNO.FileStation.Info": apiInfo("entry.cgi", 1, 2),
		}})
		return
	}
	if api == "SYNO.API.Auth" {
		s.auth(w, method)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	switch api + "." + method {
	case "SYNO.Core.User.list":
		values := make([]user, 0, len(s.users))
		for _, value := range s.users {
			values = append(values, value)
		}
		sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{"users": values, "total": len(values)}})
	case "SYNO.Core.User.create":
		name := strings.TrimSpace(r.Form.Get("name"))
		if name == "" || s.users[name].Name != "" {
			writeError(w, 409)
			return
		}
		s.nextID++
		value := user{Name: name, UID: s.nextID, Description: r.Form.Get("description"), Email: r.Form.Get("email"), Expired: "normal", Groups: []string{"users"}}
		s.users[name] = value
		s.record("create_user", name, r.Form)
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{}})
	case "SYNO.Core.User.set":
		name := r.Form.Get("name")
		value, ok := s.users[name]
		if !ok {
			writeError(w, 404)
			return
		}
		value.Expired = r.Form.Get("expired")
		s.users[name] = value
		s.record("set_user", name, r.Form)
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{}})
	case "SYNO.Core.User.Group.list":
		values := make([]group, 0, len(s.groups))
		for _, value := range s.groups {
			values = append(values, value)
		}
		sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{"groups": values, "total": len(values)}})
	case "SYNO.Core.Package.list":
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{"packages": []map[string]any{{"id": "SynologyDrive", "name": "Synology Drive Server", "status": "running"}}}})
	case "SYNO.Core.User.Group.join":
		name := r.Form.Get("name")
		value, ok := s.users[name]
		if !ok {
			writeError(w, 404)
			return
		}
		var join, leave []string
		_ = json.Unmarshal([]byte(r.Form.Get("join_group")), &join)
		_ = json.Unmarshal([]byte(r.Form.Get("leave_group")), &leave)
		membership := map[string]bool{}
		for _, current := range value.Groups {
			membership[current] = true
		}
		for _, removed := range leave {
			delete(membership, removed)
		}
		for _, added := range join {
			if s.groups[added].Name != "" {
				membership[added] = true
			}
		}
		value.Groups = value.Groups[:0]
		for current := range membership {
			value.Groups = append(value.Groups, current)
		}
		sort.Strings(value.Groups)
		s.users[name] = value
		s.record("set_groups", name, r.Form)
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{}})
	case "SYNO.Core.User.Group.create":
		name := strings.TrimSpace(r.Form.Get("name"))
		if name == "" || s.groups[name].Name != "" {
			writeError(w, 409)
			return
		}
		s.nextID++
		s.groups[name] = group{Name: name, GID: s.nextID, Description: r.Form.Get("description")}
		s.record("create_group", name, r.Form)
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{}})
	default:
		writeError(w, 103)
	}
}

func (s *server) auth(w http.ResponseWriter, method string) {
	switch method {
	case "login":
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{"sid": "mock-sid", "synotoken": "mock-token"}})
	case "logout":
		writeJSON(w, map[string]any{"success": true, "data": map[string]any{}})
	default:
		writeError(w, 103)
	}
}

func (s *server) state(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	values := make([]user, 0, len(s.users))
	for _, value := range s.users {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
	writeJSON(w, map[string]any{"users": values, "events": s.events})
}

func (s *server) record(action, target string, form map[string][]string) {
	copyForm := map[string][]string{}
	for key, values := range form {
		if key == "passwd" || key == "password" || key == "SynoToken" || key == "_sid" {
			continue
		}
		copyForm[key] = append([]string(nil), values...)
	}
	s.events = append(s.events, map[string]any{"action": action, "target": target, "form": copyForm})
}

func apiInfo(path string, minVersion, maxVersion int) map[string]any {
	return map[string]any{"path": path, "minVersion": minVersion, "maxVersion": maxVersion}
}

func writeError(w http.ResponseWriter, code int) {
	writeJSON(w, map[string]any{"success": false, "error": map[string]any{"code": code}})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fmt.Fprintln(w, `{"success":false,"error":{"code":500}}`)
	}
}
