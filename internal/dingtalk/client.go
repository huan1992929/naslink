package dingtalk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultAuthURL          = "https://login.dingtalk.com/oauth2/auth"
	DefaultAPIBase          = "https://api.dingtalk.com"
	DefaultDirectoryAPIBase = "https://oapi.dingtalk.com"
)

type Config struct {
	ClientID            string
	ClientSecret        string
	AuthURL             string
	APIBaseURL          string
	DirectoryAPIBaseURL string
	HTTPClient          *http.Client
}

type Client struct {
	clientID            string
	clientSecret        string
	authURL             string
	apiBaseURL          string
	directoryAPIBaseURL string
	http                *http.Client
}

type User struct {
	OpenID    string `json:"openId"`
	UnionID   string `json:"unionId"`
	Nick      string `json:"nick"`
	AvatarURL string `json:"avatarUrl,omitempty"`
	Mobile    string `json:"mobile,omitempty"`
	Email     string `json:"email,omitempty"`
	StateCode string `json:"stateCode,omitempty"`
}

type Department struct {
	ID       int64  `json:"deptId"`
	ParentID int64  `json:"parentId"`
	Name     string `json:"name"`
}

type DirectoryUser struct {
	UnionID           string               `json:"unionId"`
	UserID            string               `json:"userId"`
	Name              string               `json:"name"`
	JobNumber         string               `json:"jobNumber"`
	Email             string               `json:"email"`
	Mobile            string               `json:"mobile"`
	Active            bool                 `json:"active"`
	DepartmentIDs     []int64              `json:"deptIdList"`
	LeaderInDept      []bool               `json:"leaderInDept,omitempty"`
	LeaderDepartments []LeaderInDepartment `json:"leaderInDepartment,omitempty"`
}

type LeaderInDepartment struct {
	DepartmentID int64 `json:"departmentId"`
	Leader       bool  `json:"leader"`
}

type Directory struct {
	Departments []Department    `json:"departments"`
	Users       []DirectoryUser `json:"users"`
}

type DiagnosticCheck struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Required bool   `json:"required"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

type DirectoryDiagnostics struct {
	OK                 bool              `json:"ok"`
	TokenExpiresIn     int               `json:"token_expires_in"`
	DepartmentsVisible int               `json:"departments_visible"`
	UsersVisible       int               `json:"users_visible"`
	ActiveUsers        int               `json:"active_users"`
	JobNumberUsers     int               `json:"job_number_users"`
	EmailUsers         int               `json:"email_users"`
	MobileUsers        int               `json:"mobile_users"`
	Checks             []DiagnosticCheck `json:"checks"`
}

func (u User) Subject() string {
	if u.UnionID != "" {
		return "union:" + u.UnionID
	}
	return "open:" + u.OpenID
}

type tokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpireIn     int    `json:"expireIn"`
	CorpID       string `json:"corpId,omitempty"`
	Code         string `json:"code,omitempty"`
	Message      string `json:"message,omitempty"`
	RequestID    string `json:"requestid,omitempty"`
}

func New(cfg Config) (*Client, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("钉钉 Client ID 和 Client Secret 不能为空")
	}
	if cfg.AuthURL == "" {
		cfg.AuthURL = DefaultAuthURL
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = DefaultAPIBase
	}
	if cfg.DirectoryAPIBaseURL == "" {
		cfg.DirectoryAPIBaseURL = DefaultDirectoryAPIBase
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		clientID: cfg.ClientID, clientSecret: cfg.ClientSecret,
		authURL: cfg.AuthURL, apiBaseURL: strings.TrimRight(cfg.APIBaseURL, "/"),
		directoryAPIBaseURL: strings.TrimRight(cfg.DirectoryAPIBaseURL, "/"), http: cfg.HTTPClient,
	}, nil
}

func (c *Client) AuthorizationURL(redirectURI, state string) string {
	values := url.Values{
		"redirect_uri": {redirectURI}, "response_type": {"code"}, "client_id": {c.clientID},
		"scope": {"openid"}, "state": {state}, "prompt": {"consent"},
	}
	return c.authURL + "?" + values.Encode()
}

func (c *Client) ExchangeCode(ctx context.Context, code string) (User, error) {
	if code == "" {
		return User{}, errors.New("钉钉回调缺少 code")
	}
	token, err := c.userAccessToken(ctx, code)
	if err != nil {
		return User{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiBaseURL+"/v1.0/contact/users/me", nil)
	if err != nil {
		return User{}, err
	}
	request.Header.Set("x-acs-dingtalk-access-token", token.AccessToken)
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return User{}, fmt.Errorf("query DingTalk user: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return User{}, fmt.Errorf("DingTalk user API returned HTTP %d", response.StatusCode)
	}
	var user User
	if err := json.NewDecoder(response.Body).Decode(&user); err != nil {
		return User{}, err
	}
	if user.OpenID == "" && user.UnionID == "" {
		return User{}, errors.New("钉钉未返回稳定用户标识")
	}
	return user, nil
}

func (c *Client) TestAppCredentials(ctx context.Context) (time.Duration, error) {
	token, err := c.appAccessToken(ctx)
	if err != nil {
		return 0, err
	}
	return time.Duration(token.ExpireIn) * time.Second, nil
}

func (c *Client) FetchDirectory(ctx context.Context) (Directory, error) {
	token, err := c.appAccessToken(ctx)
	if err != nil {
		return Directory{}, err
	}
	return c.fetchDirectoryWithToken(ctx, token.AccessToken)
}

func (c *Client) DiagnoseDirectory(ctx context.Context) DirectoryDiagnostics {
	diagnostics := DirectoryDiagnostics{Checks: []DiagnosticCheck{
		{Key: "credentials", Label: "应用凭据", Required: true, Status: "pending", Message: "正在换取应用访问令牌"},
		{Key: "departments", Label: "部门读取权限", Required: true, Status: "blocked", Message: "等待应用凭据验证"},
		{Key: "users", Label: "员工读取权限", Required: true, Status: "blocked", Message: "等待部门读取验证"},
		{Key: "matching_fields", Label: "账号匹配字段", Required: false, Status: "blocked", Message: "等待员工读取验证"},
	}}
	token, err := c.appAccessToken(ctx)
	if err != nil {
		diagnostics.Checks[0].Status = "error"
		diagnostics.Checks[0].Message = err.Error()
		return diagnostics
	}
	diagnostics.TokenExpiresIn = token.ExpireIn
	diagnostics.Checks[0].Status = "pass"
	diagnostics.Checks[0].Message = fmt.Sprintf("凭据有效，Token 有效期 %d 秒", token.ExpireIn)

	directory, stage, err := c.fetchDirectoryDiagnosed(ctx, token.AccessToken)
	if err != nil {
		if stage == "departments" {
			diagnostics.Checks[1].Status = "error"
			diagnostics.Checks[1].Message = err.Error()
		} else {
			diagnostics.Checks[1].Status = "pass"
			diagnostics.Checks[1].Message = fmt.Sprintf("可读取 %d 个部门", len(directory.Departments))
			diagnostics.Checks[2].Status = "error"
			diagnostics.Checks[2].Message = err.Error()
		}
		return diagnostics
	}

	diagnostics.DepartmentsVisible = len(directory.Departments)
	diagnostics.UsersVisible = len(directory.Users)
	for _, user := range directory.Users {
		if user.Active {
			diagnostics.ActiveUsers++
		}
		if user.JobNumber != "" {
			diagnostics.JobNumberUsers++
		}
		if user.Email != "" {
			diagnostics.EmailUsers++
		}
		if user.Mobile != "" {
			diagnostics.MobileUsers++
		}
	}
	diagnostics.Checks[1].Status = "pass"
	diagnostics.Checks[1].Message = fmt.Sprintf("可读取 %d 个部门；数量异常偏少时请检查可见范围", diagnostics.DepartmentsVisible)
	diagnostics.Checks[2].Status = "pass"
	diagnostics.Checks[2].Message = fmt.Sprintf("可读取 %d 名员工，其中 %d 人在职", diagnostics.UsersVisible, diagnostics.ActiveUsers)
	diagnostics.Checks[3].Status = "warning"
	diagnostics.Checks[3].Message = "未读取到工号、邮箱或手机号；系统仍可按 UserID 建立绑定"
	if diagnostics.UsersVisible == 0 {
		diagnostics.Checks[2].Status = "warning"
		diagnostics.Checks[2].Message = "接口调用成功但未读取到员工，请检查应用可见范围"
		diagnostics.Checks[3].Message = "没有可见员工，暂时无法检查匹配字段"
	} else if diagnostics.JobNumberUsers+diagnostics.EmailUsers+diagnostics.MobileUsers > 0 {
		diagnostics.Checks[3].Status = "pass"
		diagnostics.Checks[3].Message = fmt.Sprintf("工号 %d 人、邮箱 %d 人、手机号 %d 人可用于历史账号匹配", diagnostics.JobNumberUsers, diagnostics.EmailUsers, diagnostics.MobileUsers)
	}
	diagnostics.OK = diagnostics.Checks[0].Status == "pass" && diagnostics.Checks[1].Status == "pass" && diagnostics.Checks[2].Status != "error"
	return diagnostics
}

func (c *Client) fetchDirectoryWithToken(ctx context.Context, accessToken string) (Directory, error) {
	directory, _, err := c.fetchDirectoryDiagnosed(ctx, accessToken)
	return directory, err
}

func (c *Client) fetchDirectoryDiagnosed(ctx context.Context, accessToken string) (Directory, string, error) {
	directory := Directory{Departments: []Department{{ID: 1, ParentID: 0, Name: "根部门"}}}
	queue := []int64{1}
	seenDepartments := map[int64]bool{1: true}
	seenUsers := map[string]DirectoryUser{}
	for len(queue) > 0 {
		departmentID := queue[0]
		queue = queue[1:]
		children, err := c.departmentChildren(ctx, accessToken, departmentID)
		if err != nil {
			return directory, "departments", fmt.Errorf("query DingTalk department %d: %w", departmentID, err)
		}
		for _, child := range children {
			if child.ID == 0 || seenDepartments[child.ID] {
				continue
			}
			seenDepartments[child.ID] = true
			directory.Departments = append(directory.Departments, child)
			queue = append(queue, child.ID)
		}
		users, err := c.departmentUsers(ctx, accessToken, departmentID)
		if err != nil {
			return directory, "users", fmt.Errorf("query DingTalk users in department %d: %w", departmentID, err)
		}
		for _, user := range users {
			key := user.UnionID
			if key == "" {
				key = user.UserID
			}
			if key != "" {
				seenUsers[key] = user
			}
		}
	}
	for _, user := range seenUsers {
		directory.Users = append(directory.Users, user)
	}
	return directory, "", nil
}

func (c *Client) appAccessToken(ctx context.Context) (tokenResponse, error) {
	payload := map[string]string{"appKey": c.clientID, "appSecret": c.clientSecret}
	var token tokenResponse
	if err := c.postJSON(ctx, "/v1.0/oauth2/accessToken", payload, &token); err != nil {
		return token, err
	}
	if token.AccessToken == "" {
		return token, apiMessage(token.Code, token.Message)
	}
	return token, nil
}

func (c *Client) departmentChildren(ctx context.Context, accessToken string, departmentID int64) ([]Department, error) {
	var rows []struct {
		ID       int64  `json:"dept_id"`
		ParentID int64  `json:"parent_id"`
		Name     string `json:"name"`
	}
	if err := c.directoryJSON(ctx, "/topapi/v2/department/listsub", accessToken, map[string]any{
		"dept_id":  departmentID,
		"language": "zh_CN",
	}, &rows); err != nil {
		return nil, err
	}
	departments := make([]Department, 0, len(rows))
	for _, row := range rows {
		departments = append(departments, Department{ID: row.ID, ParentID: row.ParentID, Name: row.Name})
	}
	return departments, nil
}

func (c *Client) departmentUsers(ctx context.Context, accessToken string, departmentID int64) ([]DirectoryUser, error) {
	users := []DirectoryUser{}
	cursor := int64(0)
	for page := 0; page < 1000; page++ {
		var response struct {
			List []struct {
				UnionID       string  `json:"unionid"`
				UserID        string  `json:"userid"`
				Name          string  `json:"name"`
				JobNumber     string  `json:"job_number"`
				Email         string  `json:"email"`
				OrgEmail      string  `json:"org_email"`
				Mobile        string  `json:"mobile"`
				Active        bool    `json:"active"`
				DepartmentIDs []int64 `json:"dept_id_list"`
				LeaderInDept  []bool  `json:"leader_in_dept"`
			} `json:"list"`
			HasMore    bool  `json:"has_more"`
			NextCursor int64 `json:"next_cursor"`
		}
		if err := c.directoryJSON(ctx, "/topapi/v2/user/list", accessToken, map[string]any{
			"dept_id":              departmentID,
			"cursor":               cursor,
			"size":                 100,
			"order_field":          "custom",
			"contain_access_limit": false,
			"language":             "zh_CN",
		}, &response); err != nil {
			return nil, err
		}
		for _, row := range response.List {
			email := row.Email
			if email == "" {
				email = row.OrgEmail
			}
			users = append(users, DirectoryUser{
				UnionID: row.UnionID, UserID: row.UserID, Name: row.Name, JobNumber: row.JobNumber,
				Email: email, Mobile: row.Mobile, Active: row.Active,
				DepartmentIDs: row.DepartmentIDs, LeaderInDept: row.LeaderInDept,
			})
		}
		if !response.HasMore {
			return users, nil
		}
		if response.NextCursor == cursor {
			return nil, errors.New("钉钉通讯录分页游标未前进")
		}
		cursor = response.NextCursor
	}
	return nil, errors.New("钉钉通讯录分页超过安全上限")
}

func (c *Client) directoryJSON(ctx context.Context, path, accessToken string, payload, target any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := c.directoryAPIBaseURL + path + "?access_token=" + url.QueryEscape(accessToken)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("request DingTalk directory API %s: %w", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("DingTalk directory API %s returned HTTP %d", path, response.StatusCode)
	}
	var envelope struct {
		ErrorCode int             `json:"errcode"`
		ErrorMsg  string          `json:"errmsg"`
		Result    json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return err
	}
	if envelope.ErrorCode != 0 {
		return fmt.Errorf("DingTalk directory API %s failed: %d %s", path, envelope.ErrorCode, envelope.ErrorMsg)
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return errors.New("钉钉通讯录接口未返回 result")
	}
	if err := json.Unmarshal(envelope.Result, target); err != nil {
		return fmt.Errorf("decode DingTalk directory API %s: %w", path, err)
	}
	return nil
}

func (c *Client) authorizedJSON(ctx context.Context, method, path, accessToken string, payload any) (json.RawMessage, error) {
	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.apiBaseURL+path, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("x-acs-dingtalk-access-token", accessToken)
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("DingTalk API %s returned HTTP %d", path, response.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *Client) userAccessToken(ctx context.Context, code string) (tokenResponse, error) {
	payload := map[string]string{
		"clientId": c.clientID, "clientSecret": c.clientSecret,
		"code": code, "grantType": "authorization_code",
	}
	var token tokenResponse
	if err := c.postJSON(ctx, "/v1.0/oauth2/userAccessToken", payload, &token); err != nil {
		return token, err
	}
	if token.AccessToken == "" {
		return token, apiMessage(token.Code, token.Message)
	}
	return token, nil
}

func (c *Client) postJSON(ctx context.Context, path string, payload any, target any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("request DingTalk: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("DingTalk API returned HTTP %d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		return err
	}
	return nil
}

func apiMessage(code, message string) error {
	if code == "" {
		code = "unknown"
	}
	if message == "" {
		message = "钉钉接口未返回 access token"
	}
	return fmt.Errorf("DingTalk API %s: %s", code, message)
}
