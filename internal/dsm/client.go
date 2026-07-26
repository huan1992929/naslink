package dsm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const DefaultMutationPrefix = "naslink_poc_"

type APIInfo struct {
	Path          string `json:"path"`
	MinVersion    int    `json:"minVersion"`
	MaxVersion    int    `json:"maxVersion"`
	RequestFormat string `json:"requestFormat,omitempty"`
}

type User struct {
	Name              string   `json:"name"`
	UID               int      `json:"uid,omitempty"`
	Description       string   `json:"description,omitempty"`
	Email             string   `json:"email,omitempty"`
	Expired           string   `json:"expired,omitempty"`
	CannotChangePass  bool     `json:"cannot_chg_passwd,omitempty"`
	PasswordNeverEnds bool     `json:"passwd_never_expire,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

type Group struct {
	Name        string `json:"name"`
	GID         int    `json:"gid,omitempty"`
	Description string `json:"description,omitempty"`
}

type ProbeReport struct {
	BaseURL        string             `json:"base_url"`
	CheckedAt      time.Time          `json:"checked_at"`
	APIAvailable   map[string]APIInfo `json:"api_available"`
	MissingAPIs    []string           `json:"missing_apis"`
	Users          []User             `json:"users,omitempty"`
	Groups         []Group            `json:"groups,omitempty"`
	UserCount      int                `json:"user_count"`
	GroupCount     int                `json:"group_count"`
	ReadOnlyPassed bool               `json:"read_only_passed"`
}

type Config struct {
	BaseURL     string
	Account     string
	Password    string
	InsecureTLS bool
	Timeout     time.Duration
}

type Client struct {
	baseURL   string
	account   string
	password  string
	http      *http.Client
	apis      map[string]APIInfo
	sid       string
	synoToken string
	noiseMu   sync.Mutex
	noiseSend *noise.CipherState
	noiseHash string
}

type apiEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Code   int             `json:"code"`
		Errors json.RawMessage `json:"errors,omitempty"`
	} `json:"error,omitempty"`
}

type APIError struct {
	API    string
	Method string
	Code   int
	Detail string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("DSM API %s.%s failed with code %d%s", e.API, e.Method, e.Code, e.Detail)
}

func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" || cfg.Account == "" || cfg.Password == "" {
		return nil, errors.New("DSM URL、账号和密码不能为空")
	}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("DSM URL 无效")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("DSM URL 只允许 http 或 https")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		// DSM account mutations can legitimately take longer than read-only
		// directory calls while the system updates local account databases.
		timeout = 45 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS} // #nosec G402 -- opt-in for DSM self-signed certificates.
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"), account: cfg.Account, password: cfg.Password,
		http: &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

func (c *Client) Discover(ctx context.Context) (map[string]APIInfo, error) {
	values := url.Values{
		"api": {"SYNO.API.Info"}, "version": {"1"}, "method": {"query"}, "query": {"all"},
	}
	envelope, err := c.request(ctx, http.MethodGet, "/webapi/entry.cgi", values)
	if err != nil {
		return nil, err
	}
	var apis map[string]APIInfo
	if err := json.Unmarshal(envelope.Data, &apis); err != nil {
		return nil, fmt.Errorf("decode API discovery: %w", err)
	}
	c.apis = apis
	return cloneAPIMap(apis), nil
}

func (c *Client) Login(ctx context.Context) error {
	version := 6
	path := "/webapi/entry.cgi"
	useDSM7BrowserSession := false
	if info, ok := c.apis["SYNO.API.Auth"]; ok {
		if info.MaxVersion >= 7 {
			version = 7
			useDSM7BrowserSession = true
		} else if info.MaxVersion < version {
			version = info.MaxVersion
		}
		path = apiPath(info.Path)
	}
	values := url.Values{
		"api": {"SYNO.API.Auth"}, "version": {fmt.Sprint(version)}, "method": {"login"},
		"account": {c.account}, "passwd": {c.password}, "session": {"NASLink"},
		"format": {"sid"}, "enable_syno_token": {"yes"},
	}
	var handshake *noise.HandshakeState
	if useDSM7BrowserSession {
		var ikMessage string
		var err error
		handshake, ikMessage, err = c.startDSM7Noise(ctx)
		if err != nil {
			return fmt.Errorf("DSM 7 管理会话握手失败: %w", err)
		}
		values.Set("client", "browser")
		values.Set("ik_message", ikMessage)
		values.Set("session", "webui")
		values.Set("logintype", "local")
		values.Set("enable_device_token", "no")
		values.Set("rememberme", "0")
	}
	envelope, err := c.request(ctx, http.MethodPost, path, values)
	if err != nil {
		return err
	}
	var data struct {
		SID       string `json:"sid"`
		SynoToken string `json:"synotoken"`
		IKMessage string `json:"ik_message"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		return err
	}
	if data.SID == "" {
		return errors.New("DSM 登录成功但未返回 SID")
	}
	c.sid, c.synoToken = data.SID, data.SynoToken
	if useDSM7BrowserSession {
		if data.IKMessage == "" {
			c.sid, c.synoToken = "", ""
			return errors.New("DSM 7 登录成功但未返回 Noise 握手信息")
		}
		if err := c.finishDSM7Noise(handshake, data.IKMessage); err != nil {
			c.sid, c.synoToken = "", ""
			return fmt.Errorf("完成 DSM 7 管理会话握手: %w", err)
		}
	}
	return nil
}

func (c *Client) Logout(ctx context.Context) error {
	if c.sid == "" {
		return nil
	}
	_, err := c.call(ctx, http.MethodPost, "SYNO.API.Auth", 6, "logout", nil)
	c.sid, c.synoToken = "", ""
	c.noiseMu.Lock()
	c.noiseSend, c.noiseHash = nil, ""
	c.noiseMu.Unlock()
	return err
}

func (c *Client) startDSM7Noise(ctx context.Context) (*noise.HandshakeState, string, error) {
	values := url.Values{
		"api": {"SYNO.API.Auth.UIConfig"}, "version": {"1"}, "method": {"get"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/webapi/entry.cgi/SYNO.API.Auth.UIConfig", strings.NewReader(values.Encode()))
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, "", fmt.Errorf("UIConfig HTTP status %d", response.StatusCode)
	}
	var encodedServerKey string
	for _, cookie := range response.Cookies() {
		if cookie.Name == "_SSID" {
			encodedServerKey = cookie.Value
			break
		}
	}
	if encodedServerKey == "" {
		return nil, "", errors.New("UIConfig 未返回 _SSID")
	}
	serverKey, err := base64.RawURLEncoding.DecodeString(encodedServerKey)
	if err != nil {
		return nil, "", fmt.Errorf("解析 _SSID: %w", err)
	}
	cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	staticKey, err := cipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: staticKey,
		PeerStatic:    serverKey,
	})
	if err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(map[string]int64{"time": time.Now().Unix()})
	if err != nil {
		return nil, "", err
	}
	message, _, _, err := handshake.WriteMessage(nil, payload)
	if err != nil {
		return nil, "", err
	}
	return handshake, base64.RawURLEncoding.EncodeToString(message), nil
}

func (c *Client) finishDSM7Noise(handshake *noise.HandshakeState, encodedMessage string) error {
	message, err := base64.RawURLEncoding.DecodeString(encodedMessage)
	if err != nil {
		return err
	}
	_, send, _, err := handshake.ReadMessage(nil, message)
	if err != nil {
		return err
	}
	if send == nil {
		return errors.New("Noise 握手未产生发送密钥")
	}
	c.noiseMu.Lock()
	c.noiseSend = send
	c.noiseHash = base64.RawURLEncoding.EncodeToString(handshake.ChannelBinding())
	c.noiseMu.Unlock()
	return nil
}

func (c *Client) nextDSM7RequestHash() (string, error) {
	c.noiseMu.Lock()
	defer c.noiseMu.Unlock()
	if c.noiseSend == nil || c.noiseHash == "" {
		return "", nil
	}
	nonce := c.noiseSend.Nonce()
	encryptedEmpty, err := c.noiseSend.Encrypt(nil, nil, nil)
	if err != nil {
		return "", err
	}
	prefix := c.noiseHash
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	return prefix + base64.RawURLEncoding.EncodeToString(encryptedEmpty) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(nonce, 10))), nil
}

func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	params := url.Values{
		"type": {"local"}, "offset": {"0"}, "limit": {"-1"}, "sort_by": {"name"},
		"sort_direction": {"ASC"},
		"additional":     {`["description","email","expired","cannot_chg_passwd","passwd_never_expire","groups"]`},
	}
	data, err := c.call(ctx, http.MethodPost, "SYNO.Core.User", 1, "list", params)
	if err != nil {
		return nil, err
	}
	var response struct {
		Users []User `json:"users"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return response.Users, nil
}

func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	params := url.Values{
		"type": {"local"}, "offset": {"0"}, "limit": {"-1"}, "sort_by": {"name"},
		"sort_direction": {"ASC"}, "additional": {`["description"]`},
	}
	api := "SYNO.Core.User.Group"
	if _, ok := c.apis["SYNO.Core.Group"]; ok {
		api = "SYNO.Core.Group"
	}
	data, err := c.call(ctx, http.MethodPost, api, 1, "list", params)
	if err != nil {
		return nil, err
	}
	var response struct {
		Groups []Group `json:"groups"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return response.Groups, nil
}

func (c *Client) ListGroupMembers(ctx context.Context, group string) ([]string, error) {
	if strings.TrimSpace(group) == "" {
		return nil, errors.New("DSM 群组名不能为空")
	}
	data, err := c.call(ctx, http.MethodPost, "SYNO.Core.Group.Member", 1, "list", url.Values{
		"group": {group}, "ingroup": {"true"}, "offset": {"0"}, "limit": {"-1"},
	})
	if err != nil {
		return nil, err
	}
	var response struct {
		Users []User `json:"users"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	members := make([]string, 0, len(response.Users))
	for _, user := range response.Users {
		members = append(members, user.Name)
	}
	return members, nil
}

type CreateUserInput struct {
	Name        string `json:"name"`
	Password    string `json:"password"`
	Description string `json:"description"`
	Email       string `json:"email"`
}

func (c *Client) CreateTestUser(ctx context.Context, prefix string, input CreateUserInput) error {
	if err := validateTestName(prefix, input.Name); err != nil {
		return err
	}
	return c.CreateUser(ctx, input)
}

func (c *Client) CreateUser(ctx context.Context, input CreateUserInput) error {
	if strings.TrimSpace(input.Name) == "" {
		return errors.New("DSM 用户名不能为空")
	}
	if len(input.Password) < 12 {
		return errors.New("DSM 用户密码至少需要 12 个字符")
	}
	params := url.Values{
		"name": {input.Name}, "password": {input.Password}, "description": {input.Description},
		"email": {input.Email}, "expired": {"normal"}, "cannot_chg_passwd": {"false"},
		"passwd_never_expire": {"true"}, "notify_by_email": {"false"}, "send_password": {"false"},
	}
	_, err := c.call(ctx, http.MethodPost, "SYNO.Core.User", 1, "create", params)
	return err
}

func (c *Client) SetTestUserEnabled(ctx context.Context, prefix, name string, enabled bool) error {
	if err := validateTestName(prefix, name); err != nil {
		return err
	}
	return c.SetUserEnabled(ctx, name, enabled)
}

func (c *Client) SetUserEnabled(ctx context.Context, name string, enabled bool) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("DSM 用户名不能为空")
	}
	expired := "now"
	if enabled {
		expired = "normal"
	}
	_, err := c.call(ctx, http.MethodPost, "SYNO.Core.User", 1, "set", url.Values{"name": {name}, "expired": {expired}})
	return err
}

func (c *Client) SetTestUserGroups(ctx context.Context, prefix, name string, join, leave []string) error {
	if err := validateTestName(prefix, name); err != nil {
		return err
	}
	return c.SetUserGroups(ctx, name, join, leave)
}

func (c *Client) SetUserGroups(ctx context.Context, name string, join, leave []string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("DSM 用户名不能为空")
	}
	if _, ok := c.apis["SYNO.Core.Group.Member"]; !ok {
		return errors.New("DSM 未公布群组成员管理 API SYNO.Core.Group.Member")
	}
	encodedNames, _ := json.Marshal([]string{name})
	for _, group := range join {
		if strings.TrimSpace(group) == "" {
			continue
		}
		if _, err := c.call(ctx, http.MethodPost, "SYNO.Core.Group.Member", 1, "add", url.Values{
			"group": {group}, "name": {string(encodedNames)},
		}); err != nil {
			return fmt.Errorf("加入群组 %s: %w", group, err)
		}
	}
	for _, group := range leave {
		if strings.TrimSpace(group) == "" {
			continue
		}
		if _, err := c.call(ctx, http.MethodPost, "SYNO.Core.Group.Member", 1, "remove", url.Values{
			"group": {group}, "name": {string(encodedNames)},
		}); err != nil {
			return fmt.Errorf("移出群组 %s: %w", group, err)
		}
	}
	return nil
}

func (c *Client) CreateGroup(ctx context.Context, name, description string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("DSM 群组名不能为空")
	}
	api := "SYNO.Core.User.Group"
	if _, ok := c.apis["SYNO.Core.Group"]; ok {
		api = "SYNO.Core.Group"
	}
	_, err := c.call(ctx, http.MethodPost, api, 1, "create", url.Values{
		"name": {name}, "description": {description},
	})
	return err
}

// UploadPackage uploads an SPK to DSM's temporary package staging area. It is
// used by the maintainer-only deployment CLI; NASLink never calls it during
// normal directory synchronization.
func (c *Client) UploadPackage(ctx context.Context, filePath string) (string, error) {
	info, ok := c.apis["SYNO.Core.Package.Installation"]
	if !ok {
		return "", errors.New("DSM 未公布套件安装 API")
	}
	payload, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer payload.Close()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("additional", `[]`); err != nil {
		return "", err
	}
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, payload); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	version := info.MinVersion
	query := url.Values{
		"api": {"SYNO.Core.Package.Installation"}, "version": {fmt.Sprint(version)},
		"method": {"upload"}, "_sid": {c.sid},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+apiPath(info.Path)+"?"+query.Encode(), &body)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("X-SYNO-TOKEN", c.synoToken)
	requestHash, err := c.nextDSM7RequestHash()
	if err != nil {
		return "", err
	}
	if requestHash != "" {
		request.Header.Set("X-SYNO-HASH", requestHash)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("DSM HTTP status %d", response.StatusCode)
	}
	var envelope apiEnvelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return "", err
	}
	if !envelope.Success {
		code := 0
		if envelope.Error != nil {
			code = envelope.Error.Code
		}
		return "", &APIError{API: "SYNO.Core.Package.Installation", Method: "upload", Code: code}
	}
	var data struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		return "", err
	}
	if data.TaskID == "" {
		return "", errors.New("DSM 上传成功但未返回任务 ID")
	}
	return data.TaskID, nil
}

func (c *Client) ConfirmPassword(ctx context.Context) (string, error) {
	if _, ok := c.apis["SYNO.Core.User.PasswordConfirm"]; !ok {
		return "", errors.New("DSM 未公布管理密码确认 API")
	}
	data, err := c.call(ctx, http.MethodPost, "SYNO.Core.User.PasswordConfirm", 1, "auth", url.Values{
		"password": {c.password},
	})
	if err != nil {
		return "", err
	}
	var response struct {
		Token string `json:"SynoConfirmPWToken"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", err
	}
	if response.Token == "" {
		return "", errors.New("DSM 密码确认成功但未返回确认令牌")
	}
	return response.Token, nil
}

func (c *Client) UpgradePackage(ctx context.Context, taskID, confirmToken string) error {
	if strings.TrimSpace(taskID) == "" {
		return errors.New("套件上传任务 ID 不能为空")
	}
	if strings.TrimSpace(confirmToken) == "" {
		return errors.New("DSM 管理密码确认令牌不能为空")
	}
	_, err := c.call(ctx, http.MethodPost, "SYNO.Core.Package.Installation", 1, "upgrade", url.Values{
		"type": {"0"}, "check_codesign": {"false"}, "force": {"false"},
		"installrunpackage": {"true"}, "task_id": {taskID}, "extra_values": {`{}`},
		"SynoConfirmPWToken": {confirmToken},
	})
	return err
}

func validateTestName(prefix, name string) error {
	if prefix == "" {
		prefix = DefaultMutationPrefix
	}
	if !strings.HasPrefix(name, prefix) || len(name) <= len(prefix) {
		return fmt.Errorf("安全拦截：只允许操作 %s 前缀的测试账号", prefix)
	}
	return nil
}

func (c *Client) Probe(ctx context.Context) (ProbeReport, error) {
	report := ProbeReport{BaseURL: c.baseURL, CheckedAt: time.Now().UTC(), APIAvailable: map[string]APIInfo{}}
	apis, err := c.Discover(ctx)
	if err != nil {
		return report, err
	}
	required := []string{"SYNO.API.Auth", "SYNO.Core.User"}
	for _, name := range required {
		if info, ok := apis[name]; ok {
			report.APIAvailable[name] = info
		} else {
			report.MissingAPIs = append(report.MissingAPIs, name)
		}
	}
	groupAPIFound := false
	for _, name := range []string{"SYNO.Core.Group", "SYNO.Core.User.Group"} {
		if info, ok := apis[name]; ok {
			report.APIAvailable[name] = info
			groupAPIFound = true
		}
	}
	if !groupAPIFound {
		report.MissingAPIs = append(report.MissingAPIs, "SYNO.Core.Group|SYNO.Core.User.Group")
	}
	optional := []string{"SYNO.Core.Group.Member", "SYNO.Core.Package", "SYNO.Core.AppPriv", "SYNO.FileStation.Info"}
	for _, name := range optional {
		if info, ok := apis[name]; ok {
			report.APIAvailable[name] = info
		}
	}
	if len(report.MissingAPIs) > 0 {
		return report, fmt.Errorf("DSM 缺少必要内部 API: %s", strings.Join(report.MissingAPIs, ", "))
	}
	if err := c.Login(ctx); err != nil {
		return report, err
	}
	defer c.Logout(context.Background())
	report.Users, err = c.ListUsers(ctx)
	if err != nil {
		return report, err
	}
	report.Groups, err = c.ListGroups(ctx)
	if err != nil {
		return report, err
	}
	if _, ok := c.apis["SYNO.Core.Group.Member"]; ok {
		userIndex := make(map[string]int, len(report.Users))
		for index, user := range report.Users {
			userIndex[user.Name] = index
			report.Users[index].Groups = nil
		}
		for _, group := range report.Groups {
			members, memberErr := c.ListGroupMembers(ctx, group.Name)
			if memberErr != nil {
				return report, fmt.Errorf("读取群组 %s 成员: %w", group.Name, memberErr)
			}
			for _, member := range members {
				if index, exists := userIndex[member]; exists {
					report.Users[index].Groups = append(report.Users[index].Groups, group.Name)
				}
			}
		}
	}
	report.UserCount, report.GroupCount = len(report.Users), len(report.Groups)
	report.ReadOnlyPassed = true
	return report, nil
}

func (c *Client) call(ctx context.Context, httpMethod, api string, version int, method string, params url.Values) (json.RawMessage, error) {
	if params == nil {
		params = url.Values{}
	}
	info, ok := c.apis[api]
	if !ok && api != "SYNO.API.Auth" {
		return nil, fmt.Errorf("DSM 未公布 API %s", api)
	}
	if ok {
		if version < info.MinVersion {
			version = info.MinVersion
		}
		if version > info.MaxVersion {
			version = info.MaxVersion
		}
	}
	params.Set("api", api)
	params.Set("version", fmt.Sprint(version))
	params.Set("method", method)
	if c.sid != "" {
		params.Set("_sid", c.sid)
	}
	path := "/webapi/entry.cgi"
	if ok {
		path = apiPath(info.Path)
	}
	envelope, err := c.request(ctx, httpMethod, path, params)
	if err != nil {
		return nil, err
	}
	return envelope.Data, nil
}

func (c *Client) request(ctx context.Context, method, path string, values url.Values) (apiEnvelope, error) {
	var request *http.Request
	var err error
	endpoint := c.baseURL + path
	if method == http.MethodGet {
		request, err = http.NewRequestWithContext(ctx, method, endpoint+"?"+values.Encode(), nil)
	} else {
		request, err = http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(values.Encode()))
		if request != nil {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return apiEnvelope{}, err
	}
	request.Header.Set("Accept", "application/json")
	if c.synoToken != "" {
		// DSM 7.3 Core APIs reject an otherwise valid SID with code 119 when
		// the CSRF token is sent only as a form parameter. The request header
		// works for Core APIs and remains compatible with the public WebAPI.
		request.Header.Set("X-SYNO-TOKEN", c.synoToken)
	}
	requestHash, err := c.nextDSM7RequestHash()
	if err != nil {
		return apiEnvelope{}, fmt.Errorf("生成 DSM 7 请求校验: %w", err)
	}
	if requestHash != "" {
		request.Header.Set("X-SYNO-HASH", requestHash)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return apiEnvelope{}, fmt.Errorf("request DSM: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		detail := strings.TrimSpace(string(body))
		if detail == "" {
			return apiEnvelope{}, fmt.Errorf("DSM HTTP status %d", response.StatusCode)
		}
		return apiEnvelope{}, fmt.Errorf("DSM HTTP status %d: %s", response.StatusCode, detail)
	}
	var envelope apiEnvelope
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&envelope); err != nil {
		return apiEnvelope{}, fmt.Errorf("decode DSM response: %w", err)
	}
	if !envelope.Success {
		apiName, methodName := values.Get("api"), values.Get("method")
		apiErr := &APIError{API: apiName, Method: methodName}
		if envelope.Error != nil {
			apiErr.Code = envelope.Error.Code
			if len(envelope.Error.Errors) > 0 {
				apiErr.Detail = ": " + string(envelope.Error.Errors)
			}
		}
		return apiEnvelope{}, apiErr
	}
	return envelope, nil
}

func apiPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/webapi/entry.cgi"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	if strings.HasPrefix(path, "webapi/") {
		return "/" + path
	}
	return "/webapi/" + path
}

func cloneAPIMap(input map[string]APIInfo) map[string]APIInfo {
	out := make(map[string]APIInfo, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
