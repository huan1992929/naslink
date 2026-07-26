package wecom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAuthURL      = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"
	DefaultInAppAuthURL = "https://open.weixin.qq.com/connect/oauth2/authorize"
	DefaultAPIBase      = "https://qyapi.weixin.qq.com"
)

type Config struct {
	CorpID, AgentID, Secret, AuthURL, InAppAuthURL, APIBaseURL string
	HTTPClient                                                 *http.Client
}

type Client struct {
	cfg  Config
	http *http.Client
}

type Department struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	ParentID int64  `json:"parentid"`
	Order    int64  `json:"order"`
}
type DirectoryUser struct {
	UserID         string  `json:"userid"`
	Name           string  `json:"name"`
	DepartmentIDs  []int64 `json:"department"`
	IsLeaderInDept []int   `json:"is_leader_in_dept,omitempty"`
	Email          string  `json:"email"`
	BizMail        string  `json:"biz_mail"`
	Mobile         string  `json:"mobile"`
	Status         int     `json:"status"`
}
type Directory struct {
	Departments []Department
	Users       []DirectoryUser
}
type User struct {
	UserID string
	Name   string
	Email  string
}

func (u User) Subject() string { return "userid:" + u.UserID }

type apiError struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}
type tokenResponse struct {
	apiError
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.CorpID) == "" || strings.TrimSpace(cfg.AgentID) == "" || strings.TrimSpace(cfg.Secret) == "" {
		return nil, errors.New("企业微信 Corp ID、Agent ID 和 Secret 不能为空")
	}
	if cfg.AuthURL == "" {
		cfg.AuthURL = DefaultAuthURL
	}
	if cfg.InAppAuthURL == "" {
		cfg.InAppAuthURL = DefaultInAppAuthURL
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = DefaultAPIBase
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	cfg.APIBaseURL = strings.TrimRight(cfg.APIBaseURL, "/")
	return &Client{cfg: cfg, http: cfg.HTTPClient}, nil
}

func (c *Client) AuthorizationURL(redirectURI, state string) string {
	return c.QRAuthorizationURL(redirectURI, state)
}

func (c *Client) QRAuthorizationURL(redirectURI, state string) string {
	q := url.Values{"appid": {c.cfg.CorpID}, "agentid": {c.cfg.AgentID}, "redirect_uri": {redirectURI}, "state": {state}}
	return c.cfg.AuthURL + "?" + q.Encode()
}

// InAppAuthorizationURL is the silent OAuth entry used inside the WeCom app.
// snsapi_base identifies the signed-in employee without prompting for consent.
func (c *Client) InAppAuthorizationURL(redirectURI, state string) string {
	q := url.Values{
		"appid": {c.cfg.CorpID}, "redirect_uri": {redirectURI},
		"response_type": {"code"}, "scope": {"snsapi_base"}, "state": {state},
	}
	return c.cfg.InAppAuthURL + "?" + q.Encode() + "#wechat_redirect"
}

func IsInAppBrowser(userAgent string) bool {
	value := strings.ToLower(userAgent)
	return strings.Contains(value, "wxwork") || strings.Contains(value, "wecom")
}

func (c *Client) TestAppCredentials(ctx context.Context) (time.Duration, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return 0, err
	}
	return time.Duration(token.ExpiresIn) * time.Second, nil
}

func (c *Client) ExchangeCode(ctx context.Context, code string) (User, error) {
	if code == "" {
		return User{}, errors.New("企业微信回调缺少 code")
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return User{}, err
	}
	var identity struct {
		apiError
		UserID string `json:"UserId"`
		OpenID string `json:"OpenId"`
	}
	paths := []string{"/cgi-bin/user/getuserinfo", "/cgi-bin/auth/getuserinfo"}
	var last error
	for _, path := range paths {
		last = c.get(ctx, path, url.Values{"access_token": {token.AccessToken}, "code": {code}}, &identity)
		if last == nil && identity.ErrCode == 0 && identity.UserID != "" {
			break
		}
	}
	if last != nil {
		return User{}, last
	}
	if identity.ErrCode != 0 {
		return User{}, fmt.Errorf("企业微信身份接口失败: %d %s", identity.ErrCode, identity.ErrMsg)
	}
	if identity.UserID == "" {
		return User{}, errors.New("企业微信未返回 UserId；外部联系人 OpenId 不能绑定 DSM 个人账号")
	}
	var detail struct {
		apiError
		UserID  string `json:"userid"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		BizMail string `json:"biz_mail"`
	}
	if err := c.get(ctx, "/cgi-bin/user/get", url.Values{"access_token": {token.AccessToken}, "userid": {identity.UserID}}, &detail); err != nil {
		return User{}, err
	}
	if detail.ErrCode != 0 {
		return User{}, fmt.Errorf("企业微信成员详情失败: %d %s", detail.ErrCode, detail.ErrMsg)
	}
	email := detail.Email
	if email == "" {
		email = detail.BizMail
	}
	return User{UserID: identity.UserID, Name: detail.Name, Email: email}, nil
}

func (c *Client) FetchDirectory(ctx context.Context) (Directory, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return Directory{}, err
	}
	var departments struct {
		apiError
		Departments []Department `json:"department"`
	}
	if err := c.get(ctx, "/cgi-bin/department/list", url.Values{"access_token": {token.AccessToken}}, &departments); err != nil {
		return Directory{}, err
	}
	if departments.ErrCode != 0 {
		return Directory{}, fmt.Errorf("企业微信部门接口失败: %d %s", departments.ErrCode, departments.ErrMsg)
	}
	seen := map[string]DirectoryUser{}
	for _, department := range departments.Departments {
		var members struct {
			apiError
			Users []DirectoryUser `json:"userlist"`
		}
		q := url.Values{"access_token": {token.AccessToken}, "department_id": {strconv.FormatInt(department.ID, 10)}, "fetch_child": {"0"}}
		if err := c.get(ctx, "/cgi-bin/user/list", q, &members); err != nil {
			return Directory{}, err
		}
		if members.ErrCode != 0 {
			return Directory{}, fmt.Errorf("企业微信部门 %d 成员接口失败: %d %s", department.ID, members.ErrCode, members.ErrMsg)
		}
		for _, user := range members.Users {
			if user.UserID != "" {
				seen[user.UserID] = user
			}
		}
	}
	out := Directory{Departments: departments.Departments}
	for _, user := range seen {
		out.Users = append(out.Users, user)
	}
	return out, nil
}

func (c *Client) accessToken(ctx context.Context) (tokenResponse, error) {
	var result tokenResponse
	err := c.get(ctx, "/cgi-bin/gettoken", url.Values{"corpid": {c.cfg.CorpID}, "corpsecret": {c.cfg.Secret}}, &result)
	if err != nil {
		return result, err
	}
	if result.ErrCode != 0 || result.AccessToken == "" {
		return result, fmt.Errorf("企业微信获取 access_token 失败: %d %s", result.ErrCode, result.ErrMsg)
	}
	return result, nil
}

func (c *Client) get(ctx context.Context, path string, query url.Values, target any) error {
	u := c.cfg.APIBaseURL + path + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("企业微信请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("企业微信 API %s 返回 HTTP %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("企业微信响应无效: %w", err)
	}
	return nil
}
