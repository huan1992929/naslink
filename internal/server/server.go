package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	dingstream "github.com/open-dingtalk/dingtalk-stream-sdk-go/client"
	dingevent "github.com/open-dingtalk/dingtalk-stream-sdk-go/event"
	dingpayload "github.com/open-dingtalk/dingtalk-stream-sdk-go/payload"
	"naslink/internal/config"
	"naslink/internal/dingtalk"
	"naslink/internal/dsm"
	"naslink/internal/license"
	"naslink/internal/oidc"
	appstate "naslink/internal/state"
	"naslink/internal/syncengine"
	"naslink/internal/wecom"
)

//go:embed web/*
var webAssets embed.FS

type Server struct {
	manager        *config.Manager
	oidc           *oidc.Provider
	store          *appstate.Store
	license        *license.Manager
	logger         *slog.Logger
	sessions       *sessionStore
	eventMu        sync.Mutex
	syncMu         sync.Mutex
	streamMu       sync.RWMutex
	dingTalkStream dingTalkStreamState
}

type dingTalkStreamState struct {
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

type session struct {
	CSRF      string
	ExpiresAt time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]session
}

func New(manager *config.Manager, oidcProvider *oidc.Provider, store *appstate.Store, licenseManager *license.Manager, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{manager: manager, oidc: oidcProvider, store: store, license: licenseManager, logger: logger, sessions: &sessionStore{sessions: map[string]session{}}, dingTalkStream: dingTalkStreamState{Status: "pending", Message: "等待服务检查 Stream 连接"}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.oidc.Register(mux)
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("POST /api/v1/setup", s.setup)
	mux.HandleFunc("POST /api/v1/session", s.login)
	mux.HandleFunc("DELETE /api/v1/session", s.requireSession(s.logout))
	mux.HandleFunc("GET /api/v1/onboarding", s.requireSession(s.getOnboarding))
	mux.HandleFunc("POST /api/v1/onboarding/start", s.requireSession(s.startOnboarding))
	mux.HandleFunc("POST /api/v1/onboarding/dsm/connect", s.requireSession(s.connectOnboardingDSM))
	mux.HandleFunc("POST /api/v1/onboarding/identity/connect", s.requireSession(s.connectOnboardingIdentity))
	mux.HandleFunc("POST /api/v1/onboarding/scope", s.requireSession(s.saveOnboardingScope))
	mux.HandleFunc("POST /api/v1/onboarding/matches/accept-safe", s.requireSession(s.acceptSafeOnboardingMatches))
	mux.HandleFunc("POST /api/v1/onboarding/sync/enable", s.requireSession(s.enableOnboardingSync))
	mux.HandleFunc("POST /api/v1/onboarding/drive/skip", s.requireSession(s.skipDriveOnboarding))
	mux.HandleFunc("POST /api/v1/onboarding/complete", s.requireSession(s.completeOnboarding))
	mux.HandleFunc("GET /api/v1/tasks", s.requireSession(s.getTasks))
	mux.HandleFunc("GET /api/v1/support/diagnostics", s.requireSession(s.diagnostics))
	mux.HandleFunc("GET /api/v1/drive/readiness", s.requireSession(s.driveReadiness))
	mux.HandleFunc("POST /api/v1/drive/preflight", s.requireSession(s.drivePreflight))
	mux.HandleFunc("GET /api/v1/settings", s.requireSession(s.getSettings))
	mux.HandleFunc("PUT /api/v1/settings", s.requireSession(s.updateSettings))
	mux.HandleFunc("POST /api/v1/dsm/probe", s.requireSession(s.probeDSM))
	mux.HandleFunc("POST /api/v1/dsm/mutate", s.requireSession(s.mutateDSM))
	mux.HandleFunc("POST /api/v1/dingtalk/test", s.requireSession(s.testDingTalk))
	mux.HandleFunc("POST /api/v1/dingtalk/diagnose", s.requireSession(s.diagnoseDingTalk))
	mux.HandleFunc("POST /api/v1/dingtalk/directory", s.requireSession(s.refreshDingTalkDirectory))
	mux.HandleFunc("POST /api/v1/identity/test", s.requireSession(s.testIdentitySource))
	mux.HandleFunc("POST /api/v1/identity/directory", s.requireSession(s.refreshIdentityDirectory))
	mux.HandleFunc("GET /events/wecom", s.verifyWeComCallback)
	mux.HandleFunc("POST /events/wecom", s.receiveWeComCallback)
	mux.HandleFunc("POST /events/dingtalk", s.receiveDingTalkEvent)
	mux.HandleFunc("POST /api/v1/directory/import", s.requireSession(s.importDirectory))
	mux.HandleFunc("GET /api/v1/system", s.requireSession(s.systemState))
	mux.HandleFunc("POST /api/v1/matches/recalculate", s.requireSession(s.recalculateMatches))
	mux.HandleFunc("POST /api/v1/matches/confirm", s.requireSession(s.confirmMatch))
	mux.HandleFunc("POST /api/v1/departments/map", s.requireSession(s.mapDepartment))
	mux.HandleFunc("PUT /api/v1/policy", s.requireSession(s.updatePolicy))
	mux.HandleFunc("POST /api/v1/sync/preview", s.requireSession(s.previewSync))
	mux.HandleFunc("POST /api/v1/sync/{id}/apply", s.requireSession(s.applySync))
	mux.HandleFunc("POST /api/v1/sync/{id}/retry", s.requireSession(s.retrySync))
	mux.HandleFunc("GET /api/v1/backup", s.requireSession(s.downloadBackup))
	mux.HandleFunc("GET /api/v1/license", s.requireSession(s.getLicense))
	mux.HandleFunc("POST /api/v1/license", s.requireSession(s.installLicense))
	mux.HandleFunc("POST /api/v1/license/activate", s.requireSession(s.activateLicense))
	mux.HandleFunc("POST /api/v1/bindings", s.requireSession(s.upsertBinding))
	assets, _ := fs.Sub(webAssets, "web")
	mux.Handle("/", securityHeaders(http.FileServer(http.FS(assets))))
	return requestLog(s.logger, mux)
}

func (s *Server) StartScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		var lastAttempt time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				snapshot := s.store.Snapshot()
				policy := snapshot.Policy
				if !policy.ScheduleEnabled || policy.ScheduleInterval < 15 || (!lastAttempt.IsZero() && now.Sub(lastAttempt) < time.Duration(policy.ScheduleInterval)*time.Minute) {
					continue
				}
				lastAttempt = now
				if err := s.runScheduledCalibration(ctx); err != nil {
					s.logger.Error("scheduled calibration failed", "error", err)
					s.audit("scheduled_calibration", "sync", false, map[string]any{"error": err.Error()})
				} else {
					s.audit("scheduled_calibration", "sync", true, nil)
				}
			}
		}
	}()
}

// StartIdentityEvents maintains DingTalk's official Stream connection. WeCom
// delivers signed callbacks through /events/wecom and does not need a socket.
func (s *Server) StartIdentityEvents(ctx context.Context) {
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			if s.manager.ActiveIdentitySource() != "dingtalk" {
				s.setDingTalkStreamState("inactive", "当前主身份源不是钉钉")
				if !waitContext(ctx, time.Minute) {
					return
				}
				continue
			}
			cfg, err := s.manager.DingTalkCredentials()
			if err != nil || cfg.ClientID == "" || cfg.ClientSecret == "" {
				s.setDingTalkStreamState("not_configured", "请先保存钉钉 Client ID 和 Client Secret")
				if !waitContext(ctx, time.Minute) {
					return
				}
				continue
			}
			s.setDingTalkStreamState("connecting", "正在建立钉钉 Stream 长连接")
			client := dingstream.NewStreamClient(dingstream.WithAppCredential(dingstream.NewAppCredentialConfig(cfg.ClientID, cfg.ClientSecret)))
			client.RegisterAllEventRouter(func(_ context.Context, frame *dingpayload.DataFrame) (*dingpayload.DataFrameResponse, error) {
				header := dingevent.NewEventHeaderFromDataFrame(frame)
				response := dingpayload.NewSuccessDataFrameResponse()
				_ = response.SetJson(dingevent.NewEventProcessResultSuccess())
				if !isDingTalkPersonnelEvent(header.EventType) {
					return response, nil
				}
				metadata := map[string]any{}
				_ = json.Unmarshal([]byte(frame.Data), &metadata)
				changeType := header.EventType
				externalID := firstString(metadata, "userId", "userid", "staffId", "deptId")
				stored, storeErr := s.store.AddSourceEvent(appstate.SourceEvent{ID: header.EventId, SourceType: "dingtalk", EventType: "personnel_change", ChangeType: changeType, ExternalID: externalID, Metadata: metadata})
				if storeErr != nil {
					_ = response.SetJson(dingevent.NewEventProcessResultLater())
					return response, storeErr
				}
				go s.processSourceEvent(stored)
				return response, nil
			})
			if err := client.Start(ctx); err != nil {
				s.setDingTalkStreamState("error", err.Error())
				s.logger.Error("DingTalk Stream connection failed", "error", err)
				if !waitContext(ctx, 30*time.Second) {
					return
				}
				continue
			}
			s.setDingTalkStreamState("connected", "Stream 长连接已建立；事件类型仍需在钉钉后台订阅")
			s.logger.Info("DingTalk Stream connected")
			<-ctx.Done()
			client.Close()
			s.setDingTalkStreamState("stopped", "服务已停止 Stream 连接")
			return
		}
	}()
}

func (s *Server) setDingTalkStreamState(status, message string) {
	s.streamMu.Lock()
	s.dingTalkStream = dingTalkStreamState{Status: status, Message: message, CheckedAt: time.Now().UTC()}
	s.streamMu.Unlock()
}

func (s *Server) getDingTalkStreamState() dingTalkStreamState {
	s.streamMu.RLock()
	defer s.streamMu.RUnlock()
	return s.dingTalkStream
}

func (s *Server) StartLicenseValidation(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			if err := s.validateRemoteLicense(ctx); err != nil && !errors.Is(err, context.Canceled) {
				s.logger.Warn("remote license validation skipped", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *Server) validateRemoteLicense(ctx context.Context) error {
	status := s.license.Status(time.Now())
	if status.Mode != "license" || status.LicenseID == "" {
		return nil
	}
	cfg, err := s.manager.LicenseCenterCredentials()
	if err != nil {
		return err
	}
	if cfg.URL == "" {
		return nil
	}
	payload, _ := json.Marshal(map[string]string{"license_id": status.LicenseID, "device_id": status.DeviceID})
	requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, strings.TrimRight(cfg.URL, "/")+"/api/v1/validate", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return s.license.RecordRemoteValidation(status.LicenseID, true, "License 已被授权中心撤销或迁移")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("授权中心验证返回 HTTP %d", resp.StatusCode)
	}
	var result struct {
		Valid   bool `json:"valid"`
		Revoked bool `json:"revoked"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&result); err != nil {
		return err
	}
	reason := ""
	if result.Revoked || !result.Valid {
		reason = "License 已被授权中心吊销"
	}
	return s.license.RecordRemoteValidation(status.LicenseID, result.Revoked || !result.Valid, reason)
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func isDingTalkPersonnelEvent(value string) bool {
	value = strings.ToLower(value)
	known := map[string]bool{"user_add_org": true, "user_modify_org": true, "user_leave_org": true, "org_dept_create": true, "org_dept_modify": true, "org_dept_remove": true, "employee_change": true}
	if known[value] {
		return true
	}
	return strings.Contains(value, "user_") || strings.Contains(value, "dept_") || strings.Contains(value, "employee")
}
func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return fmt.Sprint(value)
		}
	}
	return ""
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	public := s.manager.Public()
	licenseStatus := s.license.Status(time.Now())
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "naslink", "version": "0.3.0-rc19", "setup_complete": public.SetupComplete,
		"time": time.Now().UTC(), "license_valid": licenseStatus.Valid, "license_mode": licenseStatus.Mode,
	})
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if s.manager.IsSetup() {
		apiError(w, http.StatusConflict, "already_setup", "管理员已经初始化")
		return
	}
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "origin_rejected", "请求来源不匹配")
		return
	}
	var body struct {
		Password             string `json:"password"`
		PasswordConfirmation string `json:"password_confirmation"`
	}
	if err := decodeJSON(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if body.Password != body.PasswordConfirmation {
		apiError(w, http.StatusBadRequest, "password_mismatch", "两次输入的 NASLink 管理密码不一致")
		return
	}
	if err := s.manager.SetupAdmin(body.Password); err != nil {
		apiError(w, http.StatusBadRequest, "setup_failed", err.Error())
		return
	}
	token, csrf, err := s.sessions.create()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "session_failed", err.Error())
		return
	}
	setSessionCookie(w, r, token)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "csrf_token": csrf, "onboarding": s.onboardingResponse()})
}

type onboardingStep struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

type onboardingResponseBody struct {
	Status            string           `json:"status"`
	Title             string           `json:"title"`
	Message           string           `json:"message"`
	BlockingReasons   []string         `json:"blocking_reasons"`
	RecommendedAction string           `json:"recommended_action"`
	Counts            map[string]int   `json:"counts"`
	CurrentStep       string           `json:"current_step"`
	IdentitySource    string           `json:"identity_source"`
	DriveSkipped      bool             `json:"drive_skipped"`
	UpdatedAt         time.Time        `json:"updated_at,omitempty"`
	Steps             []onboardingStep `json:"steps"`
}

func (s *Server) onboardingResponse() onboardingResponseBody {
	data := s.store.Snapshot()
	public := s.manager.Public()
	onboarding := data.Onboarding
	if onboarding.Version == 0 {
		onboarding = appstate.Onboarding{Version: 1, CurrentStep: "welcome", IdentitySource: public.IdentitySource}
	}
	if onboarding.IdentitySource == "" {
		onboarding.IdentitySource = public.IdentitySource
	}
	if onboarding.CurrentStep == "" {
		onboarding.CurrentStep = "welcome"
	}
	dsmReady := !onboarding.DSMVerifiedAt.IsZero()
	identityReady := !onboarding.IdentityVerifiedAt.IsZero()
	scopeReady := false
	for _, department := range data.Departments {
		if department.Managed {
			scopeReady = true
			break
		}
	}
	matchesReady := len(data.Matches) > 0
	syncReady := data.Policy.ScheduleEnabled
	driveReady := onboarding.DriveSkipped || (public.OIDC.Issuer != "" && public.OIDC.ClientID != "" && public.OIDC.HasClientSecret)
	steps := []onboardingStep{
		{ID: "welcome", Status: onboardingStatus(!onboarding.StartedAt.IsZero()), Title: "开始配置", Message: "选择企业通讯录后，NASLink 会按步骤保存进度。"},
		{ID: "dsm", Status: onboardingStatus(dsmReady), Title: "连接这台群晖", Message: "仅在授权后读取账号和群组。"},
		{ID: "identity", Status: onboardingStatus(identityReady), Title: "连接企业通讯录", Message: "保存凭据后检查通讯录权限。"},
		{ID: "scope", Status: onboardingStatus(scopeReady), Title: "选择同步人员", Message: "先确定范围，不会写入 DSM。"},
		{ID: "matches", Status: onboardingStatus(matchesReady), Title: "确认已有账号", Message: "保护账号和冲突账号不会自动处理。"},
		{ID: "sync", Status: onboardingStatus(syncReady), Title: "启用员工同步", Message: "写入前仍需预览、密码确认和写后复核。"},
		{ID: "drive_optional", Status: onboardingStatus(driveReady), Title: "配置 Drive 免登录（可选）", Message: "稍后配置不会影响员工同步。"},
	}
	response := onboardingResponseBody{
		Status: "in_progress", Title: "继续首次配置", Message: "NASLink 已保存当前进度，可以随时退出后继续。",
		BlockingReasons: []string{}, RecommendedAction: "完成下一步配置", Counts: map[string]int{"departments": len(data.Departments), "users": len(data.Users), "matches": len(data.Matches)},
		CurrentStep: onboarding.CurrentStep, IdentitySource: onboarding.IdentitySource, DriveSkipped: onboarding.DriveSkipped, UpdatedAt: onboarding.UpdatedAt, Steps: steps,
	}
	if !data.Onboarding.CompletedAt.IsZero() {
		response.Status, response.Title, response.Message, response.RecommendedAction = "complete", "首次配置已完成", "员工同步和日常管理已可从首页继续。", "进入 NASLink 首页"
		return response
	}
	for _, step := range steps {
		if step.Status != "complete" && step.ID != "welcome" {
			response.CurrentStep, response.RecommendedAction = step.ID, "完成："+step.Title
			response.BlockingReasons = []string{"尚未完成：" + step.Title}
			return response
		}
	}
	response.CurrentStep, response.RecommendedAction = "complete", "完成首次配置"
	return response
}

func (s *Server) onboardingFailure(w http.ResponseWriter, status int, title, message, action string) {
	response := s.onboardingResponse()
	response.Status, response.Title, response.Message = "blocked", title, message
	response.BlockingReasons = []string{message}
	response.RecommendedAction = action
	writeJSON(w, status, response)
}

type onboardingDSMConnectRequest struct {
	BaseURL     string `json:"base_url"`
	Account     string `json:"account"`
	Password    string `json:"password"`
	InsecureTLS bool   `json:"insecure_tls"`
}

func (s *Server) connectOnboardingDSM(w http.ResponseWriter, r *http.Request) {
	var request onboardingDSMConnectRequest
	if err := decodeJSON(r, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.manager.UpdateOnboardingDSM(request.BaseURL, request.Account, request.Password, request.InsecureTLS); err != nil {
		s.onboardingFailure(w, http.StatusBadRequest, "无法保存群晖连接", err.Error(), "检查群晖地址、管理员账号和密码后重试")
		return
	}
	report, err := s.probe(r.Context())
	if err != nil {
		s.onboardingFailure(w, http.StatusBadGateway, "无法登录这台群晖", "NASLink 尚未修改任何账号或群组。请检查管理员账号、密码和连接地址。", "检查群晖管理员权限后重新连接")
		return
	}
	if err := s.store.MarkOnboardingVerified("dsm"); err != nil {
		apiError(w, http.StatusInternalServerError, "onboarding_update_failed", err.Error())
		return
	}
	if err := s.store.SetDriveServerStatus(report.DriveServerStatus); err != nil {
		apiError(w, http.StatusInternalServerError, "drive_status_store_failed", err.Error())
		return
	}
	current := s.store.Snapshot().Onboarding
	if _, err := s.store.UpdateOnboarding("identity", current.IdentitySource, current.DriveSkipped, false); err != nil {
		apiError(w, http.StatusInternalServerError, "onboarding_update_failed", err.Error())
		return
	}
	response := s.onboardingResponse()
	response.Status, response.Title, response.Message = "complete", "群晖连接成功", "已只读盘点群晖账号和群组；本次没有修改任何内容。"
	response.Counts["dsm_users"], response.Counts["dsm_groups"] = len(report.Users), len(report.Groups)
	writeJSON(w, http.StatusOK, response)
}

type onboardingIdentityConnectRequest struct {
	SourceType string `json:"source_type"`
	DingTalk   struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	} `json:"dingtalk"`
	WeCom struct {
		CorpID  string `json:"corp_id"`
		AgentID string `json:"agent_id"`
		Secret  string `json:"secret"`
	} `json:"wecom"`
}

func (s *Server) connectOnboardingIdentity(w http.ResponseWriter, r *http.Request) {
	var request onboardingIdentityConnectRequest
	if err := decodeJSON(r, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if request.SourceType == "" {
		request.SourceType = s.store.Snapshot().Onboarding.IdentitySource
	}
	if err := s.manager.UpdateOnboardingIdentity(request.SourceType, request.DingTalk.ClientID, request.DingTalk.ClientSecret, request.WeCom.CorpID, request.WeCom.AgentID, request.WeCom.Secret); err != nil {
		s.onboardingFailure(w, http.StatusBadRequest, "请补全企业通讯录凭据", err.Error(), "填写应用凭据后保存并检查权限")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	departments, users, err := s.fetchActiveDirectory(ctx)
	if err != nil {
		s.onboardingFailure(w, http.StatusBadGateway, "还无法读取企业通讯录", "NASLink 尚未修改群晖。请确认已开通部门和员工读取权限后重新检查。", "开通通讯录权限后重新检查")
		return
	}
	if err := s.store.ReplaceDirectory(departments, users); err != nil {
		apiError(w, http.StatusInternalServerError, "directory_store_failed", err.Error())
		return
	}
	report, err := s.probe(ctx)
	if err != nil {
		s.onboardingFailure(w, http.StatusBadGateway, "通讯录已读取，但群晖盘点需要重新检查", "NASLink 尚未修改群晖。请恢复群晖连接后重新检查。", "重新连接这台群晖")
		return
	}
	matches := syncengine.MatchUsers(users, report.Users, s.store.Snapshot().Matches)
	if err := s.store.ReplaceMatches(matches); err != nil {
		apiError(w, http.StatusInternalServerError, "match_store_failed", err.Error())
		return
	}
	if err := s.store.MarkOnboardingVerified("identity"); err != nil {
		apiError(w, http.StatusInternalServerError, "onboarding_update_failed", err.Error())
		return
	}
	current := s.store.Snapshot().Onboarding
	if _, err := s.store.UpdateOnboarding("scope", request.SourceType, current.DriveSkipped, false); err != nil {
		apiError(w, http.StatusInternalServerError, "onboarding_update_failed", err.Error())
		return
	}
	response := s.onboardingResponse()
	response.Status, response.Title, response.Message = "complete", "企业通讯录连接成功", "已读取通讯录；下一步选择需要同步的人员范围。"
	response.Counts["departments"], response.Counts["users"], response.Counts["matches"] = len(departments), len(users), len(matches)
	writeJSON(w, http.StatusOK, response)
}

type onboardingScopeRequest struct {
	Mode          string   `json:"mode"`
	DepartmentIDs []string `json:"department_ids"`
}

func (s *Server) saveOnboardingScope(w http.ResponseWriter, r *http.Request) {
	var request onboardingScopeRequest
	if err := decodeJSON(r, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	snapshot := s.store.Snapshot()
	if len(snapshot.Departments) == 0 {
		s.onboardingFailure(w, http.StatusConflict, "还没有可选择的部门", "请先连接企业通讯录并读取部门列表。", "连接企业通讯录")
		return
	}
	selected := map[string]bool{}
	switch request.Mode {
	case "all_active":
		for _, department := range snapshot.Departments {
			selected[department.ID] = true
		}
	case "selected":
		for _, id := range request.DepartmentIDs {
			selected[strings.TrimSpace(id)] = true
		}
		if len(selected) == 0 {
			s.onboardingFailure(w, http.StatusBadRequest, "请选择至少一个部门", "指定部门模式需要选择需要同步的部门。", "选择同步部门")
			return
		}
	default:
		apiError(w, http.StatusBadRequest, "scope_mode_invalid", "范围必须为 all_active 或 selected")
		return
	}
	known := map[string]bool{}
	for _, department := range snapshot.Departments {
		known[department.ID] = true
	}
	for id := range selected {
		if !known[id] {
			apiError(w, http.StatusBadRequest, "department_not_found", "所选部门不存在")
			return
		}
	}
	for _, department := range snapshot.Departments {
		managed := selected[department.ID]
		group := department.DSMGroup
		if managed && group == "" {
			group = "naslink_dept_" + safeOnboardingID(department.ID)
		}
		if err := s.store.UpsertDepartmentMapping(department.ID, group, managed); err != nil {
			apiError(w, http.StatusInternalServerError, "scope_store_failed", err.Error())
			return
		}
	}
	current := s.store.Snapshot().Onboarding
	if _, err := s.store.UpdateOnboarding("matches", current.IdentitySource, current.DriveSkipped, false); err != nil {
		apiError(w, http.StatusInternalServerError, "onboarding_update_failed", err.Error())
		return
	}
	response := s.onboardingResponse()
	response.Status, response.Title, response.Message = "complete", "人员范围已保存", "本步骤只保存范围，不会修改群晖。"
	response.Counts["managed_departments"] = len(selected)
	writeJSON(w, http.StatusOK, response)
}

func safeOnboardingID(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "department"
	}
	return builder.String()
}

func (s *Server) acceptSafeOnboardingMatches(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.store.Snapshot()
	protected := s.protectedUsers()
	accepted, skipped := 0, 0
	for _, match := range snapshot.Matches {
		if match.Confirmed || match.Status != "auto" || match.Score < 100 || match.DSMUsername == "" || protected[strings.ToLower(match.DSMUsername)] {
			skipped++
			continue
		}
		if err := s.store.ConfirmMatch(match.Subject, match.DSMUsername); err != nil {
			skipped++
			continue
		}
		accepted++
	}
	current := s.store.Snapshot().Onboarding
	if _, err := s.store.UpdateOnboarding("sync", current.IdentitySource, current.DriveSkipped, false); err != nil {
		apiError(w, http.StatusInternalServerError, "onboarding_update_failed", err.Error())
		return
	}
	response := s.onboardingResponse()
	response.Status, response.Title, response.Message = "complete", "安全账号建议已处理", "仅确认了唯一且非保护账号的确定性匹配；冲突账号仍需人工处理。"
	response.Counts["accepted"], response.Counts["skipped"] = accepted, skipped
	writeJSON(w, http.StatusOK, response)
}

type onboardingSyncEnableRequest struct {
	PlanID        string `json:"plan_id"`
	AdminPassword string `json:"admin_password"`
}

func (s *Server) enableOnboardingSync(w http.ResponseWriter, r *http.Request) {
	var request onboardingSyncEnableRequest
	if err := decodeJSON(r, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.manager.VerifyAdmin(request.AdminPassword) {
		s.onboardingFailure(w, http.StatusUnauthorized, "无法确认管理员身份", "NASLink 管理密码不正确，未执行任何群晖写入。", "重新输入 NASLink 管理密码")
		return
	}
	run, ok := s.store.FindRun(request.PlanID)
	if !ok || run.Status != "preview" {
		s.onboardingFailure(w, http.StatusConflict, "同步预览不可用", "请先生成新的同步预览，再确认启用员工同步。", "生成新的同步预览")
		return
	}
	if time.Since(run.CreatedAt) > 30*time.Minute {
		s.onboardingFailure(w, http.StatusConflict, "同步预览已过期", "为避免按旧数据写入，NASLink 已拒绝执行。", "重新生成同步预览")
		return
	}
	licenseStatus := s.license.Status(time.Now())
	if !licenseStatus.Valid || !license.HasFeature(licenseStatus, "sync") {
		s.onboardingFailure(w, http.StatusPaymentRequired, "当前授权不能启用同步", valueOrReason(licenseStatus.Reason, "License 未授权同步功能"), "检查系统授权")
		return
	}
	if !s.syncMu.TryLock() {
		s.onboardingFailure(w, http.StatusConflict, "正在处理另一项同步", "当前同步完成后再试。", "稍后重试")
		return
	}
	defer s.syncMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	report, err := s.probe(ctx)
	if err != nil {
		s.onboardingFailure(w, http.StatusBadGateway, "无法重新检查群晖", "NASLink 未执行任何写入。请恢复群晖连接后重新生成预览。", "重新连接这台群晖")
		return
	}
	latest := syncengine.BuildPlan(s.store.Snapshot(), report)
	if !sameSyncActions(run.Actions, latest.Actions) {
		s.onboardingFailure(w, http.StatusConflict, "同步预览已过期", "群晖或通讯录状态已变化，NASLink 未执行写入。", "重新生成同步预览")
		return
	}
	run, err = s.executeRun(ctx, run, "onboarding")
	if err != nil {
		s.onboardingFailure(w, http.StatusBadGateway, "同步未完成", "NASLink 已停止执行，请检查结果后重试。", "查看同步结果")
		return
	}
	if run.Status == "completed" {
		policy := s.store.Snapshot().Policy
		policy.ScheduleEnabled = true
		if err := s.store.UpdatePolicy(policy); err != nil {
			apiError(w, http.StatusInternalServerError, "policy_update_failed", err.Error())
			return
		}
		current := s.store.Snapshot().Onboarding
		_, _ = s.store.UpdateOnboarding("drive_optional", current.IdentitySource, current.DriveSkipped, false)
	}
	response := s.onboardingResponse()
	response.Status, response.Title, response.Message = run.Status, "员工同步已执行并复核", run.Summary
	response.Counts["successes"], response.Counts["failures"] = run.Successes, run.Failures
	writeJSON(w, http.StatusOK, response)
}

type taskItem struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Title   string `json:"title"`
	Message string `json:"message"`
	Action  string `json:"action"`
}

func (s *Server) pendingTasks() []taskItem {
	snapshot := s.store.Snapshot()
	tasks := []taskItem{}
	for _, match := range snapshot.Matches {
		if !match.Confirmed && (match.Status == "conflict" || match.Status == "review") {
			tasks = append(tasks, taskItem{ID: "match-" + match.Subject, Type: "match_review", Title: "需要确认账号", Message: "存在不能安全自动确认的账号匹配。", Action: "确认已有账号"})
		}
	}
	for _, run := range snapshot.SyncRuns {
		if run.Status == "partial" || run.Status == "failed" {
			tasks = append(tasks, taskItem{ID: "sync-" + run.ID, Type: "sync_failure", Title: "同步需要处理", Message: "存在未完成或未通过复核的同步动作。", Action: "查看同步结果"})
		}
	}
	for _, event := range snapshot.SourceEvents {
		if event.Status == "failed" {
			tasks = append(tasks, taskItem{ID: "event-" + event.ID, Type: "source_event", Title: "人员变动需要检查", Message: "一次人员变动未能生成安全预览。", Action: "检查企业通讯录连接"})
		}
	}
	return tasks
}

func (s *Server) getTasks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tasks": s.pendingTasks(), "count": len(s.pendingTasks())})
}

func (s *Server) diagnostics(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.store.Snapshot()
	public := s.manager.Public()
	latestStatus := "none"
	if len(snapshot.SyncRuns) > 0 {
		latestStatus = snapshot.SyncRuns[0].Status
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":      "0.3.0-rc19",
		"capabilities": map[string]bool{"directory": true, "sync_preview": true, "drive_oidc": public.OIDC.Issuer != ""},
		"connections":  map[string]string{"dsm": connectionState(!snapshot.Onboarding.DSMVerifiedAt.IsZero()), "identity": connectionState(!snapshot.Onboarding.IdentityVerifiedAt.IsZero())},
		"counts":       map[string]int{"departments": len(snapshot.Departments), "users": len(snapshot.Users), "matches": len(snapshot.Matches), "tasks": len(s.pendingTasks())},
		"sync":         map[string]string{"latest_status": latestStatus},
	})
}

func connectionState(ok bool) string {
	if ok {
		return "ready"
	}
	return "not_ready"
}

func (s *Server) driveReadiness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.driveAssessment())
}

func firstMessage(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (s *Server) drivePreflight(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.driveAssessment())
}

func (s *Server) driveAssessment() map[string]any {
	public := s.manager.Public()
	snapshot := s.store.Snapshot()
	reasons := []string{}
	checks := []map[string]string{
		{"key": "issuer", "status": connectionState(public.OIDC.Issuer != ""), "message": "NASLink 公共地址"},
		{"key": "client", "status": connectionState(public.OIDC.ClientID != "" && public.OIDC.HasClientSecret), "message": "DSM OIDC 客户端"},
	}
	if public.OIDC.Issuer == "" || public.OIDC.ClientID == "" || !public.OIDC.HasClientSecret {
		reasons = append(reasons, "请先完成 NASLink 与 DSM 的 Drive 免登录配置")
	}
	if public.IdentitySource == "wecom" {
		checks = append(checks, map[string]string{"key": "drive_url", "status": connectionState(public.WeCom.DriveWebURL != ""), "message": "Synology Drive Web 地址"})
		if public.WeCom.DriveWebURL == "" {
			reasons = append(reasons, "请填写 Synology Drive Web 地址")
		}
	}
	driveStatus := snapshot.Onboarding.DriveServerStatus
	if driveStatus == "" {
		driveStatus = "unknown"
	}
	driveCheck := map[string]string{"key": "drive_server", "status": driveStatus, "message": "Synology Drive Server 运行状态"}
	checks = append(checks, driveCheck)
	switch driveStatus {
	case "installed":
	case "not_installed":
		reasons = append(reasons, "这台群晖未安装 Synology Drive Server")
	case "not_running":
		reasons = append(reasons, "Synology Drive Server 已安装但当前未运行")
	case "error":
		reasons = append(reasons, "无法确认 Synology Drive Server 的运行状态")
	default:
		reasons = append(reasons, "尚未通过群晖运行时检查确认 Synology Drive Server 已安装且可用")
	}
	boundActive := false
	bindings := map[string]config.Binding{}
	for _, binding := range public.Bindings {
		bindings[binding.SourceSubject] = binding
	}
	for _, user := range snapshot.Users {
		if binding, ok := bindings[user.Subject]; ok && user.Active && binding.DSMUsername != "" {
			boundActive = true
			break
		}
	}
	checks = append(checks, map[string]string{"key": "test_user", "status": connectionState(boundActive), "message": "当前在职且已固定绑定的测试员工"})
	if !boundActive {
		reasons = append(reasons, "请先选择一名在职员工并确认其固定 DSM 账号绑定，再测试 Drive 免登录")
	}
	status, action := "ready", "使用已绑定的在职员工测试 Drive 免登录"
	if driveStatus == "unknown" {
		status, action = "needs_live_test", "先连接群晖并执行 Drive Server 运行时检查"
	}
	if len(reasons) > 0 && status != "needs_live_test" {
		status, action = "blocked", "处理："+reasons[0]
	}
	return map[string]any{"status": status, "title": "Drive 配置检查", "message": valueOrReason(firstMessage(reasons), "Drive 免登录配置与运行时检查均已就绪。"), "blocking_reasons": reasons, "recommended_action": action, "counts": map[string]int{}, "checks": checks}
}

func onboardingStatus(ready bool) string {
	if ready {
		return "complete"
	}
	return "not_started"
}

func (s *Server) getOnboarding(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.onboardingResponse())
}

func (s *Server) startOnboarding(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IdentitySource string `json:"identity_source"`
	}
	if err := decodeJSON(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if body.IdentitySource == "" {
		body.IdentitySource = s.manager.Public().IdentitySource
	}
	if _, err := s.store.UpdateOnboarding("dsm", body.IdentitySource, false, false); err != nil {
		apiError(w, http.StatusBadRequest, "onboarding_update_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.onboardingResponse())
}

func (s *Server) skipDriveOnboarding(w http.ResponseWriter, _ *http.Request) {
	current := s.store.Snapshot().Onboarding
	if _, err := s.store.UpdateOnboarding("drive_optional", current.IdentitySource, true, false); err != nil {
		apiError(w, http.StatusInternalServerError, "onboarding_update_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.onboardingResponse())
}

func (s *Server) completeOnboarding(w http.ResponseWriter, _ *http.Request) {
	response := s.onboardingResponse()
	if response.CurrentStep != "complete" {
		apiError(w, http.StatusConflict, "onboarding_incomplete", "请先完成员工同步，或处理当前阻塞项")
		return
	}
	if _, err := s.store.UpdateOnboarding("complete", response.IdentitySource, response.DriveSkipped, true); err != nil {
		apiError(w, http.StatusInternalServerError, "onboarding_update_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.onboardingResponse())
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "origin_rejected", "请求来源不匹配")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.manager.VerifyAdmin(body.Password) {
		time.Sleep(350 * time.Millisecond)
		apiError(w, http.StatusUnauthorized, "invalid_credentials", "管理员密码错误")
		return
	}
	token, csrf, err := s.sessions.create()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "session_failed", err.Error())
		return
	}
	setSessionCookie(w, r, token)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf_token": csrf})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("naslink_session"); err == nil {
		s.sessions.delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "naslink_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.manager.Public())
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var update config.Update
	if err := decodeJSON(r, &update); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.manager.Update(update); err != nil {
		apiError(w, http.StatusBadRequest, "update_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.manager.Public())
}

func (s *Server) probeDSM(w http.ResponseWriter, r *http.Request) {
	client, err := s.dsmClient()
	if err != nil {
		apiError(w, http.StatusBadRequest, "dsm_config", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	report, err := client.Probe(ctx)
	if err != nil {
		apiError(w, http.StatusBadGateway, "dsm_probe_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type mutationRequest struct {
	Action       string              `json:"action"`
	Apply        bool                `json:"apply"`
	Confirmation string              `json:"confirmation"`
	User         dsm.CreateUserInput `json:"user"`
	Name         string              `json:"name"`
	JoinGroups   []string            `json:"join_groups"`
	LeaveGroups  []string            `json:"leave_groups"`
}

func (s *Server) mutateDSM(w http.ResponseWriter, r *http.Request) {
	var request mutationRequest
	if err := decodeJSON(r, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	public := s.manager.Public()
	name := request.Name
	if request.Action == "create_user" {
		name = request.User.Name
	}
	if !strings.HasPrefix(name, public.DSM.MutationPrefix) || len(name) <= len(public.DSM.MutationPrefix) {
		apiError(w, http.StatusForbidden, "safety_guard", "只允许操作测试账号前缀 "+public.DSM.MutationPrefix)
		return
	}
	plan := map[string]any{
		"action": request.Action, "target": name, "apply": request.Apply,
		"message": "预览完成，尚未修改 DSM。",
	}
	if !request.Apply {
		writeJSON(w, http.StatusOK, plan)
		return
	}
	if request.Confirmation != "APPLY NASLINK POC" {
		apiError(w, http.StatusBadRequest, "confirmation_required", "确认词必须为 APPLY NASLINK POC")
		return
	}
	client, err := s.dsmClient()
	if err != nil {
		apiError(w, http.StatusBadRequest, "dsm_config", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if _, err := client.Discover(ctx); err != nil {
		apiError(w, http.StatusBadGateway, "dsm_discovery_failed", err.Error())
		return
	}
	if err := client.Login(ctx); err != nil {
		apiError(w, http.StatusBadGateway, "dsm_login_failed", err.Error())
		return
	}
	defer client.Logout(context.Background())
	prefix := public.DSM.MutationPrefix
	switch request.Action {
	case "create_user":
		err = client.CreateTestUser(ctx, prefix, request.User)
	case "enable_user":
		err = client.SetTestUserEnabled(ctx, prefix, request.Name, true)
	case "disable_user":
		err = client.SetTestUserEnabled(ctx, prefix, request.Name, false)
	case "set_groups":
		err = client.SetTestUserGroups(ctx, prefix, request.Name, request.JoinGroups, request.LeaveGroups)
	default:
		apiError(w, http.StatusBadRequest, "unknown_action", "未知测试操作")
		return
	}
	if err != nil {
		apiError(w, http.StatusBadGateway, "dsm_mutation_failed", err.Error())
		return
	}
	plan["message"] = "测试操作已执行。"
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) testDingTalk(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.manager.DingTalkCredentials()
	if err != nil {
		apiError(w, http.StatusBadRequest, "dingtalk_config", err.Error())
		return
	}
	client, err := dingtalk.New(dingtalk.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, AuthURL: cfg.AuthURL, APIBaseURL: cfg.APIBaseURL})
	if err != nil {
		apiError(w, http.StatusBadRequest, "dingtalk_config", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	expires, err := client.TestAppCredentials(ctx)
	if err != nil {
		apiError(w, http.StatusBadGateway, "dingtalk_test_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token_expires_in": int(expires.Seconds())})
}

type identityTestRequest struct {
	SourceType string `json:"source_type"`
	DingTalk   struct {
		ClientID            string `json:"client_id"`
		ClientSecret        string `json:"client_secret"`
		AuthURL             string `json:"auth_url"`
		APIBaseURL          string `json:"api_base_url"`
		DirectoryAPIBaseURL string `json:"directory_api_base_url,omitempty"`
	} `json:"dingtalk"`
	WeCom struct {
		CorpID       string `json:"corp_id"`
		AgentID      string `json:"agent_id"`
		Secret       string `json:"secret"`
		AuthURL      string `json:"auth_url"`
		InAppAuthURL string `json:"in_app_auth_url"`
		APIBaseURL   string `json:"api_base_url"`
	} `json:"wecom"`
}

func (s *Server) diagnoseDingTalk(w http.ResponseWriter, r *http.Request) {
	var request identityTestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		apiError(w, http.StatusBadRequest, "invalid_json", "检测参数格式错误")
		return
	}
	stored, err := s.manager.DingTalkCredentials()
	if err != nil {
		apiError(w, http.StatusBadRequest, "dingtalk_config", err.Error())
		return
	}
	client, err := dingtalk.New(dingtalk.Config{
		ClientID:            firstNonEmpty(strings.TrimSpace(request.DingTalk.ClientID), stored.ClientID),
		ClientSecret:        firstNonEmpty(request.DingTalk.ClientSecret, stored.ClientSecret),
		AuthURL:             firstNonEmpty(strings.TrimSpace(request.DingTalk.AuthURL), stored.AuthURL),
		APIBaseURL:          firstNonEmpty(strings.TrimSpace(request.DingTalk.APIBaseURL), stored.APIBaseURL),
		DirectoryAPIBaseURL: strings.TrimSpace(request.DingTalk.DirectoryAPIBaseURL),
	})
	if err != nil {
		apiError(w, http.StatusBadRequest, "dingtalk_config", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	diagnostics := client.DiagnoseDirectory(ctx)
	stream := s.getDingTalkStreamState()
	streamCheck := dingtalk.DiagnosticCheck{Key: "stream", Label: "人员变动事件", Required: false, Status: "warning", Message: stream.Message}
	switch stream.Status {
	case "connected":
		streamCheck.Status = "warning"
		streamCheck.Message = "Stream 长连接已建立；事件订阅列表仍需在钉钉后台确认"
	case "connecting", "pending":
		streamCheck.Status = "pending"
	case "error":
		streamCheck.Status = "error"
	}
	diagnostics.Checks = append(diagnostics.Checks, streamCheck)
	writeJSON(w, http.StatusOK, map[string]any{"diagnostics": diagnostics, "stream": stream})
}

func (s *Server) testIdentitySource(w http.ResponseWriter, r *http.Request) {
	var request identityTestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		apiError(w, http.StatusBadRequest, "invalid_json", "验证参数格式错误")
		return
	}
	sourceType := strings.TrimSpace(request.SourceType)
	if sourceType == "" {
		sourceType = s.manager.ActiveIdentitySource()
	}
	if sourceType != "dingtalk" && sourceType != "wecom" {
		apiError(w, http.StatusBadRequest, "identity_source", "身份源必须是 dingtalk 或 wecom")
		return
	}
	if sourceType == "wecom" {
		stored, err := s.manager.WeComCredentials()
		if err != nil {
			apiError(w, http.StatusBadRequest, "wecom_config", err.Error())
			return
		}
		client, err := wecom.New(wecom.Config{
			CorpID: firstNonEmpty(strings.TrimSpace(request.WeCom.CorpID), stored.CorpID), AgentID: firstNonEmpty(strings.TrimSpace(request.WeCom.AgentID), stored.AgentID),
			Secret: firstNonEmpty(request.WeCom.Secret, stored.Secret), AuthURL: firstNonEmpty(strings.TrimSpace(request.WeCom.AuthURL), stored.AuthURL),
			InAppAuthURL: firstNonEmpty(strings.TrimSpace(request.WeCom.InAppAuthURL), stored.InAppAuthURL), APIBaseURL: firstNonEmpty(strings.TrimSpace(request.WeCom.APIBaseURL), stored.APIBaseURL),
		})
		if err != nil {
			apiError(w, http.StatusBadRequest, "wecom_config", err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		expires, err := client.TestAppCredentials(ctx)
		if err != nil {
			apiError(w, http.StatusBadGateway, "wecom_test_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "source_type": "wecom", "token_expires_in": int(expires.Seconds())})
		return
	}
	stored, err := s.manager.DingTalkCredentials()
	if err != nil {
		apiError(w, http.StatusBadRequest, "dingtalk_config", err.Error())
		return
	}
	client, err := dingtalk.New(dingtalk.Config{
		ClientID: firstNonEmpty(strings.TrimSpace(request.DingTalk.ClientID), stored.ClientID), ClientSecret: firstNonEmpty(request.DingTalk.ClientSecret, stored.ClientSecret),
		AuthURL: firstNonEmpty(strings.TrimSpace(request.DingTalk.AuthURL), stored.AuthURL), APIBaseURL: firstNonEmpty(strings.TrimSpace(request.DingTalk.APIBaseURL), stored.APIBaseURL),
	})
	if err != nil {
		apiError(w, http.StatusBadRequest, "dingtalk_config", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	expires, err := client.TestAppCredentials(ctx)
	if err != nil {
		apiError(w, http.StatusBadGateway, "dingtalk_test_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "source_type": "dingtalk", "token_expires_in": int(expires.Seconds())})
}

func (s *Server) systemState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Snapshot())
}

func (s *Server) refreshDingTalkDirectory(w http.ResponseWriter, r *http.Request) {
	s.refreshIdentityDirectory(w, r)
}

func (s *Server) refreshIdentityDirectory(w http.ResponseWriter, r *http.Request) {
	licenseStatus := s.license.Status(time.Now())
	if !licenseStatus.Valid || !license.HasFeature(licenseStatus, "directory") {
		apiError(w, http.StatusPaymentRequired, "license_required", valueOrReason(licenseStatus.Reason, "License 未授权通讯录功能"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	departments, users, err := s.fetchActiveDirectory(ctx)
	if err != nil {
		source := s.manager.ActiveIdentitySource()
		s.audit("identity_directory_refresh", source, false, map[string]any{"error": err.Error()})
		apiError(w, http.StatusBadGateway, "identity_directory_failed", err.Error())
		return
	}
	managedCount := syncengine.ManagedUserCount(users, s.store.Snapshot().Departments)
	if managedCount > licenseStatus.MaxUsers {
		apiError(w, http.StatusPaymentRequired, "license_user_limit", fmt.Sprintf("已选同步范围 %d 人超过 License 上限 %d 人", managedCount, licenseStatus.MaxUsers))
		return
	}
	if err := s.store.ReplaceDirectory(departments, users); err != nil {
		apiError(w, http.StatusInternalServerError, "directory_save_failed", err.Error())
		return
	}
	s.audit("identity_directory_refresh", s.manager.ActiveIdentitySource(), true, map[string]any{"departments": len(departments), "users": len(users)})
	writeJSON(w, http.StatusOK, s.store.Snapshot())
}

func (s *Server) verifyWeComCallback(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.manager.WeComCredentials()
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "wecom_callback_config", err.Error())
		return
	}
	callback, err := wecom.NewCallbackCipher(cfg.CallbackToken, cfg.CallbackAESKey, cfg.CorpID)
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "wecom_callback_config", err.Error())
		return
	}
	plain, err := callback.VerifyAndDecrypt(r.URL.Query().Get("msg_signature"), r.URL.Query().Get("timestamp"), r.URL.Query().Get("nonce"), r.URL.Query().Get("echostr"))
	if err != nil {
		apiError(w, http.StatusForbidden, "wecom_callback_rejected", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(plain)
}

func (s *Server) receiveWeComCallback(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.manager.WeComCredentials()
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "wecom_callback_config", err.Error())
		return
	}
	callback, err := wecom.NewCallbackCipher(cfg.CallbackToken, cfg.CallbackAESKey, cfg.CorpID)
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "wecom_callback_config", err.Error())
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_event", "事件体无效")
		return
	}
	event, err := callback.ParseEvent(r.URL.Query().Get("msg_signature"), r.URL.Query().Get("timestamp"), r.URL.Query().Get("nonce"), string(raw))
	if err != nil {
		apiError(w, http.StatusForbidden, "wecom_callback_rejected", err.Error())
		return
	}
	if event.Event != "change_contact" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
		return
	}
	externalID := event.UserID
	if externalID == "" {
		externalID = event.DepartmentID
	}
	stored, err := s.store.AddSourceEvent(appstate.SourceEvent{SourceType: "wecom", EventType: event.Event, ChangeType: event.ChangeType, ExternalID: externalID, Metadata: map[string]any{"new_user_id": event.NewUserID, "parent_id": event.ParentID}})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "event_store_failed", err.Error())
		return
	}
	go s.processSourceEvent(stored)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("success"))
}

func (s *Server) receiveDingTalkEvent(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.manager.DingTalkCredentials()
	if err != nil || cfg.EventToken == "" {
		apiError(w, http.StatusServiceUnavailable, "dingtalk_event_config", "钉钉事件令牌尚未配置")
		return
	}
	provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if provided == "" || provided != cfg.EventToken {
		apiError(w, http.StatusForbidden, "dingtalk_event_rejected", "钉钉事件令牌无效")
		return
	}
	var body struct {
		EventType  string         `json:"event_type"`
		ChangeType string         `json:"change_type"`
		EventID    string         `json:"event_id"`
		UserID     string         `json:"user_id"`
		DeptID     string         `json:"dept_id"`
		Data       map[string]any `json:"data"`
	}
	if err := decodeJSON(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_event", err.Error())
		return
	}
	if body.EventType == "" {
		body.EventType = "personnel_change"
	}
	externalID := body.UserID
	if externalID == "" {
		externalID = body.DeptID
	}
	stored, err := s.store.AddSourceEvent(appstate.SourceEvent{ID: body.EventID, SourceType: "dingtalk", EventType: body.EventType, ChangeType: body.ChangeType, ExternalID: externalID, Metadata: body.Data})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "event_store_failed", err.Error())
		return
	}
	go s.processSourceEvent(stored)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "event_id": stored.ID})
}

func (s *Server) processSourceEvent(event appstate.SourceEvent) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if event.SourceType != s.manager.ActiveIdentitySource() {
		_ = s.store.MarkSourceEvent(event.ID, "ignored", "事件来源不是当前主身份源")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := s.runEventCalibration(ctx, event); err != nil {
		_ = s.store.MarkSourceEvent(event.ID, "failed", err.Error())
		s.audit("source_event", event.ID, false, map[string]any{"error": err.Error(), "source": event.SourceType})
		return
	}
	_ = s.store.MarkSourceEvent(event.ID, "processed", "")
	s.audit("source_event", event.ID, true, map[string]any{"source": event.SourceType, "change_type": event.ChangeType})
}

func (s *Server) runEventCalibration(ctx context.Context, event appstate.SourceEvent) error {
	status := s.license.Status(time.Now())
	if !status.Valid || !license.HasFeature(status, "directory") {
		return errors.New("License 未授权人员变动同步")
	}
	departments, users, err := s.fetchActiveDirectory(ctx)
	if err != nil {
		return err
	}
	if managedCount := syncengine.ManagedUserCount(users, s.store.Snapshot().Departments); managedCount > status.MaxUsers {
		return fmt.Errorf("已选同步范围 %d 人超过 License 上限 %d", managedCount, status.MaxUsers)
	}
	if err := s.store.ReplaceDirectory(departments, users); err != nil {
		return err
	}
	report, err := s.probe(ctx)
	if err != nil {
		return err
	}
	snapshot := s.store.Snapshot()
	matches := syncengine.MatchUsers(snapshot.Users, report.Users, snapshot.Matches)
	if err := s.store.ReplaceMatches(matches); err != nil {
		return err
	}
	s.confirmAutoMatches(matches)
	run := syncengine.BuildPlan(s.store.Snapshot(), report)
	run.Mode = "event-preview"
	run.Summary = fmt.Sprintf("人员变动事件 %s/%s 已生成待确认计划；%s", event.EventType, event.ChangeType, run.Summary)
	if err := s.store.SaveRun(run); err != nil {
		return err
	}
	if !s.store.Snapshot().Policy.AutoApplyEvents || len(run.Actions) == 0 {
		return nil
	}
	_, err = s.executeRun(ctx, run, "event-auto")
	return err
}

func (s *Server) importDirectory(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Departments []appstate.Department `json:"departments"`
		Users       []appstate.SourceUser `json:"users"`
	}
	if err := decodeJSON(r, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(request.Users) > 10_000 || len(request.Departments) > 2_000 {
		apiError(w, http.StatusBadRequest, "directory_too_large", "导入通讯录超过一期安全上限")
		return
	}
	if err := s.store.ReplaceDirectory(request.Departments, request.Users); err != nil {
		apiError(w, http.StatusInternalServerError, "directory_save_failed", err.Error())
		return
	}
	s.audit("directory_import", "local", true, map[string]any{"departments": len(request.Departments), "users": len(request.Users)})
	writeJSON(w, http.StatusOK, s.store.Snapshot())
}

func (s *Server) recalculateMatches(w http.ResponseWriter, r *http.Request) {
	report, err := s.probe(r.Context())
	if err != nil {
		apiError(w, http.StatusBadGateway, "dsm_probe_failed", err.Error())
		return
	}
	snapshot := s.store.Snapshot()
	matches := syncengine.MatchUsers(snapshot.Users, report.Users, snapshot.Matches)
	if err := s.store.ReplaceMatches(matches); err != nil {
		apiError(w, http.StatusInternalServerError, "match_save_failed", err.Error())
		return
	}
	s.confirmAutoMatches(matches)
	s.audit("matches_recalculated", "directory", true, map[string]any{"matches": len(matches)})
	writeJSON(w, http.StatusOK, s.store.Snapshot())
}

func (s *Server) confirmMatch(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Subject     string `json:"subject"`
		DSMUsername string `json:"dsm_username"`
	}
	if err := decodeJSON(r, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.ConfirmMatch(request.Subject, request.DSMUsername); err != nil {
		apiError(w, http.StatusConflict, "match_conflict", err.Error())
		return
	}
	snapshot := s.store.Snapshot()
	for _, user := range snapshot.Users {
		if user.Subject == request.Subject {
			_ = s.manager.UpsertBinding(config.Binding{SourceType: valueOrReason(user.SourceType, s.manager.ActiveIdentitySource()), SourceSubject: user.Subject, DSMUsername: request.DSMUsername, DisplayName: user.Name, Email: user.Email})
			break
		}
	}
	s.audit("match_confirmed", request.DSMUsername, true, map[string]any{"subject": request.Subject})
	writeJSON(w, http.StatusOK, s.store.Snapshot())
}

func (s *Server) mapDepartment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		DepartmentID string `json:"department_id"`
		DSMGroup     string `json:"dsm_group"`
		Managed      bool   `json:"managed"`
	}
	if err := decodeJSON(r, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if request.Managed && strings.TrimSpace(request.DSMGroup) == "" {
		apiError(w, http.StatusBadRequest, "group_required", "启用同步时必须选择 DSM 群组")
		return
	}
	if strings.EqualFold(request.DSMGroup, "administrators") || strings.EqualFold(request.DSMGroup, "admin") || strings.EqualFold(request.DSMGroup, "system") {
		apiError(w, http.StatusForbidden, "protected_group", "系统或管理员群组不能作为部门同步目标")
		return
	}
	predicted := s.store.Snapshot()
	for i := range predicted.Departments {
		if predicted.Departments[i].ID == request.DepartmentID {
			predicted.Departments[i].DSMGroup = request.DSMGroup
			predicted.Departments[i].Managed = request.Managed
		}
	}
	licenseStatus := s.license.Status(time.Now())
	managedCount := syncengine.ManagedUserCount(predicted.Users, predicted.Departments)
	if licenseStatus.Valid && managedCount > licenseStatus.MaxUsers {
		apiError(w, http.StatusPaymentRequired, "license_user_limit", fmt.Sprintf("启用该部门后同步范围为 %d 人，超过 License 上限 %d 人", managedCount, licenseStatus.MaxUsers))
		return
	}
	if err := s.store.UpsertDepartmentMapping(request.DepartmentID, request.DSMGroup, request.Managed); err != nil {
		apiError(w, http.StatusBadRequest, "department_mapping_failed", err.Error())
		return
	}
	s.audit("department_mapped", request.DepartmentID, true, map[string]any{"group": request.DSMGroup, "managed": request.Managed})
	writeJSON(w, http.StatusOK, s.store.Snapshot())
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	var policy appstate.Policy
	if err := decodeJSON(r, &policy); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.UpdatePolicy(policy); err != nil {
		apiError(w, http.StatusBadRequest, "policy_invalid", err.Error())
		return
	}
	s.audit("policy_updated", "sync", true, nil)
	writeJSON(w, http.StatusOK, s.store.Snapshot())
}

func (s *Server) previewSync(w http.ResponseWriter, r *http.Request) {
	if !s.syncMu.TryLock() {
		apiError(w, http.StatusConflict, "sync_busy", "另一个同步任务正在执行，请稍后再试")
		return
	}
	defer s.syncMu.Unlock()
	report, err := s.probe(r.Context())
	if err != nil {
		apiError(w, http.StatusBadGateway, "dsm_probe_failed", err.Error())
		return
	}
	snapshot := s.store.Snapshot()
	matches := syncengine.MatchUsers(snapshot.Users, report.Users, snapshot.Matches)
	if err := s.store.ReplaceMatches(matches); err != nil {
		apiError(w, http.StatusInternalServerError, "match_save_failed", err.Error())
		return
	}
	s.confirmAutoMatches(matches)
	snapshot = s.store.Snapshot()
	run := syncengine.BuildPlan(snapshot, report)
	if err := s.store.SaveRun(run); err != nil {
		apiError(w, http.StatusInternalServerError, "sync_save_failed", err.Error())
		return
	}
	s.audit("sync_preview", run.ID, true, map[string]any{"actions": len(run.Actions)})
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) applySync(w http.ResponseWriter, r *http.Request) {
	licenseStatus := s.license.Status(time.Now())
	if !licenseStatus.Valid || !license.HasFeature(licenseStatus, "sync") {
		apiError(w, http.StatusPaymentRequired, "license_required", valueOrReason(licenseStatus.Reason, "License 未授权同步功能"))
		return
	}
	snapshot := s.store.Snapshot()
	if syncengine.ManagedUserCount(snapshot.Users, snapshot.Departments) > licenseStatus.MaxUsers {
		apiError(w, http.StatusPaymentRequired, "license_user_limit", "已选同步范围人数超过 License 上限")
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(r, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if request.Confirmation != "APPLY NASLINK SYNC" {
		apiError(w, http.StatusBadRequest, "confirmation_required", "确认词必须为 APPLY NASLINK SYNC")
		return
	}
	run, ok := s.store.FindRun(r.PathValue("id"))
	if !ok || run.Status != "preview" {
		apiError(w, http.StatusConflict, "sync_not_executable", "同步计划不存在或已经执行")
		return
	}
	if !s.syncMu.TryLock() {
		apiError(w, http.StatusConflict, "sync_busy", "另一个同步任务正在执行，请稍后再试")
		return
	}
	defer s.syncMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	report, err := s.probe(ctx)
	if err != nil {
		apiError(w, http.StatusBadGateway, "dsm_probe_failed", err.Error())
		return
	}
	latest := syncengine.BuildPlan(s.store.Snapshot(), report)
	if !sameSyncActions(run.Actions, latest.Actions) {
		apiError(w, http.StatusConflict, "sync_plan_stale", "DSM 或通讯录状态已变化，请重新生成同步计划")
		return
	}
	run, err = s.executeRun(ctx, run, "manual")
	if err != nil {
		apiError(w, http.StatusBadGateway, "sync_execution_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) executeRun(ctx context.Context, run appstate.SyncRun, mode string) (appstate.SyncRun, error) {
	client, err := s.dsmClient()
	if err != nil {
		return run, err
	}
	if _, err := client.Discover(ctx); err != nil {
		return run, err
	}
	if err := client.Login(ctx); err != nil {
		return run, err
	}
	defer client.Logout(context.Background())
	run.Status, run.Mode, run.StartedAt = "running", mode, time.Now().UTC()
	_ = s.store.SaveRun(run)
	protected := s.protectedUsers()
	for i := range run.Actions {
		action := &run.Actions[i]
		if protected[strings.ToLower(action.DSMUsername)] {
			action.ExecutionError = "安全拦截：受保护账号不允许自动修改"
			run.Failures++
			continue
		}
		switch action.Type {
		case "create_user":
			password, passwordErr := randomPassword(s.store.Snapshot().Policy.RandomPasswordN)
			if passwordErr == nil {
				passwordErr = client.CreateUser(ctx, dsm.CreateUserInput{Name: action.DSMUsername, Password: password, Description: action.DisplayName + " [NASLink]", Email: action.Email})
			}
			err = passwordErr
		case "enable_user":
			err = client.SetUserEnabled(ctx, action.DSMUsername, true)
		case "disable_user":
			err = client.SetUserEnabled(ctx, action.DSMUsername, false)
		case "create_group":
			err = client.CreateGroup(ctx, action.DSMUsername, action.DisplayName+" [NASLink]")
		case "set_groups":
			err = client.SetUserGroups(ctx, action.DSMUsername, action.JoinGroups, action.LeaveGroups)
		default:
			err = fmt.Errorf("未知同步动作 %s", action.Type)
		}
		if err != nil {
			action.ExecutionError = err.Error()
			run.Failures++
			s.audit("sync_action", action.DSMUsername, false, map[string]any{"type": action.Type, "error": err.Error()})
			continue
		}
		action.Executed = true
		if verifyErr := s.waitForActionVerification(ctx, client, *action); verifyErr != nil {
			action.ExecutionError = "DSM 写入已接受，但结果复核失败：" + verifyErr.Error()
			action.Verification = "目标状态未生效"
			run.Failures++
			s.audit("sync_action_verify", action.DSMUsername, false, map[string]any{"type": action.Type, "error": verifyErr.Error()})
			continue
		}
		action.Verified = true
		action.Verification = "DSM 复核通过"
		run.Successes++
		if action.Type != "create_group" {
			_ = s.store.MarkManaged(action.DSMUsername)
		}
		if action.Type == "create_user" && action.Subject != "" {
			s.bindSource(action.Subject, action.DSMUsername)
		}
		s.audit("sync_action", action.DSMUsername, true, map[string]any{"type": action.Type, "verified": true})
	}
	run.FinishedAt = time.Now().UTC()
	if run.Failures > 0 {
		run.Status = "partial"
	} else {
		run.Status = "completed"
	}
	run.Summary = fmt.Sprintf("执行并复核完成：已验证 %d，未生效 %d。", run.Successes, run.Failures)
	_ = s.store.SaveRun(run)
	return run, nil
}

func (s *Server) retrySync(w http.ResponseWriter, r *http.Request) {
	original, ok := s.store.FindRun(r.PathValue("id"))
	if !ok || (original.Status != "partial" && original.Status != "failed") {
		apiError(w, http.StatusConflict, "sync_not_retryable", "只能重试部分失败或失败的同步记录")
		return
	}
	retry := appstate.SyncRun{ID: appstate.NewID("sync"), Mode: "retry-preview", Status: "preview", CreatedAt: time.Now().UTC()}
	for _, action := range original.Actions {
		if action.ExecutionError != "" || !action.Executed {
			action.ID = appstate.NewID("act")
			action.ExecutionError = ""
			action.Executed = false
			retry.Actions = append(retry.Actions, action)
		}
	}
	retry.Summary = fmt.Sprintf("从 %s 生成 %d 项失败动作重试计划。", original.ID, len(retry.Actions))
	if err := s.store.SaveRun(retry); err != nil {
		apiError(w, http.StatusInternalServerError, "sync_save_failed", err.Error())
		return
	}
	s.audit("sync_retry_created", retry.ID, true, map[string]any{"source_run": original.ID, "actions": len(retry.Actions)})
	writeJSON(w, http.StatusOK, retry)
}

func (s *Server) downloadBackup(w http.ResponseWriter, _ *http.Request) {
	raw, err := s.store.Export()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "backup_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="naslink-backup-%s.json"`, time.Now().Format("20060102-150405")))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) getLicense(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.license.Status(time.Now()))
}

func (s *Server) installLicense(w http.ResponseWriter, r *http.Request) {
	var envelope license.Envelope
	if err := decodeJSON(r, &envelope); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_license", err.Error())
		return
	}
	raw, _ := json.Marshal(envelope)
	status, err := s.license.Install(raw)
	if err != nil {
		s.audit("license_install", "license", false, map[string]any{"error": err.Error()})
		apiError(w, http.StatusBadRequest, "license_rejected", err.Error())
		return
	}
	s.audit("license_install", status.LicenseID, true, map[string]any{"edition": status.Edition, "max_users": status.MaxUsers})
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) activateLicense(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.manager.LicenseCenterCredentials()
	if err != nil {
		apiError(w, http.StatusBadRequest, "license_center_config", err.Error())
		return
	}
	if cfg.URL == "" || cfg.ActivationCode == "" {
		apiError(w, http.StatusBadRequest, "license_center_config", "授权中心地址和激活码尚未配置")
		return
	}
	payload, _ := json.Marshal(map[string]string{"activation_code": cfg.ActivationCode, "device_id": s.license.DeviceID(), "version": "0.3.0-rc19"})
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.URL, "/")+"/api/v1/activate", bytes.NewReader(payload))
	if err != nil {
		apiError(w, 500, "license_activation_failed", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		apiError(w, http.StatusBadGateway, "license_activation_failed", err.Error())
		return
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(http.MaxBytesReader(w, resp.Body, 1<<20))
	if err != nil {
		apiError(w, 502, "license_activation_failed", err.Error())
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var remote map[string]any
		_ = json.Unmarshal(raw, &remote)
		apiError(w, http.StatusBadGateway, "license_activation_rejected", fmt.Sprintf("授权中心返回 HTTP %d", resp.StatusCode))
		return
	}
	var result struct {
		License license.Envelope `json:"license"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		apiError(w, 502, "license_activation_failed", "授权中心响应无效")
		return
	}
	envelope, _ := json.Marshal(result.License)
	status, err := s.license.Install(envelope)
	if err != nil {
		apiError(w, 400, "license_rejected", err.Error())
		return
	}
	s.audit("license_online_activation", status.LicenseID, true, map[string]any{"center": cfg.URL})
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) upsertBinding(w http.ResponseWriter, r *http.Request) {
	var binding config.Binding
	if err := decodeJSON(r, &binding); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.manager.UpsertBinding(binding); err != nil {
		apiError(w, http.StatusBadRequest, "binding_failed", err.Error())
		return
	}
	subject := binding.SourceSubject
	if subject == "" {
		subject = binding.DingTalkSubject
	}
	if err := s.store.ConfirmMatch(subject, binding.DSMUsername); err != nil {
		apiError(w, http.StatusConflict, "binding_conflict", err.Error())
		return
	}
	s.audit("binding_confirmed", binding.DSMUsername, true, map[string]any{"subject": subject, "source_type": binding.SourceType})
	writeJSON(w, http.StatusOK, s.manager.Public().Bindings)
}

func (s *Server) dingTalkClient() (*dingtalk.Client, error) {
	cfg, err := s.manager.DingTalkCredentials()
	if err != nil {
		return nil, err
	}
	return dingtalk.New(dingtalk.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, AuthURL: cfg.AuthURL, APIBaseURL: cfg.APIBaseURL})
}

func (s *Server) fetchDingDirectory(ctx context.Context) ([]appstate.Department, []appstate.SourceUser, error) {
	client, err := s.dingTalkClient()
	if err != nil {
		return nil, nil, err
	}
	directory, err := client.FetchDirectory(ctx)
	if err != nil {
		return nil, nil, err
	}
	departments := make([]appstate.Department, 0, len(directory.Departments))
	for _, department := range directory.Departments {
		departments = append(departments, appstate.Department{ID: fmt.Sprint(department.ID), ParentID: fmt.Sprint(department.ParentID), Name: department.Name})
	}
	users := make([]appstate.SourceUser, 0, len(directory.Users))
	for _, user := range directory.Users {
		subject := "union:" + user.UnionID
		if user.UnionID == "" {
			subject = "user:" + user.UserID
		}
		departmentIDs := make([]string, 0, len(user.DepartmentIDs))
		for _, id := range user.DepartmentIDs {
			departmentIDs = append(departmentIDs, fmt.Sprint(id))
		}
		leaderIDs := make([]string, 0)
		seenLeaderIDs := map[string]bool{}
		for index, leader := range user.LeaderInDept {
			if leader && index < len(user.DepartmentIDs) {
				id := fmt.Sprint(user.DepartmentIDs[index])
				leaderIDs, seenLeaderIDs[id] = append(leaderIDs, id), true
			}
		}
		for _, relation := range user.LeaderDepartments {
			id := fmt.Sprint(relation.DepartmentID)
			if relation.Leader && !seenLeaderIDs[id] {
				leaderIDs, seenLeaderIDs[id] = append(leaderIDs, id), true
			}
		}
		users = append(users, appstate.SourceUser{SourceType: "dingtalk", Subject: subject, UnionID: user.UnionID, UserID: user.UserID, Name: user.Name, EmployeeNo: user.JobNumber, Email: user.Email, Mobile: user.Mobile, DepartmentIDs: departmentIDs, LeaderDepartmentIDs: leaderIDs, Active: user.Active})
	}
	return departments, users, nil
}

func (s *Server) weComClient() (*wecom.Client, error) {
	cfg, err := s.manager.WeComCredentials()
	if err != nil {
		return nil, err
	}
	return wecom.New(wecom.Config{CorpID: cfg.CorpID, AgentID: cfg.AgentID, Secret: cfg.Secret, AuthURL: cfg.AuthURL, InAppAuthURL: cfg.InAppAuthURL, APIBaseURL: cfg.APIBaseURL})
}

func (s *Server) fetchWeComDirectory(ctx context.Context) ([]appstate.Department, []appstate.SourceUser, error) {
	client, err := s.weComClient()
	if err != nil {
		return nil, nil, err
	}
	directory, err := client.FetchDirectory(ctx)
	if err != nil {
		return nil, nil, err
	}
	departments := make([]appstate.Department, 0, len(directory.Departments))
	for _, department := range directory.Departments {
		departments = append(departments, appstate.Department{ID: fmt.Sprint(department.ID), ParentID: fmt.Sprint(department.ParentID), Name: department.Name})
	}
	users := make([]appstate.SourceUser, 0, len(directory.Users))
	for _, user := range directory.Users {
		departmentIDs := make([]string, 0, len(user.DepartmentIDs))
		leaderIDs := make([]string, 0)
		for _, id := range user.DepartmentIDs {
			departmentIDs = append(departmentIDs, fmt.Sprint(id))
		}
		for index, leader := range user.IsLeaderInDept {
			if leader == 1 && index < len(user.DepartmentIDs) {
				leaderIDs = append(leaderIDs, fmt.Sprint(user.DepartmentIDs[index]))
			}
		}
		email := user.Email
		if email == "" {
			email = user.BizMail
		}
		users = append(users, appstate.SourceUser{SourceType: "wecom", Subject: "userid:" + user.UserID, UserID: user.UserID, Name: user.Name, Email: email, Mobile: user.Mobile, DepartmentIDs: departmentIDs, LeaderDepartmentIDs: leaderIDs, Active: user.Status == 1})
	}
	return departments, users, nil
}

func (s *Server) fetchActiveDirectory(ctx context.Context) ([]appstate.Department, []appstate.SourceUser, error) {
	if s.manager.ActiveIdentitySource() == "wecom" {
		return s.fetchWeComDirectory(ctx)
	}
	return s.fetchDingDirectory(ctx)
}

func (s *Server) runScheduledCalibration(parent context.Context) error {
	if !s.syncMu.TryLock() {
		return errors.New("已有人工同步正在执行，本次定时校准已跳过")
	}
	defer s.syncMu.Unlock()
	status := s.license.Status(time.Now())
	if !status.Valid || !license.HasFeature(status, "directory") {
		return errors.New(valueOrReason(status.Reason, "License 未授权定时校准"))
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	departments, users, err := s.fetchActiveDirectory(ctx)
	if err != nil {
		return err
	}
	if managedCount := syncengine.ManagedUserCount(users, s.store.Snapshot().Departments); managedCount > status.MaxUsers {
		return fmt.Errorf("已选同步范围 %d 人超过 License 上限 %d", managedCount, status.MaxUsers)
	}
	if err := s.store.ReplaceDirectory(departments, users); err != nil {
		return err
	}
	report, err := s.probe(ctx)
	if err != nil {
		return err
	}
	snapshot := s.store.Snapshot()
	matches := syncengine.MatchUsers(snapshot.Users, report.Users, snapshot.Matches)
	if err := s.store.ReplaceMatches(matches); err != nil {
		return err
	}
	s.confirmAutoMatches(matches)
	run := syncengine.BuildPlan(s.store.Snapshot(), report)
	run.Mode = "scheduled-preview"
	run.Summary = "定时校准已生成待确认计划；" + run.Summary
	return s.store.SaveRun(run)
}

func sameSyncActions(left, right []appstate.Action) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Type != right[i].Type || left[i].Subject != right[i].Subject || left[i].DSMUsername != right[i].DSMUsername ||
			strings.Join(left[i].JoinGroups, "\x00") != strings.Join(right[i].JoinGroups, "\x00") ||
			strings.Join(left[i].LeaveGroups, "\x00") != strings.Join(right[i].LeaveGroups, "\x00") {
			return false
		}
	}
	return true
}

func (s *Server) waitForActionVerification(ctx context.Context, client *dsm.Client, action appstate.Action) error {
	delays := []time.Duration{0, 350 * time.Millisecond, 900 * time.Millisecond, 1800 * time.Millisecond}
	var lastErr error
	for _, delay := range delays {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		if err := verifyAction(ctx, client, action); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

func verifyAction(ctx context.Context, client *dsm.Client, action appstate.Action) error {
	if action.Type == "create_group" {
		groups, err := client.ListGroups(ctx)
		if err != nil {
			return err
		}
		for _, group := range groups {
			if group.Name == action.DSMUsername {
				return nil
			}
		}
		return fmt.Errorf("群组 %s 不存在", action.DSMUsername)
	}
	if action.Type == "set_groups" {
		for _, group := range action.JoinGroups {
			members, err := client.ListGroupMembers(ctx, group)
			if err != nil {
				return err
			}
			if !containsString(members, action.DSMUsername) {
				return fmt.Errorf("账号 %s 尚未加入群组 %s", action.DSMUsername, group)
			}
		}
		for _, group := range action.LeaveGroups {
			members, err := client.ListGroupMembers(ctx, group)
			if err != nil {
				return err
			}
			if containsString(members, action.DSMUsername) {
				return fmt.Errorf("账号 %s 仍在群组 %s", action.DSMUsername, group)
			}
		}
		return nil
	}
	users, err := client.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, user := range users {
		if user.Name != action.DSMUsername {
			continue
		}
		switch action.Type {
		case "create_user":
			return nil
		case "enable_user":
			if user.Expired == "" || user.Expired == "normal" {
				return nil
			}
			return fmt.Errorf("账号 %s 仍处于禁用状态", action.DSMUsername)
		case "disable_user":
			if user.Expired != "" && user.Expired != "normal" {
				return nil
			}
			return fmt.Errorf("账号 %s 仍处于启用状态", action.DSMUsername)
		}
	}
	return fmt.Errorf("账号 %s 不存在", action.DSMUsername)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (s *Server) probe(parent context.Context) (dsm.ProbeReport, error) {
	client, err := s.dsmClient()
	if err != nil {
		return dsm.ProbeReport{}, err
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	return client.Probe(ctx)
}

func (s *Server) protectedUsers() map[string]bool {
	protected := map[string]bool{"admin": true, "guest": true, "root": true, "system": true}
	credentials, err := s.manager.DSMCredentials()
	if err == nil && credentials.Account != "" {
		protected[strings.ToLower(credentials.Account)] = true
	}
	return protected
}

func (s *Server) confirmAutoMatches(matches []appstate.Match) {
	snapshot := s.store.Snapshot()
	users := map[string]appstate.SourceUser{}
	for _, user := range snapshot.Users {
		users[user.Subject] = user
	}
	for _, match := range matches {
		if match.Status != "auto" || match.Score < snapshot.Policy.AutoBindScore || match.DSMUsername == "" {
			continue
		}
		if err := s.store.ConfirmMatch(match.Subject, match.DSMUsername); err != nil {
			continue
		}
		user := users[match.Subject]
		_ = s.manager.UpsertBinding(config.Binding{SourceType: valueOrReason(user.SourceType, s.manager.ActiveIdentitySource()), SourceSubject: match.Subject, DSMUsername: match.DSMUsername, DisplayName: user.Name, Email: user.Email})
	}
}

func (s *Server) bindSource(subject, username string) {
	if err := s.store.ConfirmMatch(subject, username); err != nil {
		return
	}
	for _, user := range s.store.Snapshot().Users {
		if user.Subject == subject {
			_ = s.manager.UpsertBinding(config.Binding{SourceType: valueOrReason(user.SourceType, s.manager.ActiveIdentitySource()), SourceSubject: subject, DSMUsername: username, DisplayName: user.Name, Email: user.Email})
			return
		}
	}
}

func (s *Server) audit(action, target string, success bool, metadata map[string]any) {
	_ = s.store.AddAudit(appstate.AuditEvent{Actor: "local-admin", Action: action, Target: target, Success: success, Metadata: metadata})
}

func randomPassword(length int) (string, error) {
	if length < 16 {
		length = 24
	}
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(buffer)
	if len(encoded) > length {
		encoded = encoded[:length]
	}
	return "N1!" + encoded, nil
}

func valueOrReason(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func firstNonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func (s *Server) dsmClient() (*dsm.Client, error) {
	cfg, err := s.manager.DSMCredentials()
	if err != nil {
		return nil, err
	}
	return dsm.New(dsm.Config{BaseURL: cfg.BaseURL, Account: cfg.Account, Password: cfg.Password, InsecureTLS: cfg.InsecureTLS})
}

func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("naslink_session")
		if err != nil {
			apiError(w, http.StatusUnauthorized, "authentication_required", "请先登录管理后台")
			return
		}
		sess, ok := s.sessions.get(cookie.Value)
		if !ok {
			apiError(w, http.StatusUnauthorized, "session_expired", "管理会话已过期")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-CSRF-Token") != sess.CSRF {
			apiError(w, http.StatusForbidden, "csrf_rejected", "CSRF Token 无效")
			return
		}
		if r.Method != http.MethodGet && !sameOrigin(r) {
			apiError(w, http.StatusForbidden, "origin_rejected", "请求来源不匹配")
			return
		}
		next(w, r)
	}
}

func (s *sessionStore) create() (string, string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	csrf, err := randomToken(24)
	if err != nil {
		return "", "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	s.sessions[token] = session{CSRF: csrf, ExpiresAt: time.Now().Add(8 * time.Hour)}
	return token, csrf, nil
}

func (s *sessionStore) get(token string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if ok && time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, token)
		ok = false
	}
	return sess, ok
}

func (s *sessionStore) delete(token string) { s.mu.Lock(); delete(s.sessions, token); s.mu.Unlock() }
func (s *sessionStore) cleanupLocked() {
	for token, sess := range s.sessions {
		if time.Now().After(sess.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buffer), nil
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: "naslink_session", Value: token, Path: "/", MaxAge: 8 * 60 * 60,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return origin == "http://"+r.Host || origin == "https://"+r.Host
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("JSON 请求无效: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func apiError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'self'")
		next.ServeHTTP(w, r)
	})
}

func requestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		if !strings.Contains(r.URL.Path, "callback") && !strings.Contains(r.URL.Path, "token") {
			logger.Info("http request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(started))
		}
	})
}
