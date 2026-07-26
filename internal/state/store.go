package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Department struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ParentID string `json:"parent_id,omitempty"`
	DSMGroup string `json:"dsm_group,omitempty"`
	Managed  bool   `json:"managed"`
}

type SourceUser struct {
	SourceType          string   `json:"source_type,omitempty"`
	Subject             string   `json:"subject"`
	UserID              string   `json:"user_id,omitempty"`
	UnionID             string   `json:"union_id,omitempty"`
	Name                string   `json:"name"`
	EmployeeNo          string   `json:"employee_no,omitempty"`
	Email               string   `json:"email,omitempty"`
	Mobile              string   `json:"mobile,omitempty"`
	DepartmentIDs       []string `json:"department_ids,omitempty"`
	LeaderDepartmentIDs []string `json:"leader_department_ids,omitempty"`
	Active              bool     `json:"active"`
}

type SourceEvent struct {
	ID          string         `json:"id"`
	SourceType  string         `json:"source_type"`
	EventType   string         `json:"event_type"`
	ChangeType  string         `json:"change_type,omitempty"`
	ExternalID  string         `json:"external_id,omitempty"`
	ReceivedAt  time.Time      `json:"received_at"`
	ProcessedAt time.Time      `json:"processed_at,omitempty"`
	Status      string         `json:"status"`
	Error       string         `json:"error,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type Match struct {
	Subject     string    `json:"subject"`
	DSMUsername string    `json:"dsm_username,omitempty"`
	Score       int       `json:"score"`
	Status      string    `json:"status"`
	Reasons     []string  `json:"reasons,omitempty"`
	Confirmed   bool      `json:"confirmed"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Policy struct {
	UsernameRule     string `json:"username_rule"`
	UsernamePrefix   string `json:"username_prefix,omitempty"`
	AutoBindScore    int    `json:"auto_bind_score"`
	CreateMissing    bool   `json:"create_missing"`
	DisableDeparted  bool   `json:"disable_departed"`
	RemoveOldGroups  bool   `json:"remove_old_groups"`
	AutoApplyEvents  bool   `json:"auto_apply_events"`
	RandomPasswordN  int    `json:"random_password_length"`
	ScheduleEnabled  bool   `json:"schedule_enabled"`
	ScheduleInterval int    `json:"schedule_interval_minutes"`
}

type Action struct {
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	Subject        string   `json:"subject,omitempty"`
	DSMUsername    string   `json:"dsm_username"`
	DisplayName    string   `json:"display_name,omitempty"`
	Email          string   `json:"email,omitempty"`
	JoinGroups     []string `json:"join_groups,omitempty"`
	LeaveGroups    []string `json:"leave_groups,omitempty"`
	Reason         string   `json:"reason"`
	Risk           string   `json:"risk"`
	GeneratedPass  string   `json:"-"`
	ExecutionError string   `json:"execution_error,omitempty"`
	Executed       bool     `json:"executed"`
	Verified       bool     `json:"verified"`
	Verification   string   `json:"verification,omitempty"`
}

type SyncRun struct {
	ID         string    `json:"id"`
	Mode       string    `json:"mode"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Actions    []Action  `json:"actions"`
	Successes  int       `json:"successes"`
	Failures   int       `json:"failures"`
	Summary    string    `json:"summary,omitempty"`
}

type AuditEvent struct {
	ID       string         `json:"id"`
	At       time.Time      `json:"at"`
	Actor    string         `json:"actor"`
	Action   string         `json:"action"`
	Target   string         `json:"target,omitempty"`
	Success  bool           `json:"success"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Onboarding records the operator's place in the first-run journey. It is
// deliberately separate from connection health: callers must still derive
// whether a step can be completed from the current configuration and data.
type Onboarding struct {
	Version            int       `json:"version"`
	CurrentStep        string    `json:"current_step,omitempty"`
	IdentitySource     string    `json:"identity_source,omitempty"`
	StartedAt          time.Time `json:"started_at,omitempty"`
	CompletedAt        time.Time `json:"completed_at,omitempty"`
	DriveSkipped       bool      `json:"drive_skipped"`
	DSMVerifiedAt      time.Time `json:"dsm_verified_at,omitempty"`
	IdentityVerifiedAt time.Time `json:"identity_verified_at,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

type Data struct {
	Version      int           `json:"version"`
	InstallID    string        `json:"install_id"`
	CreatedAt    time.Time     `json:"created_at"`
	DirectoryAt  time.Time     `json:"directory_at,omitempty"`
	Departments  []Department  `json:"departments"`
	Users        []SourceUser  `json:"users"`
	Matches      []Match       `json:"matches"`
	ManagedUsers []string      `json:"managed_users"`
	Policy       Policy        `json:"policy"`
	SyncRuns     []SyncRun     `json:"sync_runs"`
	AuditEvents  []AuditEvent  `json:"audit_events"`
	SourceEvents []SourceEvent `json:"source_events"`
	Onboarding   Onboarding    `json:"onboarding"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	data Data
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dataDir, "state.json")}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.data = Data{Version: 2, InstallID: randomID("ins"), CreatedAt: time.Now().UTC(), Policy: defaultPolicy(), Onboarding: defaultOnboarding()}
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if s.data.InstallID == "" {
		s.data.InstallID = randomID("ins")
	}
	if s.data.Policy.UsernameRule == "" {
		s.data.Policy = defaultPolicy()
	}
	if s.data.Onboarding.Version == 0 {
		s.data.Onboarding = defaultOnboarding()
	}
	for i := range s.data.Users {
		if s.data.Users[i].SourceType == "" {
			s.data.Users[i].SourceType = "dingtalk"
		}
	}
	return s, nil
}

func defaultOnboarding() Onboarding {
	return Onboarding{Version: 1, CurrentStep: "welcome", IdentitySource: "dingtalk"}
}

func defaultPolicy() Policy {
	return Policy{UsernameRule: "employee_no", AutoBindScore: 100, RandomPasswordN: 24, ScheduleInterval: 1440}
}

func (s *Store) Snapshot() Data {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, _ := json.Marshal(s.data)
	var out Data
	_ = json.Unmarshal(raw, &out)
	return out
}

// UpdateOnboarding persists a validated transition. The supported steps are
// intentionally fixed so a malformed API request cannot corrupt resume state.
func (s *Store) UpdateOnboarding(step, identitySource string, driveSkipped, complete bool) (Onboarding, error) {
	validSteps := map[string]bool{"welcome": true, "dsm": true, "identity": true, "scope": true, "matches": true, "sync": true, "drive_optional": true, "complete": true}
	if !validSteps[step] {
		return Onboarding{}, errors.New("无效的配置步骤")
	}
	if identitySource != "" && identitySource != "dingtalk" && identitySource != "wecom" {
		return Onboarding{}, errors.New("身份源必须是 dingtalk 或 wecom")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := &s.data.Onboarding
	if current.Version == 0 {
		*current = defaultOnboarding()
	}
	now := time.Now().UTC()
	if current.StartedAt.IsZero() {
		current.StartedAt = now
	}
	current.CurrentStep = step
	if identitySource != "" {
		current.IdentitySource = identitySource
	}
	current.DriveSkipped = driveSkipped
	if complete {
		current.CurrentStep = "complete"
		current.CompletedAt = now
	} else if step != "complete" {
		current.CompletedAt = time.Time{}
	}
	current.UpdatedAt = now
	if err := s.saveLocked(); err != nil {
		return Onboarding{}, err
	}
	return *current, nil
}

func (s *Store) MarkOnboardingVerified(kind string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Onboarding.Version == 0 {
		s.data.Onboarding = defaultOnboarding()
	}
	now := time.Now().UTC()
	switch kind {
	case "dsm":
		s.data.Onboarding.DSMVerifiedAt = now
	case "identity":
		s.data.Onboarding.IdentityVerifiedAt = now
	default:
		return errors.New("未知的配置验证类型")
	}
	s.data.Onboarding.UpdatedAt = now
	return s.saveLocked()
}

func (s *Store) ReplaceDirectory(departments []Department, users []SourceUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldGroups := map[string]Department{}
	for _, department := range s.data.Departments {
		oldGroups[department.ID] = department
	}
	incomingDepartments := map[string]bool{}
	for i := range departments {
		incomingDepartments[departments[i].ID] = true
		if old, ok := oldGroups[departments[i].ID]; ok {
			departments[i].DSMGroup, departments[i].Managed = old.DSMGroup, old.Managed
		}
	}
	for _, old := range oldGroups {
		if old.Managed && !incomingDepartments[old.ID] {
			if !strings.Contains(old.Name, "[已撤销]") {
				old.Name += " [已撤销]"
			}
			departments = append(departments, old)
		}
	}
	incomingUsers := map[string]bool{}
	for _, user := range users {
		incomingUsers[user.Subject] = true
	}
	for _, oldUser := range s.data.Users {
		if oldUser.Subject != "" && !incomingUsers[oldUser.Subject] {
			oldUser.Active = false
			users = append(users, oldUser)
		}
	}
	sort.Slice(departments, func(i, j int) bool { return departments[i].Name < departments[j].Name })
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	s.data.Departments, s.data.Users, s.data.DirectoryAt = departments, users, time.Now().UTC()
	return s.saveLocked()
}

func (s *Store) AddSourceEvent(event SourceEvent) (SourceEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.ID == "" {
		event.ID = randomID("evt")
	}
	if event.ReceivedAt.IsZero() {
		event.ReceivedAt = time.Now().UTC()
	}
	if event.Status == "" {
		event.Status = "received"
	}
	s.data.SourceEvents = append([]SourceEvent{event}, s.data.SourceEvents...)
	if len(s.data.SourceEvents) > 500 {
		s.data.SourceEvents = s.data.SourceEvents[:500]
	}
	return event, s.saveLocked()
}

func (s *Store) MarkSourceEvent(id, status, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.SourceEvents {
		if s.data.SourceEvents[i].ID == id {
			s.data.SourceEvents[i].Status = status
			s.data.SourceEvents[i].Error = message
			s.data.SourceEvents[i].ProcessedAt = time.Now().UTC()
			return s.saveLocked()
		}
	}
	return errors.New("事件不存在")
}

func (s *Store) UpsertDepartmentMapping(id, group string, managed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Departments {
		if s.data.Departments[i].ID == id {
			s.data.Departments[i].DSMGroup = group
			s.data.Departments[i].Managed = managed
			return s.saveLocked()
		}
	}
	return errors.New("部门不存在")
}

func (s *Store) ReplaceMatches(matches []Match) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	confirmed := map[string]Match{}
	for _, match := range s.data.Matches {
		if match.Confirmed {
			confirmed[match.Subject] = match
		}
	}
	for i := range matches {
		if old, ok := confirmed[matches[i].Subject]; ok {
			matches[i] = old
		}
	}
	s.data.Matches = matches
	return s.saveLocked()
}

func (s *Store) ConfirmMatch(subject, username string) error {
	if subject == "" || username == "" {
		return errors.New("用户标识和 DSM 用户名不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, match := range s.data.Matches {
		if match.DSMUsername == username && match.Subject != subject && match.Confirmed {
			return errors.New("该 DSM 账号已绑定其他员工")
		}
	}
	for i := range s.data.Matches {
		if s.data.Matches[i].Subject == subject {
			s.data.Matches[i].DSMUsername = username
			s.data.Matches[i].Confirmed = true
			s.data.Matches[i].Status = "confirmed"
			s.data.Matches[i].Score = 100
			s.data.Matches[i].Reasons = []string{"管理员人工确认"}
			s.data.Matches[i].UpdatedAt = time.Now().UTC()
			return s.saveLocked()
		}
	}
	s.data.Matches = append(s.data.Matches, Match{Subject: subject, DSMUsername: username, Score: 100, Status: "confirmed", Confirmed: true, Reasons: []string{"管理员人工确认"}, UpdatedAt: time.Now().UTC()})
	return s.saveLocked()
}

func (s *Store) UpdatePolicy(policy Policy) error {
	if policy.AutoBindScore < 60 || policy.AutoBindScore > 100 {
		return errors.New("自动匹配阈值必须在 60 到 100 之间")
	}
	if policy.RandomPasswordN < 16 || policy.RandomPasswordN > 128 {
		return errors.New("随机密码长度必须在 16 到 128 之间")
	}
	if policy.ScheduleInterval < 15 {
		return errors.New("同步间隔不能小于 15 分钟")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Policy = policy
	return s.saveLocked()
}

func (s *Store) SaveRun(run SyncRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.SyncRuns {
		if s.data.SyncRuns[i].ID == run.ID {
			s.data.SyncRuns[i] = run
			return s.saveLocked()
		}
	}
	s.data.SyncRuns = append([]SyncRun{run}, s.data.SyncRuns...)
	if len(s.data.SyncRuns) > 100 {
		s.data.SyncRuns = s.data.SyncRuns[:100]
	}
	return s.saveLocked()
}

func (s *Store) FindRun(id string) (SyncRun, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, run := range s.data.SyncRuns {
		if run.ID == id {
			return run, true
		}
	}
	return SyncRun{}, false
}

func (s *Store) MarkManaged(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, value := range s.data.ManagedUsers {
		if value == username {
			return nil
		}
	}
	s.data.ManagedUsers = append(s.data.ManagedUsers, username)
	sort.Strings(s.data.ManagedUsers)
	return s.saveLocked()
}

func (s *Store) AddAudit(event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.ID == "" {
		event.ID = randomID("aud")
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	s.data.AuditEvents = append([]AuditEvent{event}, s.data.AuditEvents...)
	if len(s.data.AuditEvents) > 500 {
		s.data.AuditEvents = s.data.AuditEvents[:500]
	}
	return s.saveLocked()
}

func (s *Store) Export() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.MarshalIndent(s.data, "", "  ")
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func NewID(prefix string) string { return randomID(prefix) }

func randomID(prefix string) string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(buffer)
}
