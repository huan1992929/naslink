package syncengine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"naslink/internal/dsm"
	"naslink/internal/state"
)

var invalidUsername = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func BuildPlan(snapshot state.Data, report dsm.ProbeReport) state.SyncRun {
	run := state.SyncRun{ID: state.NewID("sync"), Mode: "preview", Status: "preview", CreatedAt: time.Now().UTC()}
	targets := map[string]dsm.User{}
	for _, user := range report.Users {
		targets[strings.ToLower(user.Name)] = user
	}
	matches := map[string]state.Match{}
	for _, match := range snapshot.Matches {
		matches[match.Subject] = match
	}
	deptGroups := map[string]string{}
	managedGroups := map[string]bool{}
	managedDepartments := map[string]bool{}
	existingGroups := map[string]bool{}
	previouslyManaged := map[string]bool{}
	claimedUsernames := map[string]string{}
	for _, group := range report.Groups {
		existingGroups[strings.ToLower(group.Name)] = true
	}
	for _, username := range snapshot.ManagedUsers {
		previouslyManaged[strings.ToLower(username)] = true
	}
	for _, department := range snapshot.Departments {
		if department.Managed && department.DSMGroup != "" {
			deptGroups[department.ID] = department.DSMGroup
			managedGroups[department.DSMGroup] = true
			managedDepartments[department.ID] = true
			if !existingGroups[strings.ToLower(department.DSMGroup)] {
				run.Actions = append(run.Actions, action("create_group", state.SourceUser{Name: department.Name}, department.DSMGroup, nil, nil, "受管部门尚无 DSM 群组", "medium"))
				existingGroups[strings.ToLower(department.DSMGroup)] = true
			}
		}
	}
	for _, source := range snapshot.Users {
		inScope := userInManagedScope(source, managedDepartments)
		match := matches[source.Subject]
		username := match.DSMUsername
		generated := false
		trusted := match.Confirmed || (match.Status == "auto" && match.Score >= snapshot.Policy.AutoBindScore)
		if username == "" && source.Active && inScope && snapshot.Policy.CreateMissing {
			username = generatedUsername(source, snapshot.Policy)
			generated = true
			trusted = username != ""
		}
		if !trusted || username == "" {
			continue
		}
		wasManaged := previouslyManaged[strings.ToLower(username)]
		if !inScope && !wasManaged {
			continue
		}
		target, exists := targets[strings.ToLower(username)]
		if generated && exists {
			continue
		}
		if owner, duplicate := claimedUsernames[strings.ToLower(username)]; duplicate && owner != source.Subject {
			continue
		}
		claimedUsernames[strings.ToLower(username)] = source.Subject
		if source.Active && inScope && !exists && snapshot.Policy.CreateMissing {
			run.Actions = append(run.Actions, action("create_user", source, username, nil, nil, "在职员工尚无 DSM 账号", "medium"))
			target = dsm.User{Name: username}
			exists = true
		}
		if !exists {
			continue
		}
		if privileged(target.Groups) {
			continue
		}
		if source.Active && inScope && target.Expired == "now" {
			run.Actions = append(run.Actions, action("enable_user", source, username, nil, nil, "在职员工账号当前被禁用", "medium"))
		}
		if !source.Active && snapshot.Policy.DisableDeparted && target.Expired != "now" {
			run.Actions = append(run.Actions, action("disable_user", source, username, nil, nil, "身份源标记为离职或停用", "high"))
			continue
		}
		if !source.Active {
			continue
		}
		desired := map[string]bool{}
		for _, departmentID := range source.DepartmentIDs {
			if group := deptGroups[departmentID]; group != "" {
				desired[group] = true
			}
		}
		current := map[string]bool{}
		for _, group := range target.Groups {
			current[group] = true
		}
		join, leave := []string{}, []string{}
		for group := range desired {
			if !current[group] {
				join = append(join, group)
			}
		}
		if snapshot.Policy.RemoveOldGroups {
			for group := range managedGroups {
				if current[group] && !desired[group] {
					leave = append(leave, group)
				}
			}
		}
		sort.Strings(join)
		sort.Strings(leave)
		if len(join)+len(leave) > 0 {
			run.Actions = append(run.Actions, action("set_groups", source, username, join, leave, "部门与 DSM 群组差异", "medium"))
		}
	}
	run.Summary = fmt.Sprintf("计划 %d 项变更；不包含删除账号或文件操作。", len(run.Actions))
	return run
}

// ManagedUserCount returns the active identities that belong to at least one
// explicitly managed department. Reading the full directory is not billable
// and never implies that every identity will be written to DSM.
func ManagedUserCount(users []state.SourceUser, departments []state.Department) int {
	managed := map[string]bool{}
	for _, department := range departments {
		if department.Managed && department.DSMGroup != "" {
			managed[department.ID] = true
		}
	}
	count := 0
	for _, user := range users {
		if user.Active && userInManagedScope(user, managed) {
			count++
		}
	}
	return count
}

func userInManagedScope(user state.SourceUser, managed map[string]bool) bool {
	for _, departmentID := range user.DepartmentIDs {
		if managed[departmentID] {
			return true
		}
	}
	return false
}

func action(kind string, source state.SourceUser, username string, join, leave []string, reason, risk string) state.Action {
	return state.Action{ID: state.NewID("act"), Type: kind, Subject: source.Subject, DSMUsername: username, DisplayName: source.Name, Email: source.Email, JoinGroups: join, LeaveGroups: leave, Reason: reason, Risk: risk}
}

func generatedUsername(user state.SourceUser, policy state.Policy) string {
	value := ""
	switch policy.UsernameRule {
	case "email_prefix":
		value = user.Email
		if at := strings.IndexByte(value, '@'); at >= 0 {
			value = value[:at]
		}
	case "user_id":
		value = user.UserID
	default:
		value = user.EmployeeNo
	}
	value = invalidUsername.ReplaceAllString(strings.TrimSpace(value), "_")
	value = strings.Trim(value, "._-")
	if value == "" {
		digest := sha256.Sum256([]byte(user.Subject))
		value = "user_" + hex.EncodeToString(digest[:4])
	}
	return policy.UsernamePrefix + value
}
