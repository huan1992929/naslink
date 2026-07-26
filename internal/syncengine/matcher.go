package syncengine

import (
	"sort"
	"strings"
	"time"
	"unicode"

	"naslink/internal/dsm"
	"naslink/internal/state"
)

type candidate struct {
	username string
	score    int
	reasons  []string
}

func MatchUsers(source []state.SourceUser, targets []dsm.User, existing []state.Match) []state.Match {
	confirmed := map[string]state.Match{}
	for _, match := range existing {
		if match.Confirmed {
			confirmed[match.Subject] = match
		}
	}
	used := map[string]string{}
	result := make([]state.Match, 0, len(source))
	for _, user := range source {
		if match, ok := confirmed[user.Subject]; ok {
			result = append(result, match)
			used[strings.ToLower(match.DSMUsername)] = user.Subject
			continue
		}
		candidates := scoreCandidates(user, targets)
		match := state.Match{Subject: user.Subject, Status: "unmatched", UpdatedAt: time.Now().UTC()}
		if len(candidates) > 0 {
			best := candidates[0]
			match.DSMUsername, match.Score, match.Reasons = best.username, best.score, best.reasons
			match.Status = "review"
			if best.score >= 100 {
				match.Status = "auto"
			}
			if len(candidates) > 1 && candidates[1].score == best.score {
				match.Status = "conflict"
				match.Reasons = append(match.Reasons, "多个账号得分相同")
			}
			if other, occupied := used[strings.ToLower(best.username)]; occupied && other != user.Subject {
				match.Status = "conflict"
				match.Reasons = append(match.Reasons, "DSM 账号已被其他员工候选")
			} else if match.Status == "auto" {
				used[strings.ToLower(best.username)] = user.Subject
			}
		}
		result = append(result, match)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Status != result[j].Status {
			return result[i].Status < result[j].Status
		}
		return result[i].Subject < result[j].Subject
	})
	return result
}

func scoreCandidates(source state.SourceUser, targets []dsm.User) []candidate {
	values := make([]candidate, 0)
	email := strings.ToLower(strings.TrimSpace(source.Email))
	emailPrefix := email
	if at := strings.IndexByte(emailPrefix, '@'); at >= 0 {
		emailPrefix = emailPrefix[:at]
	}
	for _, target := range targets {
		score := 0
		reasons := []string{}
		username := strings.ToLower(strings.TrimSpace(target.Name))
		targetEmail := strings.ToLower(strings.TrimSpace(target.Email))
		description := normalize(target.Description)
		if email != "" && targetEmail == email {
			score += 100
			reasons = append(reasons, "企业邮箱完全一致")
		}
		if source.EmployeeNo != "" && strings.EqualFold(source.EmployeeNo, target.Name) {
			score += 100
			reasons = append(reasons, "工号与 DSM 用户名一致")
		}
		if emailPrefix != "" && username == emailPrefix {
			score += 85
			reasons = append(reasons, "邮箱前缀与 DSM 用户名一致")
		}
		if source.Name != "" && description == normalize(source.Name) {
			score += 55
			reasons = append(reasons, "DSM 描述与姓名一致")
		} else if source.Name != "" && strings.Contains(description, normalize(source.Name)) {
			score += 30
			reasons = append(reasons, "DSM 描述包含姓名")
		}
		if score > 0 {
			if privileged(target.Groups) {
				score -= 60
				reasons = append(reasons, "DSM 账号属于管理员群组")
			}
			if target.Expired == "now" {
				score -= 10
				reasons = append(reasons, "DSM 账号已禁用")
			}
			if score > 100 {
				score = 100
			}
			values = append(values, candidate{username: target.Name, score: score, reasons: reasons})
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].score != values[j].score {
			return values[i].score > values[j].score
		}
		return values[i].username < values[j].username
	})
	return values
}

func privileged(groups []string) bool {
	for _, group := range groups {
		if strings.EqualFold(group, "administrators") || strings.EqualFold(group, "admin") {
			return true
		}
	}
	return false
}

func normalize(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' || r == '_' || r == '·' {
			return -1
		}
		return unicode.ToLower(r)
	}, strings.TrimSpace(value))
}
