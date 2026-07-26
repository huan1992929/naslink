package syncengine

import (
	"testing"

	"naslink/internal/dsm"
	"naslink/internal/state"
)

func TestMatchUsersByEmailAndEmployeeNumber(t *testing.T) {
	source := []state.SourceUser{{Subject: "union:1", Name: "张三", EmployeeNo: "A001", Email: "zhangsan@example.com", Active: true}}
	targets := []dsm.User{{Name: "A001", Email: "zhangsan@example.com", Description: "张三"}}
	matches := MatchUsers(source, targets, nil)
	if len(matches) != 1 || matches[0].Status != "auto" || matches[0].Score != 100 || matches[0].DSMUsername != "A001" {
		t.Fatalf("unexpected match: %#v", matches)
	}
}

func TestBuildPlanNeverDeletes(t *testing.T) {
	snapshot := state.Data{
		Policy:      state.Policy{AutoBindScore: 100, CreateMissing: true, DisableDeparted: true, RandomPasswordN: 24},
		Departments: []state.Department{{ID: "dept-1", Name: "研发部", DSMGroup: "dept_rd", Managed: true}},
		Users:       []state.SourceUser{{Subject: "union:1", Name: "李四", EmployeeNo: "A002", Active: true, DepartmentIDs: []string{"dept-1"}}},
	}
	run := BuildPlan(snapshot, dsm.ProbeReport{Groups: []dsm.Group{{Name: "dept_rd"}}})
	if len(run.Actions) != 2 || run.Actions[0].Type != "create_user" || run.Actions[1].Type != "set_groups" {
		t.Fatalf("unexpected actions: %#v", run.Actions)
	}
	for _, action := range run.Actions {
		if action.Type == "delete_user" {
			t.Fatal("planner must never delete users")
		}
	}
}

func TestBuildPlanDisablesConfirmedDepartedUser(t *testing.T) {
	snapshot := state.Data{
		Policy:      state.Policy{AutoBindScore: 100, DisableDeparted: true, RandomPasswordN: 24},
		Departments: []state.Department{{ID: "dept-1", Name: "研发部", DSMGroup: "dept_rd", Managed: true}},
		Users:       []state.SourceUser{{Subject: "union:1", Name: "张三", Active: false, DepartmentIDs: []string{"dept-1"}}},
		Matches:     []state.Match{{Subject: "union:1", DSMUsername: "zhangsan", Confirmed: true, Status: "confirmed"}},
	}
	run := BuildPlan(snapshot, dsm.ProbeReport{Users: []dsm.User{{Name: "zhangsan", Expired: "normal"}}, Groups: []dsm.Group{{Name: "dept_rd"}}})
	if len(run.Actions) != 1 || run.Actions[0].Type != "disable_user" {
		t.Fatalf("expected disable action: %#v", run.Actions)
	}
}

func TestBuildPlanDoesNotCreateUsersOutsideManagedDepartments(t *testing.T) {
	snapshot := state.Data{
		Policy:      state.Policy{AutoBindScore: 100, CreateMissing: true, RandomPasswordN: 24},
		Departments: []state.Department{{ID: "dept-1", Name: "未选部门", DSMGroup: "dept_unmanaged", Managed: false}},
		Users:       []state.SourceUser{{Subject: "union:1", Name: "王五", EmployeeNo: "A003", Active: true, DepartmentIDs: []string{"dept-1"}}},
	}
	run := BuildPlan(snapshot, dsm.ProbeReport{})
	if len(run.Actions) != 0 {
		t.Fatalf("unmanaged department must not write DSM: %#v", run.Actions)
	}
}

func TestBuildPlanCreatesMissingManagedGroupBeforeUser(t *testing.T) {
	snapshot := state.Data{
		Policy:      state.Policy{AutoBindScore: 100, CreateMissing: true, RandomPasswordN: 24},
		Departments: []state.Department{{ID: "dept-1", Name: "设计部", DSMGroup: "dept_design", Managed: true}},
		Users:       []state.SourceUser{{Subject: "union:1", Name: "赵六", EmployeeNo: "A004", Active: true, DepartmentIDs: []string{"dept-1"}}},
	}
	run := BuildPlan(snapshot, dsm.ProbeReport{})
	if len(run.Actions) != 3 || run.Actions[0].Type != "create_group" || run.Actions[1].Type != "create_user" || run.Actions[2].Type != "set_groups" {
		t.Fatalf("expected group then user creation: %#v", run.Actions)
	}
}

func TestManagedUserCountOnlyCountsActiveUsersInManagedScope(t *testing.T) {
	departments := []state.Department{
		{ID: "managed", DSMGroup: "dept_managed", Managed: true},
		{ID: "unmanaged", DSMGroup: "dept_other", Managed: false},
	}
	users := []state.SourceUser{
		{Active: true, DepartmentIDs: []string{"managed"}},
		{Active: true, DepartmentIDs: []string{"managed", "unmanaged"}},
		{Active: false, DepartmentIDs: []string{"managed"}},
		{Active: true, DepartmentIDs: []string{"unmanaged"}},
	}
	if got := ManagedUserCount(users, departments); got != 2 {
		t.Fatalf("expected 2 managed active users, got %d", got)
	}
}

func TestBuildPlanProtectsAdministratorAccounts(t *testing.T) {
	snapshot := state.Data{
		Policy:  state.Policy{AutoBindScore: 100, DisableDeparted: true, RandomPasswordN: 24},
		Users:   []state.SourceUser{{Subject: "union:1", Name: "管理员", Active: false}},
		Matches: []state.Match{{Subject: "union:1", DSMUsername: "ops", Confirmed: true, Status: "confirmed"}},
	}
	run := BuildPlan(snapshot, dsm.ProbeReport{Users: []dsm.User{{Name: "ops", Groups: []string{"administrators"}}}})
	if len(run.Actions) != 0 {
		t.Fatalf("administrator must not be changed: %#v", run.Actions)
	}
}
