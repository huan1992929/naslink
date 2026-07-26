package state

import (
	"testing"
	"time"
)

func TestStorePreservesDepartmentMapping(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceDirectory([]Department{{ID: "1", Name: "设计中心"}}, []SourceUser{{Subject: "union:1", Name: "张三", Active: true}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertDepartmentMapping("1", "dept_design", true); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceDirectory([]Department{{ID: "1", Name: "设计院"}}, nil); err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if snapshot.Departments[0].DSMGroup != "dept_design" || !snapshot.Departments[0].Managed {
		t.Fatalf("mapping was not preserved: %#v", snapshot.Departments[0])
	}
}

func TestConfirmMatchRejectsDuplicateDSMUser(t *testing.T) {
	store, _ := Open(t.TempDir())
	if err := store.ConfirmMatch("union:1", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmMatch("union:2", "alice"); err == nil {
		t.Fatal("expected duplicate binding rejection")
	}
}

func TestMissingDirectoryUserBecomesInactive(t *testing.T) {
	store, _ := Open(t.TempDir())
	_ = store.ReplaceDirectory(nil, []SourceUser{{Subject: "union:1", Name: "张三", Active: true}})
	_ = store.ReplaceDirectory(nil, nil)
	snapshot := store.Snapshot()
	if len(snapshot.Users) != 1 || snapshot.Users[0].Active {
		t.Fatalf("missing user should be retained as inactive: %#v", snapshot.Users)
	}
}

func TestOnboardingPersistsResumeState(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.UpdateOnboarding("scope", "wecom", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if updated.CurrentStep != "scope" || updated.IdentitySource != "wecom" || !updated.DriveSkipped || updated.StartedAt.IsZero() || updated.UpdatedAt.IsZero() {
		t.Fatalf("unexpected onboarding state: %#v", updated)
	}
	store, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	persisted := store.Snapshot().Onboarding
	if persisted.CurrentStep != "scope" || persisted.IdentitySource != "wecom" || !persisted.DriveSkipped || persisted.UpdatedAt.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("onboarding was not persisted: %#v", persisted)
	}
}
