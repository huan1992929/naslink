package state

import "testing"

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
