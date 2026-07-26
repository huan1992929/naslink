package config

import "testing"

func TestManagerEncryptsSecretsAndVerifiesAdmin(t *testing.T) {
	m, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetupAdmin("a-strong-admin-password"); err != nil {
		t.Fatal(err)
	}
	if !m.VerifyAdmin("a-strong-admin-password") {
		t.Fatal("password should verify")
	}
	if m.VerifyAdmin("wrong-password") {
		t.Fatal("wrong password verified")
	}

	var update Update
	update.DSM.BaseURL = "https://nas.test:5001"
	update.DSM.Account = "naslink_poc_admin"
	update.DSM.Password = "dsm-secret"
	update.DSM.MutationPrefix = "naslink_poc_"
	update.DingTalk.ClientSecret = "ding-secret"
	update.IdentitySource = "wecom"
	update.WeCom.CorpID = "ww-test"
	update.WeCom.AgentID = "1001"
	update.WeCom.Secret = "wecom-secret"
	update.WeCom.InAppAuthURL = "https://open.weixin.qq.com/connect/oauth2/authorize"
	update.WeCom.DriveWebURL = "https://drive.example.com"
	update.WeCom.CallbackToken = "callback-token"
	update.WeCom.CallbackAESKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	update.LicenseCenter.URL = "https://license.example"
	update.LicenseCenter.ActivationCode = "NASL-TEST-CODE"
	update.OIDC.Issuer = "https://naslink.example.com"
	update.OIDC.ClientSecret = "oidc-secret"
	if err := m.Update(update); err != nil {
		t.Fatal(err)
	}

	if m.settings.DSM.Password == "dsm-secret" {
		t.Fatal("DSM secret stored in plaintext")
	}
	dsm, err := m.DSMCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if dsm.Password != "dsm-secret" {
		t.Fatalf("got %q", dsm.Password)
	}
	wecom, err := m.WeComCredentials()
	if err != nil || wecom.Secret != "wecom-secret" || wecom.CallbackToken != "callback-token" {
		t.Fatalf("wecom credentials: %#v %v", wecom, err)
	}
	if wecom.DriveWebURL != "https://drive.example.com" || m.Public().WeCom.LaunchURL == "" {
		t.Fatalf("wecom drive settings missing: %#v", wecom)
	}
	center, err := m.LicenseCenterCredentials()
	if err != nil || center.ActivationCode != "NASL-TEST-CODE" {
		t.Fatalf("license center credentials: %#v %v", center, err)
	}
}

func TestManagerRejectsUnsafeDriveURL(t *testing.T) {
	m, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var update Update
	update.DSM.MutationPrefix = "naslink_poc_"
	update.WeCom.DriveWebURL = "javascript:alert(1)"
	if err := m.Update(update); err == nil {
		t.Fatal("unsafe Drive URL was accepted")
	}
}
