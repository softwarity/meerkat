package store

import (
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/mfa"
)

func TestTOTPEnrollmentLifecycle(t *testing.T) {
	s, ctx := rbacStore(t)
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "x"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	st, err := s.GetUserTOTP(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUserTOTP: %v", err)
	}
	if st.Enrolled || st.Secret != "" || st.Pending != "" || len(st.Scratch) != 0 {
		t.Fatalf("fresh user should have no TOTP, got %+v", st)
	}

	if err := s.SetUserTOTPPending(ctx, "u1", "SECRETPENDING"); err != nil {
		t.Fatalf("SetUserTOTPPending: %v", err)
	}
	st, _ = s.GetUserTOTP(ctx, "u1")
	if st.Enrolled || st.Pending != "SECRETPENDING" {
		t.Fatalf("expected pending-only, got %+v", st)
	}

	_, hashes, err := mfa.NewScratchCodes(8)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableUserTOTP(ctx, "u1", "SECRETCONFIRMED", hashes); err != nil {
		t.Fatalf("EnableUserTOTP: %v", err)
	}
	st, _ = s.GetUserTOTP(ctx, "u1")
	if !st.Enrolled || st.Secret != "SECRETCONFIRMED" || st.Pending != "" || len(st.Scratch) != 8 {
		t.Fatalf("expected enrolled with 8 scratch codes, got %+v", st)
	}

	if err := s.DisableUserTOTP(ctx, "u1"); err != nil {
		t.Fatalf("DisableUserTOTP: %v", err)
	}
	st, _ = s.GetUserTOTP(ctx, "u1")
	if st.Enrolled || len(st.Scratch) != 0 {
		t.Fatalf("expected cleared TOTP, got %+v", st)
	}
}

func TestConsumeScratch(t *testing.T) {
	s, ctx := rbacStore(t)
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "x"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	plain, hashes, err := mfa.NewScratchCodes(3)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableUserTOTP(ctx, "u1", "SEC", hashes); err != nil {
		t.Fatalf("EnableUserTOTP: %v", err)
	}

	ok, err := s.ConsumeScratch(ctx, "u1", plain[1])
	if err != nil || !ok {
		t.Fatalf("valid scratch code: ok=%v err=%v", ok, err)
	}
	// Single use: the same code no longer works.
	if ok, _ := s.ConsumeScratch(ctx, "u1", plain[1]); ok {
		t.Fatal("a burned scratch code was accepted a second time")
	}
	// An unrelated code is rejected.
	if ok, _ := s.ConsumeScratch(ctx, "u1", "not-a-code"); ok {
		t.Fatal("an unrelated code was accepted")
	}
	st, _ := s.GetUserTOTP(ctx, "u1")
	if len(st.Scratch) != 2 {
		t.Fatalf("expected 2 remaining scratch codes, got %d", len(st.Scratch))
	}
}

func TestMFARequiredForUser(t *testing.T) {
	s, ctx := rbacStore(t)
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "x"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Default: global false, user inherits → not required.
	if req, err := s.MFARequiredForUser(ctx, "u1"); err != nil || req {
		t.Fatalf("default should be not required, got %v (err %v)", req, err)
	}

	// Global on, user inherits → required.
	if err := s.SetSetting(ctx, SettingMFARequired, true); err != nil {
		t.Fatal(err)
	}
	if req, _ := s.MFARequiredForUser(ctx, "u1"); !req {
		t.Fatal("global policy should force MFA")
	}

	// User override "false" beats the global "true" (most specific wins).
	if err := s.UpdateUser(ctx, User{ID: "u1", Username: "alice", MFARequired: "false"}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if req, _ := s.MFARequiredForUser(ctx, "u1"); req {
		t.Fatal("user override false should win over global true")
	}

	// User override "true" forces it even when global is off.
	if err := s.SetSetting(ctx, SettingMFARequired, false); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser(ctx, User{ID: "u1", Username: "alice", MFARequired: "true"}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if req, _ := s.MFARequiredForUser(ctx, "u1"); !req {
		t.Fatal("user override true should win over global false")
	}
}

func TestSaveUserMFARoundTrip(t *testing.T) {
	s, ctx := rbacStore(t)
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "x", MFARequired: "true"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got, _ := s.GetUserByID(ctx, "u1"); got.MFARequired != "true" {
		t.Fatalf("created user mfaRequired = %q, want true", got.MFARequired)
	}
	if err := s.UpdateUser(ctx, User{ID: "u1", Username: "alice", MFARequired: "false"}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if got, _ := s.GetUserByID(ctx, "u1"); got.MFARequired != "false" {
		t.Fatalf("updated user mfaRequired = %q, want false", got.MFARequired)
	}
	// An invalid tri-state is rejected on both paths.
	if err := s.CreateUser(ctx, User{ID: "u2", Username: "bob", MFARequired: "maybe"}); err == nil {
		t.Fatal("CreateUser accepted an invalid mfaRequired value")
	}
	if err := s.UpdateUser(ctx, User{ID: "u1", Username: "alice", MFARequired: "maybe"}); err == nil {
		t.Fatal("UpdateUser accepted an invalid mfaRequired value")
	}
}

func TestTrustedBrowserLifecycle(t *testing.T) {
	s, ctx := rbacStore(t)
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "x"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	now := time.Now().Unix()
	if err := s.AddTrustedBrowser(ctx, "b1", "u1", "hashA", "Chrome/macOS", now+3600); err != nil {
		t.Fatalf("AddTrustedBrowser: %v", err)
	}

	if ok, _ := s.IsBrowserTrusted(ctx, "u1", "hashA", now); !ok {
		t.Fatal("fresh trusted browser should be trusted")
	}
	if ok, _ := s.IsBrowserTrusted(ctx, "u1", "hashA", now+7200); ok {
		t.Fatal("expired trust should not count")
	}
	if ok, _ := s.IsBrowserTrusted(ctx, "u1", "other", now); ok {
		t.Fatal("wrong hash should not be trusted")
	}
	if ok, _ := s.IsBrowserTrusted(ctx, "u2", "hashA", now); ok {
		t.Fatal("another user's request must not match")
	}

	if list, _ := s.ListTrustedBrowsers(ctx, "u1"); len(list) != 1 || list[0].Label != "Chrome/macOS" {
		t.Fatalf("ListTrustedBrowsers = %+v", list)
	}
	if removed, _ := s.RevokeTrustedBrowser(ctx, "u1", "b1"); !removed {
		t.Fatal("revoke should report the row existed")
	}
	if list, _ := s.ListTrustedBrowsers(ctx, "u1"); len(list) != 0 {
		t.Fatal("browser still listed after revoke")
	}

	_ = s.AddTrustedBrowser(ctx, "b2", "u1", "h2", "", now+3600)
	_ = s.AddTrustedBrowser(ctx, "b3", "u1", "h3", "", now+3600)
	if err := s.RevokeAllTrustedBrowsers(ctx, "u1"); err != nil {
		t.Fatalf("RevokeAllTrustedBrowsers: %v", err)
	}
	if list, _ := s.ListTrustedBrowsers(ctx, "u1"); len(list) != 0 {
		t.Fatal("browsers survived revoke-all")
	}

	// Default policy: off, 7-day TTL.
	if pol, _ := s.GetTrustedBrowserPolicy(ctx); pol.Allowed || pol.TTL != "P7D" {
		t.Fatalf("default trusted-browser policy = %+v, want {false P7D}", pol)
	}
}
