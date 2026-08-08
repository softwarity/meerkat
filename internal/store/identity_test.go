package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestUserLifecycle(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	u := User{
		ID: "u1", Username: "alice", PasswordHash: "h", Fullname: "Alice A", Email: "alice@example.com",
		Enabled: true, Dev: true,
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.Fullname != "Alice A" || !got.Dev || got.Tester || got.Timezone != "UTC" || got.CreatedAt == 0 {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	got.Tester = true
	got.Fullname = "Alice B"
	if err := s.UpdateUser(ctx, got); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	again, err := s.GetUserByID(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !again.Tester || again.Fullname != "Alice B" {
		t.Fatalf("update lost: %+v", again)
	}

	if err := s.SetUserPassword(ctx, "u1", "h2", false); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	if u2, _ := s.GetUserByID(ctx, "u1"); u2.PasswordHash != "h2" {
		t.Fatalf("password not replaced: %+v", u2)
	}

	if err := s.UpdateUser(ctx, User{ID: "ghost", Username: "ghost"}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("UpdateUser(ghost) = %v, want ErrNoRows", err)
	}

	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("ListUsers = %d, %v", len(users), err)
	}

	existed, err := s.DeleteUser(ctx, "u1")
	if err != nil || !existed {
		t.Fatalf("DeleteUser = %v, %v", existed, err)
	}
}

func TestTenantAndMembershipLifecycle(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	for _, u := range []User{
		{ID: "u1", Username: "alice", PasswordHash: "h", Enabled: true},
		{ID: "u2", Username: "bob", PasswordHash: "h", Enabled: true},
	} {
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}
	tn := Tenant{
		ID: "t1", Name: "acme", Enabled: true,
		BusinessAccess: BusinessAccess{Inherited: true},
	}
	if err := s.SaveTenant(ctx, tn); err != nil {
		t.Fatalf("SaveTenant: %v", err)
	}

	// Membership with an override, plus a plain inherited one.
	if err := s.SaveMembership(ctx, Membership{
		UserID: "u1", TenantID: "t1", Type: MemberAdmin, Enabled: true,
		BusinessAccess: BusinessAccess{Timezone: "Europe/Paris", Days: ranges("08:00", "18:00", 1, 2, 3, 4, 5)},
		SessionTTL:     "PT1H",
	}); err != nil {
		t.Fatalf("SaveMembership: %v", err)
	}
	if err := s.SaveMembership(ctx, Membership{
		UserID: "u2", TenantID: "t1", Type: MemberUser, Enabled: true,
		BusinessAccess: BusinessAccess{Inherited: true},
	}); err != nil {
		t.Fatalf("SaveMembership: %v", err)
	}

	// Type validation names the offender and lists what is allowed (OWNER is no
	// longer a membership type - ownership lives on the tenant).
	err := s.SaveMembership(ctx, Membership{UserID: "u2", TenantID: "t1", Type: "OWNER"})
	if err == nil || !strings.Contains(err.Error(), "ADMIN, USER") {
		t.Fatalf("invalid type error = %v", err)
	}

	members, err := s.ListMembers(ctx, "t1")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 2 || members[0].Type != MemberAdmin || members[0].Username != "alice" {
		t.Fatalf("members order/content: %+v", members)
	}
	if members[0].BusinessAccess.Days[0].From != "08:00" || !members[1].BusinessAccess.Inherited {
		t.Fatalf("business access round trip: %+v", members)
	}

	// An ADMIN member administers the tenant; a plain USER does not.
	admin, err := s.ListTenantsAdministeredBy(ctx, "u1")
	if err != nil || len(admin) != 1 || admin[0].Name != "acme" {
		t.Fatalf("ListTenantsAdministeredBy(admin) = %+v, %v", admin, err)
	}
	if none, _ := s.ListTenantsAdministeredBy(ctx, "u2"); len(none) != 0 {
		t.Fatalf("plain USER should administer nothing: %+v", none)
	}

	// Ownership is decoupled from membership: a non-member owner administers the
	// tenant through owner_id alone, without appearing as a member.
	if err := s.CreateUser(ctx, User{ID: "u3", Username: "carol", PasswordHash: "h", Enabled: true}); err != nil {
		t.Fatalf("CreateUser(carol): %v", err)
	}
	if existed, err := s.SetTenantOwner(ctx, "t1", "u3"); err != nil || !existed {
		t.Fatalf("SetTenantOwner = %v, %v", existed, err)
	}
	if owned, err := s.ListTenantsAdministeredBy(ctx, "u3"); err != nil || len(owned) != 1 || owned[0].Name != "acme" {
		t.Fatalf("owner (non-member) must administer: %+v, %v", owned, err)
	}
	if uts, _ := s.ListUserTenants(ctx, "u3"); len(uts) != 0 {
		t.Fatalf("owner (non-member) must not appear as a member: %+v", uts)
	}
	if got, err := s.GetTenant(ctx, "t1"); err != nil || got.OwnerID != "u3" {
		t.Fatalf("GetTenant owner = %q, %v", got.OwnerID, err)
	}

	uts, err := s.ListUserTenants(ctx, "u2")
	if err != nil || len(uts) != 1 || uts[0].TenantName != "acme" || uts[0].Type != MemberUser {
		t.Fatalf("ListUserTenants = %+v, %v", uts, err)
	}

	// Deleting the tenant cascades the memberships.
	if existed, err := s.DeleteTenant(ctx, "t1"); err != nil || !existed {
		t.Fatalf("DeleteTenant = %v, %v", existed, err)
	}
	if left, _ := s.ListUserTenants(ctx, "u1"); len(left) != 0 {
		t.Fatalf("memberships must cascade: %+v", left)
	}
}

func TestGlobalSettingsSeededAndOverridable(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	var ba BusinessAccess
	if err := s.GetSetting(ctx, SettingBusinessAccess, &ba); err != nil {
		t.Fatalf("GetSetting(business_access): %v", err)
	}
	if len(ba.Days) != 7 || ba.Days[0].From != "00:00" || ba.Days[0].To != "23:59" {
		t.Fatalf("default business access: %+v", ba)
	}
	var ttl string
	if err := s.GetSetting(ctx, SettingSessionTTL, &ttl); err != nil || ttl != "PT30M" {
		t.Fatalf("default session ttl = %q, %v", ttl, err)
	}

	ba.Days = ranges("07:30", "23:59", 1, 2, 3, 4, 5)
	if err := s.SetSetting(ctx, SettingBusinessAccess, ba); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	var back BusinessAccess
	if err := s.GetSetting(ctx, SettingBusinessAccess, &back); err != nil || len(back.Days) != 5 || back.Days[0].From != "07:30" {
		t.Fatalf("override round trip: %+v, %v", back, err)
	}
}

func TestResolveInheritance(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "h", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveTenant(ctx, Tenant{ID: "t1", Name: "acme", Enabled: true,
		BusinessAccess: BusinessAccess{Inherited: true}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveMembership(ctx, Membership{UserID: "u1", TenantID: "t1", Type: MemberUser,
		Enabled: true, BusinessAccess: BusinessAccess{Inherited: true}}); err != nil {
		t.Fatal(err)
	}

	// Everything inherited -> the global values apply.
	ba, err := s.ResolveBusinessAccess(ctx, "u1", "t1")
	if err != nil || len(ba.Days) != 7 || ba.Days[0].From != "00:00" {
		t.Fatalf("global fallback: %+v, %v", ba, err)
	}
	if ttl, err := s.ResolveSessionTTL(ctx, "u1", "t1"); err != nil || ttl != "PT30M" {
		t.Fatalf("global ttl fallback: %q, %v", ttl, err)
	}

	// Tenant override wins over global.
	if err := s.SaveTenant(ctx, Tenant{ID: "t1", Name: "acme", Enabled: true, SessionTTL: "PT1H",
		BusinessAccess: BusinessAccess{Timezone: "UTC", Days: ranges("08:00", "18:00", 1, 2, 3, 4, 5)}}); err != nil {
		t.Fatal(err)
	}
	if ba, _ = s.ResolveBusinessAccess(ctx, "u1", "t1"); ba.Days[0].From != "08:00" {
		t.Fatalf("tenant override: %+v", ba)
	}
	if ttl, _ := s.ResolveSessionTTL(ctx, "u1", "t1"); ttl != "PT1H" {
		t.Fatalf("tenant ttl override")
	}

	// Membership override wins over tenant.
	if err := s.SaveMembership(ctx, Membership{UserID: "u1", TenantID: "t1", Type: MemberUser,
		Enabled: true, SessionTTL: "PT10M",
		BusinessAccess: BusinessAccess{Timezone: "UTC", Days: ranges("10:00", "16:00", 2)}}); err != nil {
		t.Fatal(err)
	}
	if ba, _ = s.ResolveBusinessAccess(ctx, "u1", "t1"); len(ba.Days) != 1 || ba.Days[0].From != "10:00" {
		t.Fatalf("membership override: %+v", ba)
	}
	if ttl, _ := s.ResolveSessionTTL(ctx, "u1", "t1"); ttl != "PT10M" {
		t.Fatalf("membership ttl override")
	}

	// No tenant -> straight to global.
	if ttl, _ := s.ResolveSessionTTL(ctx, "u1", ""); ttl != "PT30M" {
		t.Fatalf("no-tenant ttl")
	}
}

func TestWithinBusinessAccess(t *testing.T) {
	// Tuesday 2026-07-21 14:30 UTC.
	now := time.Date(2026, 7, 21, 14, 30, 0, 0, time.UTC)
	in := BusinessAccess{Timezone: "UTC", Days: ranges("08:00", "18:00", 1, 2, 3, 4, 5)}
	if ok, err := WithinBusinessAccess(in, now); err != nil || !ok {
		t.Fatalf("inside window: %v %v", ok, err)
	}
	// Same instant is 23:30 in Tokyo -> outside.
	tokyo := in
	tokyo.Timezone = "Asia/Tokyo"
	if ok, _ := WithinBusinessAccess(tokyo, now); ok {
		t.Fatalf("tokyo evening should be outside")
	}
	// Weekend-only window excludes a Tuesday.
	weekend := BusinessAccess{Days: ranges("", "", 6, 7), Timezone: "UTC"}
	if ok, _ := WithinBusinessAccess(weekend, now); ok {
		t.Fatalf("tuesday is no weekend")
	}
	// Membership date bounds.
	dated := in
	dated.DateTo = "2026-06-30"
	if ok, _ := WithinBusinessAccess(dated, now); ok {
		t.Fatalf("past dateTo must refuse")
	}
	// A split day (lunch break): inside the afternoon range, outside between.
	split := BusinessAccess{Timezone: "UTC", Days: []DayRange{
		{Day: 2, From: "08:00", To: "12:00"}, {Day: 2, From: "14:00", To: "18:00"}}}
	if ok, _ := WithinBusinessAccess(split, now); !ok {
		t.Fatalf("14:30 sits in the afternoon range")
	}
	if ok, _ := WithinBusinessAccess(split, time.Date(2026, 7, 21, 12, 30, 0, 0, time.UTC)); ok {
		t.Fatalf("12:30 falls between the ranges")
	}
	// Bad timezone names the failure.
	bad := in
	bad.Timezone = "Mars/Olympus"
	if _, err := WithinBusinessAccess(bad, now); err == nil || !strings.Contains(err.Error(), "Mars/Olympus") {
		t.Fatalf("bad tz: %v", err)
	}
}

func TestParseISODuration(t *testing.T) {
	cases := map[string]time.Duration{
		"PT10M":  10 * time.Minute,
		"PT30M":  30 * time.Minute,
		"PT2H":   2 * time.Hour,
		"P1D":    24 * time.Hour,
		"P7D":    7 * 24 * time.Hour,
		"P1DT2H": 26 * time.Hour,
	}
	for in, want := range cases {
		if got, err := ParseISODuration(in); err != nil || got != want {
			t.Fatalf("ParseISODuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "P", "30M", "PT", "P1W", "PTM"} {
		if _, err := ParseISODuration(bad); err == nil {
			t.Fatalf("ParseISODuration(%q) must fail", bad)
		}
	}
}

func TestSessionCarriesTenant(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "a", PasswordHash: "h", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, Session{TokenHash: "th", UserID: "u1", TenantID: "t1", ExpiresAt: 4102444800}); err != nil {
		t.Fatal(err)
	}
	sess, err := s.GetSession(ctx, "th")
	if err != nil || sess.TenantID != "t1" {
		t.Fatalf("tenant round trip: %+v, %v", sess, err)
	}
	if err := s.SetSessionTenant(ctx, "th", "t2"); err != nil {
		t.Fatal(err)
	}
	if sess, _ = s.GetSession(ctx, "th"); sess.TenantID != "t2" {
		t.Fatalf("tenant update lost: %+v", sess)
	}
}

func TestThemesLeaveTheStoreComplete(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	// A theme saved with two tokens only comes back with EVERY token filled.
	if err := s.SaveTheme(ctx, Theme{ID: "amber", Name: "amber",
		Dark: map[string]string{"primary": "#ffb86c"}, Light: map[string]string{"primary": "#b8860b"}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTheme(ctx, "amber")
	if err != nil {
		t.Fatal(err)
	}
	if got.Dark["primary"] != "#ffb86c" || got.Light["primary"] != "#b8860b" {
		t.Fatalf("explicit tokens lost: %+v", got)
	}
	def := DefaultTheme()
	for _, key := range ThemeTokenKeys() {
		if got.Dark[key] == "" || got.Light[key] == "" {
			t.Fatalf("token %q not completed: dark=%q light=%q", key, got.Dark[key], got.Light[key])
		}
		if key != "primary" && got.Dark[key] != def.Dark[key] {
			t.Fatalf("token %q should default to %q, got %q", key, def.Dark[key], got.Dark[key])
		}
	}
}

// ranges builds one identical hour range per listed day.
func ranges(from, to string, days ...int) []DayRange {
	out := make([]DayRange, 0, len(days))
	for _, d := range days {
		out = append(out, DayRange{Day: d, From: from, To: to})
	}
	return out
}

// A developer's public certificate: valid PEM in, same PEM out, garbage
// refused, empty clears.
func TestDevCertRoundtrip(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	if err := s.CreateUser(ctx, User{ID: "d1", Username: "neo", PasswordHash: "x", Dev: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dev-neo"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	if err := s.SetUserDevCert(ctx, "d1", pemText); err != nil {
		t.Fatalf("SetUserDevCert: %v", err)
	}
	got, err := s.GetUserDevCert(ctx, "d1")
	if err != nil || got != pemText {
		t.Fatalf("roundtrip failed: %v %q", err, got)
	}
	if err := s.SetUserDevCert(ctx, "d1", "not a cert"); err == nil {
		t.Fatal("garbage certificate accepted")
	}
	if err := s.SetUserDevCert(ctx, "d1", ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got, _ := s.GetUserDevCert(ctx, "d1"); got != "" {
		t.Fatalf("not cleared: %q", got)
	}
}
