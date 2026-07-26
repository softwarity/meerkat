package store

import (
	"errors"
	"testing"
	"time"
)

func TestPasskeyLifecycle(t *testing.T) {
	s, ctx := rbacStore(t)
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "x"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if has, _ := s.HasPasskeys(ctx, "u1"); has {
		t.Fatal("fresh user should have no passkeys")
	}
	if err := s.AddPasskey(ctx, "k1", "u1", "credAAA", `{"id":"AAA"}`, "MacBook"); err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
	if err := s.AddPasskey(ctx, "k2", "u1", "credBBB", `{"id":"BBB"}`, "iPhone"); err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}

	if has, _ := s.HasPasskeys(ctx, "u1"); !has {
		t.Fatal("user should now have passkeys")
	}
	list, _ := s.ListPasskeys(ctx, "u1")
	if len(list) != 2 {
		t.Fatalf("ListPasskeys = %d, want 2", len(list))
	}
	blobs, _ := s.PasskeyBlobs(ctx, "u1")
	if len(blobs) != 2 {
		t.Fatalf("PasskeyBlobs = %d, want 2", len(blobs))
	}

	// A duplicate credential ID is rejected (UNIQUE).
	if err := s.AddPasskey(ctx, "k3", "u1", "credAAA", `{}`, "dup"); err == nil {
		t.Fatal("duplicate credential_id was accepted")
	}

	// Update the blob (sign counter) located by credential ID.
	if err := s.UpdatePasskeyData(ctx, "credAAA", `{"id":"AAA","count":1}`); err != nil {
		t.Fatalf("UpdatePasskeyData: %v", err)
	}
	if err := s.UpdatePasskeyData(ctx, "nope", `{}`); err == nil {
		t.Fatal("update of unknown credential should fail")
	}

	// Revoke is user-scoped and reports existence.
	if ok, _ := s.RevokePasskey(ctx, "u1", "k1"); !ok {
		t.Fatal("revoke should report the credential existed")
	}
	if list, _ := s.ListPasskeys(ctx, "u1"); len(list) != 1 {
		t.Fatalf("after revoke ListPasskeys = %d, want 1", len(list))
	}
}

func TestWebauthnChallengeOneShot(t *testing.T) {
	s, ctx := rbacStore(t)
	now := time.Now().Unix()

	if err := s.PutChallenge(ctx, "c1", `{"challenge":"x"}`, now+300); err != nil {
		t.Fatalf("PutChallenge: %v", err)
	}
	got, err := s.TakeChallenge(ctx, "c1", now)
	if err != nil || got != `{"challenge":"x"}` {
		t.Fatalf("TakeChallenge = %q, %v", got, err)
	}
	// One shot: a second take finds nothing (no replay).
	if _, err := s.TakeChallenge(ctx, "c1", now); err == nil {
		t.Fatal("challenge was replayable")
	}

	// An expired challenge is consumed but reported as gone.
	if err := s.PutChallenge(ctx, "c2", `{}`, now-1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeChallenge(ctx, "c2", now); !errors.Is(err, ErrNoRows) {
		t.Fatalf("expired challenge err = %v, want ErrNoRows", err)
	}

	if n, _ := s.PurgeExpiredChallenges(ctx, now); n != 0 {
		t.Fatalf("purge removed %d, want 0 (c2 already consumed)", n)
	}
}
