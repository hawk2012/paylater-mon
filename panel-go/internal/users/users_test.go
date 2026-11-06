package users

import (
	"context"
	"encoding/json"
	"testing"
)

// mockBackend — тестовый Vault backend.
type mockBackend struct {
	data []byte
}

func (m *mockBackend) ReadUsers(ctx context.Context) ([]byte, error) {
	return m.data, nil
}

func (m *mockBackend) WriteUsers(ctx context.Context, data []byte) error {
	m.data = data
	return nil
}

func TestLoadCreatesDefaultAdmin(t *testing.T) {
	backend := &mockBackend{}
	store := New(backend)
	if err := store.Load(context.Background()); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	u, ok := store.Get("admin")
	if !ok {
		t.Fatal("expected default admin user")
	}
	if u.Role != RoleSuperAdmin {
		t.Errorf("expected superadmin, got %s", u.Role)
	}
	if !u.MustChangePassword {
		t.Error("expected MustChangePassword=true")
	}
}

func TestAuthenticate(t *testing.T) {
	backend := &mockBackend{}
	store := New(backend)
	_ = store.Load(context.Background())

	u, ok := store.Authenticate("admin", "admin")
	if !ok {
		t.Fatal("expected auth success")
	}
	if u.Username != "admin" {
		t.Errorf("expected admin, got %s", u.Username)
	}

	_, ok = store.Authenticate("admin", "wrong")
	if ok {
		t.Error("expected auth failure with wrong password")
	}

	_, ok = store.Authenticate("nonexistent", "admin")
	if ok {
		t.Error("expected auth failure for nonexistent user")
	}
}

func TestCreateAndDelete(t *testing.T) {
	backend := &mockBackend{}
	store := New(backend)
	_ = store.Load(context.Background())

	err := store.Create(context.Background(), "testuser", "pass123", RoleUser, true)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	u, ok := store.Get("testuser")
	if !ok {
		t.Fatal("expected testuser to exist")
	}
	if u.Role != RoleUser {
		t.Errorf("expected user role, got %s", u.Role)
	}

	// Duplicate should fail.
	err = store.Create(context.Background(), "testuser", "pass", RoleUser, true)
	if err == nil {
		t.Error("expected error for duplicate user")
	}

	// Delete as superadmin.
	err = store.Delete(context.Background(), RoleSuperAdmin, "testuser")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, ok = store.Get("testuser")
	if ok {
		t.Error("expected testuser to be deleted")
	}
}

func TestCannotDeleteLastSuperAdmin(t *testing.T) {
	backend := &mockBackend{}
	store := New(backend)
	_ = store.Load(context.Background())

	err := store.Delete(context.Background(), RoleSuperAdmin, "admin")
	if err == nil {
		t.Error("expected error deleting last superadmin")
	}
}

func TestUpdatePassword(t *testing.T) {
	backend := &mockBackend{}
	store := New(backend)
	_ = store.Load(context.Background())

	err := store.UpdatePassword(context.Background(), "admin", "admin", "newpass123")
	if err != nil {
		t.Fatalf("UpdatePassword failed: %v", err)
	}

	u, ok := store.Authenticate("admin", "newpass123")
	if !ok {
		t.Fatal("expected auth with new password")
	}
	if u.MustChangePassword {
		t.Error("expected MustChangePassword=false after change")
	}
}

func TestUpdateRole(t *testing.T) {
	backend := &mockBackend{}
	store := New(backend)
	_ = store.Load(context.Background())

	// Create second superadmin.
	_ = store.Create(context.Background(), "admin2", "pass", RoleSuperAdmin, false)

	// Demote first admin.
	err := store.UpdateRole(context.Background(), RoleSuperAdmin, "admin", RoleAdmin)
	if err != nil {
		t.Fatalf("UpdateRole failed: %v", err)
	}

	u, _ := store.Get("admin")
	if u.Role != RoleAdmin {
		t.Errorf("expected admin role, got %s", u.Role)
	}
}

func TestCanEditConfig(t *testing.T) {
	if !CanEditConfig(RoleSuperAdmin) {
		t.Error("superadmin should edit config")
	}
	if !CanEditConfig(RoleAdmin) {
		t.Error("admin should edit config")
	}
	if CanEditConfig(RoleUser) {
		t.Error("user should not edit config")
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	p1 := GenerateRandomPassword(12)
	p2 := GenerateRandomPassword(12)
	if len(p1) != 12 {
		t.Errorf("expected length 12, got %d", len(p1))
	}
	if p1 == p2 {
		t.Error("expected different passwords")
	}
}

func TestPersistToBackend(t *testing.T) {
	backend := &mockBackend{}
	store := New(backend)
	_ = store.Load(context.Background())
	_ = store.Create(context.Background(), "user1", "pass", RoleUser, true)

	// Verify backend has data.
	if len(backend.data) == 0 {
		t.Fatal("expected backend to have data")
	}
	var list []User
	if err := json.Unmarshal(backend.data, &list); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(list) < 2 {
		t.Errorf("expected at least 2 users, got %d", len(list))
	}
}
