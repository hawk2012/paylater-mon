package sessions

import "testing"

func TestCreateAndGet(t *testing.T) {
	s := New()
	sess := s.Create("testuser")
	if sess.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if sess.Username != "testuser" {
		t.Errorf("expected testuser, got %s", sess.Username)
	}

	username := s.Get(sess.Token)
	if username != "testuser" {
		t.Errorf("expected testuser, got %s", username)
	}
}

func TestGetInvalidToken(t *testing.T) {
	s := New()
	if username := s.Get("invalid"); username != "" {
		t.Errorf("expected empty username, got %s", username)
	}
}

func TestDelete(t *testing.T) {
	s := New()
	sess := s.Create("user1")
	s.Delete(sess.Token)
	if username := s.Get(sess.Token); username != "" {
		t.Errorf("expected empty after delete, got %s", username)
	}
}
