package servercore

import "testing"

// TestUrlQueryEscape проверяет минимальный URL-encode для query-параметров.
func TestUrlQueryEscape(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"ubuntu-22.04", "ubuntu-22.04"},
		{"my snapshot", "my%20snapshot"},
		{"a/b", "a%2Fb"},
		{"plain", "plain"},
	}
	for _, c := range cases {
		if got := urlQueryEscape(c.in); got != c.want {
			t.Errorf("urlQueryEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestParseCreatedIDNova проверяет извлечение ID созданной ВМ из ответа Nova.
func TestParseCreatedIDNova(t *testing.T) {
	body := []byte(`{"server": {"id": "vm-12345", "name": "clone-1"}}`)
	id := parseCreatedID(body)
	if id != "vm-12345" {
		t.Errorf("expected vm-12345, got %q", id)
	}
}

// TestParseCreatedIDServerCore проверяет извлечение ID из ответа ServerCore.
func TestParseCreatedIDServerCore(t *testing.T) {
	body := []byte(`{"id": "sc-999", "name": "clone-2", "status": "creating"}`)
	id := parseCreatedID(body)
	if id != "sc-999" {
		t.Errorf("expected sc-999, got %q", id)
	}
}

// TestParseCreatedIDEmpty проверяет пустой/невалидный ответ.
func TestParseCreatedIDEmpty(t *testing.T) {
	if id := parseCreatedID([]byte(`{}`)); id != "" {
		t.Errorf("expected empty, got %q", id)
	}
	if id := parseCreatedID([]byte(`not json`)); id != "" {
		t.Errorf("expected empty for invalid json, got %q", id)
	}
}
