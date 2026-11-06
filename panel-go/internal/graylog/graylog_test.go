package graylog

import "testing"

func TestStr(t *testing.T) {
	m := map[string]interface{}{"key": "value", "num": 42.0}
	if str(m, "key") != "value" {
		t.Errorf("expected 'value', got %q", str(m, "key"))
	}
	if str(m, "missing") != "" {
		t.Errorf("expected empty, got %q", str(m, "missing"))
	}
}

func TestToInt64(t *testing.T) {
	m := map[string]interface{}{"count": 42.0}
	if toInt64(m, "count") != 42 {
		t.Errorf("expected 42, got %d", toInt64(m, "count"))
	}
	if toInt64(m, "missing") != 0 {
		t.Errorf("expected 0, got %d", toInt64(m, "missing"))
	}
}

func TestToBool(t *testing.T) {
	m := map[string]interface{}{"flag": true}
	if !toBool(m, "flag") {
		t.Error("expected true for bool")
	}
	if toBool(m, "missing") {
		t.Error("expected false for missing")
	}
}
