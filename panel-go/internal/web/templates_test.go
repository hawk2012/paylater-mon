package web

import (
	"bytes"
	"net/http/httptest"
	"paylater-mon/internal/models"
	"testing"
)

// TestLoadTemplatesIsolatesContent проверяет, что каждый набор шаблонов
// содержит собственный блок "content" (баг коллизии имён шаблонов:
// раньше все страницы определяли {{define "content"}} и побеждал
// последний разобранный файл).
func TestLoadTemplatesIsolatesContent(t *testing.T) {
	a := &App{}
	sets, err := a.loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates error: %v", err)
	}

	expect := map[string]struct {
		marker string
		data   map[string]interface{}
	}{
		"home":            {"Dashboard", map[string]interface{}{"Title": "Dashboard", "DownContainers": 0, "ServerCount": 0, "TotalContainers": 0, "Problems": []interface{}{}, "Servers": []interface{}{}, "MonitoringEnabled": true}},
		"zeebe_processes": {"Активные инстансы процессов", map[string]interface{}{"Title": "Процессы Zeebe", "Active": nil, "Incidents": nil, "Stuck": nil}},
		"login":           {"Вход в систему", map[string]interface{}{"Title": "Вход"}},
		"system":          {"Система", map[string]interface{}{"Title": "Система", "CanEdit": false, "VaultOk": false, "TeamsOk": false, "AiEnabled": false, "MonitoringEnabled": false, "ConfigJSON": "{}"}},
		"users":           {"Пользователи", map[string]interface{}{"Title": "Пользователи", "Users": nil, "CurrentUser": "admin", "CurrentRole": "superadmin"}},
		"graylog_env": {"Streams", map[string]interface{}{
			"Title":   "Graylog PROD",
			"Env":     "prod",
			"Nodes":   []models.GraylogClusterNode{{Hostname: "node1", Lifecycle: "running", ProcessingMessages: 100, Throughput: 10}},
			"Streams": []models.GraylogStream{{ID: "abc123", Title: "System logs"}},
			"Query":   "",
			"Range":   3600,
			"Search":  nil,
		}},
		"tls": {"TLS-конфигурация серверов", map[string]interface{}{
			"Title": "TLS", "Tips": []string{"tip1"},
		}},
		"staging_tls": {"Staging-TLS", map[string]interface{}{
			"Title": "Staging-TLS",
		}},
	}
	for page, want := range expect {
		tpl, ok := sets[page]
		if !ok {
			t.Errorf("набор шаблонов для страницы %q не найден", page)
			continue
		}
		want.data["ActivePage"] = page
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, "layout", want.data); err != nil {
			t.Errorf("ExecuteTemplate(%q): %v", page, err)
			continue
		}
		if !bytes.Contains(buf.Bytes(), []byte(want.marker)) {
			t.Errorf("страница %q не содержит собственный контент (marker %q)", page, want.marker)
		}
	}

	// Логин-страница не должна содержать контент zeebe_processes и наоборот.
	loginTpl := sets["login"]
	var loginBuf bytes.Buffer
	_ = loginTpl.ExecuteTemplate(&loginBuf, "layout", map[string]interface{}{"Title": "Вход", "ActivePage": "login"})
	if bytes.Contains(loginBuf.Bytes(), []byte("Активные инстансы процессов")) {
		t.Error("login отрисовал контент zeebe_processes — коллизия content-блоков осталась")
	}
}

// TestRenderUsesPageTemplate проверяет, что render выбирает правильный
// набор шаблонов по имени страницы.
func TestRenderUsesPageTemplate(t *testing.T) {
	a := &App{}
	sets, err := a.loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates error: %v", err)
	}
	a.templates = sets

	rr := httptest.NewRecorder()
	a.render(rr, "zeebe_processes", map[string]interface{}{"Title": "Процессы Zeebe"})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("Активные инстансы процессов")) {
		t.Error("render zeebe_processes не отрисовал нужный контент")
	}

	rr2 := httptest.NewRecorder()
	a.render(rr2, "home", map[string]interface{}{"Title": "Dashboard"})
	if rr2.Code != 200 {
		t.Fatalf("expected 200, got %d", rr2.Code)
	}
	if bytes.Contains(rr2.Body.Bytes(), []byte("Активные инстансы процессов")) {
		t.Error("home отрисовал контент zeebe_processes — render не выбирает страницу")
	}
}
