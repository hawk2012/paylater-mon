package servercore

import (
	"paylater-mon/internal/config"
	"paylater-mon/internal/models"
	"testing"
)

func TestParsePercent(t *testing.T) {
	cases := map[string]float64{
		"50%":   50,
		"75.5%": 75.5,
		"100":   100,
		"":      0,
		"abc":   0,
		"12.5%": 12.5,
	}
	for input, want := range cases {
		if got := parsePercent(input); got != want {
			t.Errorf("parsePercent(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestParseDockerMem(t *testing.T) {
	cases := map[string]float64{
		"512MiB": 512,
		"1GiB":   1024,
		"768KiB": 0.75,
		"0B":     0,
		"2.5GiB": 2560,
	}
	for input, want := range cases {
		got := parseDockerMem(input)
		if got != want {
			t.Errorf("parseDockerMem(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestAtOf(t *testing.T) {
	if got := atof("123.45"); got != 123.45 {
		t.Errorf("atof(123.45) = %v, want 123.45", got)
	}
	if got := atof(""); got != 0 {
		t.Errorf("atof(empty) = %v, want 0", got)
	}
}

// TestFilterMonitored проверяет фильтрацию: выведенные из эксплуатации и
// серверы из немониторимых групп (mkrt, adm) исключаются.
func TestFilterMonitored(t *testing.T) {
	cfg := config.Default()
	cfg.ServerCore.ExcludedServers = []string{"uz-prod-camunda-1", "172.31.32.37"}
	cfg.ServerCore.ServerGroups = []config.ServerGroupConfig{
		{Name: "Mikrotik", Pattern: "mkrt", Monitored: false},
		{Name: "Администрация", Pattern: "adm", Monitored: false},
		{Name: "Боевые", Pattern: "prod", Monitored: true},
	}
	s := New(cfg, nil)

	hosts := []models.ServerHost{
		{Name: "uz-prod-camunda-1", IpAddress: "172.31.32.61"},   // excluded by name
		{Name: "uz-prod-camunda87-1", IpAddress: "172.31.32.69"}, // prod, monitored
		{Name: "uz-some-server-1", IpAddress: "172.31.32.37"},    // excluded by IP
		{Name: "uz-prod-app-1", IpAddress: "172.31.32.50"},       // prod, monitored
		{Name: "uz-mkrt-ovpn", IpAddress: "172.31.32.100"},       // mkrt, not monitored
		{Name: "uz-adm-nuget-1", IpAddress: "172.31.32.23"},      // adm, not monitored
	}
	out := s.filterMonitored(hosts)
	if len(out) != 2 {
		t.Fatalf("expected 2 monitored hosts, got %d: %+v", len(out), out)
	}
	if out[0].Name != "uz-prod-camunda87-1" || out[1].Name != "uz-prod-app-1" {
		t.Errorf("unexpected survivors: %+v", out)
	}
}

// TestIsServerExcluded проверяет определение исключённого сервера.
func TestIsServerExcluded(t *testing.T) {
	cfg := config.Default()
	cfg.ServerCore.ExcludedServers = []string{"uz-prod-camunda-1", "172.31.32.37"}
	s := New(cfg, nil)

	if !s.IsServerExcluded("uz-prod-camunda-1", "172.31.32.61") {
		t.Error("expected uz-prod-camunda-1 to be excluded by name")
	}
	if !s.IsServerExcluded("any-name", "172.31.32.37") {
		t.Error("expected 172.31.32.37 to be excluded by IP")
	}
	if s.IsServerExcluded("uz-prod-camunda87-1", "172.31.32.69") {
		t.Error("uz-prod-camunda87-1 should not be excluded")
	}
}

// TestCategorizeServer проверяет группировку серверов по имени.
func TestCategorizeServer(t *testing.T) {
	cfg := config.Default()
	cfg.ServerCore.ExcludedServers = []string{"uz-prod-camunda-1"}
	cfg.ServerCore.ServerGroups = []config.ServerGroupConfig{
		{Name: "Mikrotik", Pattern: "mkrt", Monitored: false},
		{Name: "Администрация", Pattern: "adm", Monitored: false},
		{Name: "Мобилка", Pattern: "mob", Monitored: true},
		{Name: "Тестовые", Pattern: "test", Monitored: true},
		{Name: "Боевые", Pattern: "prod", Monitored: true},
	}
	s := New(cfg, nil)

	cases := []struct {
		name        string
		wantGroup   string
		wantMonitor bool
	}{
		{"uz-prod-camunda-1", "Выведены из эксплуатации", false},
		{"uz-mkrt-ovpn", "Mikrotik", false},
		{"uz-adm-nuget-1", "Администрация", false},
		{"uz-mob-app-1", "Мобилка", true},
		{"uz-test-app-1", "Тестовые", true},
		{"uz-prod-camunda87-1", "Боевые", true},
		{"uz-some-other-1", "Прочие", true},
	}
	for _, c := range cases {
		grp, mon := s.CategorizeServer(c.name, "")
		if grp != c.wantGroup || mon != c.wantMonitor {
			t.Errorf("CategorizeServer(%q) = (%q, %v), want (%q, %v)", c.name, grp, mon, c.wantGroup, c.wantMonitor)
		}
	}
}
