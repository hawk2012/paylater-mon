package servercore

import "testing"

func TestParseNovaServers(t *testing.T) {
	body := []byte(`{
		"servers": [
			{
				"id": "abc-123",
				"name": "uz-prod-app-1",
				"status": "ACTIVE",
				"addresses": {
					"private": [{"addr": "172.31.32.10", "version": 4}]
				},
				"flavor": {"id": "flavor-1", "vcpus": 4, "ram": 8192},
				"image": {"id": "img-1"},
				"OS-EXT-STS:vm_state": "active",
				"created": "2024-01-15T10:00:00Z"
			},
			{
				"id": "def-456",
				"name": "uz-test-db-1",
				"status": "SHUTOFF",
				"addresses": {},
				"flavor": {},
				"image": {}
			}
		]
	}`)
	hosts := parseNovaServers(body)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0].ID != "abc-123" {
		t.Errorf("expected ID abc-123, got %s", hosts[0].ID)
	}
	if hosts[0].Name != "uz-prod-app-1" {
		t.Errorf("expected Name uz-prod-app-1, got %s", hosts[0].Name)
	}
}

func TestParseNovaServersEmpty(t *testing.T) {
	hosts := parseNovaServers([]byte(`{"servers": []}`))
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(hosts))
	}
}

func TestParseNovaServersInvalid(t *testing.T) {
	hosts := parseNovaServers([]byte(`not json`))
	if hosts != nil {
		t.Errorf("expected nil for invalid JSON, got %v", hosts)
	}
}

// TestNormalizeOSName проверяет нормализацию имён образов ОС (пункт 61).
func TestNormalizeOSName(t *testing.T) {
	cases := []struct {
		name, id, want string
	}{
		{"ubuntu-22.04-x86_64", "", "Ubuntu 22.04"},
		{"Ubuntu 22.04 LTS", "", "Ubuntu 22.04"},
		{"debian-12-generic", "", "Debian 12"},
		{"windows-server-2019-x86_64", "", "Windows Server 2019"},
		{"centos-7", "", "CentOS 7"},
		{"rocky-9.2", "", "Rocky Linux 9.2"},
		{"", "550e8400-e29b-41d4-a716-446655440000", "Unknown (550e8400)"},
		{"", "", "Unknown"},
		{"routeros-7.10", "", "MikroTik RouterOS 7.10"},
		{"freebsd-13.2", "", "FreeBSD 13.2"},
	}
	for _, c := range cases {
		got := normalizeOSName(c.name, c.id)
		if got != c.want {
			t.Errorf("normalizeOSName(%q, %q) = %q, want %q", c.name, c.id, got, c.want)
		}
	}
}

// TestLooksLikeGUID проверяет детекцию UUID/GUID.
func TestLooksLikeGUID(t *testing.T) {
	if !looksLikeGUID("550e8400-e29b-41d4-a716-446655440000") {
		t.Error("valid UUID should be detected as GUID")
	}
	if looksLikeGUID("ubuntu-22.04") {
		t.Error("ubuntu-22.04 should not be GUID")
	}
	if looksLikeGUID("Ubuntu 22.04 LTS") {
		t.Error("human-readable name should not be GUID")
	}
}

// TestParseGlanceImages проверяет разбор ответа Glance v2.
func TestParseGlanceImages(t *testing.T) {
	body := []byte(`{
		"images": [
			{"id": "img-001", "name": "ubuntu-22.04-x86_64", "status": "active", "size": 5368709120},
			{"id": "img-002", "name": "windows-server-2019", "status": "active"}
		]
	}`)
	images := parseGlanceImages(body)
	if len(images) != 2 {
		t.Fatalf("expected 2 images, got %d", len(images))
	}
	if images[0].OperatingSystem != "Ubuntu 22.04" {
		t.Errorf("expected Ubuntu 22.04, got %q", images[0].OperatingSystem)
	}
	if images[1].OperatingSystem != "Windows Server 2019" {
		t.Errorf("expected Windows Server 2019, got %q", images[1].OperatingSystem)
	}
}
