package stagingtls

import (
	"sort"
	"strings"
	"testing"
	"time"

	"paylater-mon/internal/tlsscan"
)

func TestIsProdName(t *testing.T) {
	if !isProdName("uz-prod-app-1") {
		t.Error("uz-prod-app-1 should be prod")
	}
	if isProdName("uz-stg-app-1") {
		t.Error("uz-stg-app-1 should not be prod")
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(SeverityCritical) >= severityRank(SeverityWorkaround) {
		t.Error("critical must rank before workaround")
	}
	if severityRank(SeverityWorkaround) >= severityRank(SeverityRecommend) {
		t.Error("workaround must rank before recommendation")
	}
}

func TestTLS13Ports(t *testing.T) {
	sv := tlsscan.ServerTLS{Ports: []tlsscan.PortResult{
		{Port: 443, Versions: map[string]bool{tlsscan.TLS12: true, tlsscan.TLS13: true}, Protocol: tlsscan.ProtoHTTPS},
		{Port: 8080, Versions: map[string]bool{tlsscan.TLS12: true}, Protocol: tlsscan.ProtoTLS},
		{Port: 80, Protocol: tlsscan.ProtoHTTP},
	}}
	ports := tls13Ports(sv)
	if len(ports) != 1 || ports[0] != 443 {
		t.Errorf("expected [443], got %v", ports)
	}
}

func TestReady(t *testing.T) {
	s := New(nil, nil)
	issues := []Issue{
		{Severity: SeverityWorkaround, Message: "w"},
		{Severity: SeverityRecommend, Message: "r"},
	}
	if !s.ready(issues) {
		t.Error("expected ready=true without critical issues")
	}
	issues = append(issues, Issue{Severity: SeverityCritical, Message: "c"})
	if s.ready(issues) {
		t.Error("expected ready=false with critical issue")
	}
}

func TestSummary(t *testing.T) {
	s := New(nil, nil)
	r := &Report{
		Ready: true,
		Prod:  []tlsscan.ServerTLS{{ServerName: "prod-1"}},
		Issues: []Issue{
			{Severity: SeverityCritical},
			{Severity: SeverityWorkaround},
			{Severity: SeverityRecommend},
		},
	}
	sum := s.summary(r)
	for _, want := range []string{"ГОТОВО", "критических 1", "PROD-серверов проверено: 1"} {
		if !contains(sum, want) {
			t.Errorf("summary missing %q: %s", want, sum)
		}
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

// TestParseDockerImages проверяет разбор вывода docker images --digests.
func TestParseDockerImages(t *testing.T) {
	out := "nginx|1.25.3|sha256:abc123def4567890abc123def4567890|a1b2c3\n" +
		"nginx|1.25.3|sha256:abc123def4567890abc123def4567890|a1b2c3\n" + // дубль
		"paylater/api|<none>|sha256:zzz|111\n" +
		"redis|7.2|sha256:xyz987|feed\n" +
		""
	images := parseDockerImages(out)
	if len(images) != 3 {
		t.Fatalf("expected 3 unique images, got %d: %+v", len(images), images)
	}
	if images[0].FullName() != "nginx:1.25.3" {
		t.Errorf("expected nginx:1.25.3, got %q", images[0].FullName())
	}
	if images[0].Digest != "sha256:abc123def4567890abc123def4567890" {
		t.Errorf("digest mismatch: %q", images[0].Digest)
	}
	// Образ без тега — FullName = repository.
	foundNoTag := false
	for _, im := range images {
		if im.FullName() == "paylater/api" {
			foundNoTag = true
		}
	}
	if !foundNoTag {
		t.Error("expected image with <none> tag normalized to repository only")
	}
}

// TestBuildDockerImageIssues проверяет детекцию рассинхрона digest между серверами.
func TestBuildDockerImageIssues(t *testing.T) {
	s := New(nil, nil)
	r := &Report{
		Versions: []ServerVersions{
			{ServerName: "prod-a", DockerImages: []DockerImage{
				{Repository: "nginx", Tag: "1.25.3", Digest: "sha256:aaa"},
				{Repository: "redis", Tag: "7.2", Digest: "sha256:ccc"},
			}},
			{ServerName: "prod-b", DockerImages: []DockerImage{
				{Repository: "nginx", Tag: "1.25.3", Digest: "sha256:bbb"}, // рассинхрон
				{Repository: "redis", Tag: "7.2", Digest: "sha256:ccc"},
			}},
			{ServerName: "prod-c", DockerImages: []DockerImage{
				{Repository: "nginx", Tag: "1.25.3", Digest: "sha256:aaa"},
			}},
		},
	}
	issues := s.buildDockerImageIssues(r)
	foundMismatch := false
	foundPartial := false
	for _, i := range issues {
		if i.Category == "docker" && strings.Contains(i.Message, "разные digest") {
			foundMismatch = true
		}
		if i.Category == "docker" && strings.Contains(i.Message, "присутствует на") {
			foundPartial = true
		}
	}
	if !foundMismatch {
		t.Error("expected digest mismatch issue for nginx:1.25.3")
	}
	if !foundPartial {
		t.Error("expected partial deployment issue for redis (2 из 3)")
	}
}

// TestShortDigest проверяет сокращение digest.
func TestShortDigest(t *testing.T) {
	if got := shortDigest("sha256:abcdef1234567890"); got != "abcdef123456" {
		t.Errorf("expected 12-char digest, got %q", got)
	}
}

// TestPercentileMs проверяет вычисление перцентилей.
func TestPercentileMs(t *testing.T) {
	var durs []time.Duration
	for i := 1; i <= 10; i++ {
		durs = append(durs, time.Duration(i*100)*time.Millisecond)
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	// Индекс: int(9 * 50 / 100) = 4 → 500ms.
	if got := percentileMs(durs, 50); got != 500 {
		t.Errorf("p50 = %v, want 500", got)
	}
	// int(9 * 95 / 100) = 8 → 900ms.
	if got := percentileMs(durs, 95); got != 900 {
		t.Errorf("p95 = %v, want 900", got)
	}
	// int(9 * 99 / 100) = 8 → 900ms.
	if got := percentileMs(durs, 99); got != 900 {
		t.Errorf("p99 = %v, want 900", got)
	}
	// Пустой список.
	if got := percentileMs(nil, 50); got != 0 {
		t.Errorf("empty p50 = %v, want 0", got)
	}
}
