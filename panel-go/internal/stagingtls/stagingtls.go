// Package stagingtls — раздел «Staging-TLS»: проверка готовности PROD-серверов
// к включению TLS 1.3. Серверы берутся напрямую из списка ServerCore (Nova)
// по имени (prod), сканируются на TLS/HTTP/nginx/Docker, собираются версии ПО,
// проводится нагрузочный тест TLS 1.3.
//
// По итогам формируется отчёт о выявленных проблемах:
//   - критические (блокируют включение TLS 1.3 в PROD);
//   - критические с обходными путями (workaround);
//   - рекомендации.
//
// и заключение о готовности инфраструктуры к включению TLS 1.3 в PROD.
package stagingtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"paylater-mon/internal/config"
	"paylater-mon/internal/servercore"
	"paylater-mon/internal/tlsscan"
)

// Severity — типы проблем в отчёте.
const (
	SeverityCritical   = "critical"   // блокирует включение TLS 1.3
	SeverityWorkaround = "workaround" // критическое, но есть обходной путь
	SeverityRecommend  = "recommendation"
)

// ServerVersions — версии ПО на сервере (собираются через SSH).
type ServerVersions struct {
	ServerName string `json:"server_name"`
	OSVersion  string `json:"os_version"`
	Kernel     string `json:"kernel"`
	Docker     string `json:"docker"`
	Nginx      string `json:"nginx"`
	OpenSSL    string `json:"openssl"`
	Java       string `json:"java"`
	Node       string `json:"node"`
	// Пункт 48: Docker-образы/теги/digest на сервере.
	DockerImages []DockerImage `json:"docker_images,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// DockerImage — образ Docker, установленный на сервере (пункт 48).
type DockerImage struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
	ID         string `json:"id"`
}

// FullName возвращает "repo:tag" или "repo" если тега нет.
func (d DockerImage) FullName() string {
	if d.Tag != "" && d.Tag != "<none>" {
		return d.Repository + ":" + d.Tag
	}
	return d.Repository
}

// Component — имя компонента для сравнения версий PROD vs Staging.
func (v ServerVersions) Component(name string) string {
	switch name {
	case "os":
		return v.OSVersion
	case "kernel":
		return v.Kernel
	case "docker":
		return v.Docker
	case "nginx":
		return v.Nginx
	case "openssl":
		return v.OpenSSL
	case "java":
		return v.Java
	case "node":
		return v.Node
	}
	return ""
}

// LoadTestResult — результат нагрузочного теста TLS 1.3.
type LoadTestResult struct {
	Server      string  `json:"server"`
	IP          string  `json:"ip"`
	Port        int     `json:"port"`
	Connections int     `json:"connections"`
	Success     int     `json:"success"`
	Failed      int     `json:"failed"`
	AvgMs       float64 `json:"avg_ms"`
	MinMs       float64 `json:"min_ms"`
	MaxMs       float64 `json:"max_ms"`
	// Пункт 49: расширенные метрики нагрузки.
	P50Ms    float64 `json:"p50_ms"`
	P95Ms    float64 `json:"p95_ms"`
	P99Ms    float64 `json:"p99_ms"`
	RPS      float64 `json:"rps"`
	TotalSec float64 `json:"total_sec"`
	Error    string  `json:"error,omitempty"`
}

// Issue — проблема в отчёте Staging-TLS.
type Issue struct {
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Server     string `json:"server,omitempty"`
	Message    string `json:"message"`
	Workaround string `json:"workaround,omitempty"`
}

// Report — итоговый отчёт по проверке PROD-серверов.
type Report struct {
	GeneratedAt string              `json:"generated_at"`
	ProdNames   []string            `json:"prod_names"`
	Prod        []tlsscan.ServerTLS `json:"prod"`
	Versions    []ServerVersions    `json:"versions"`
	LoadTests   []LoadTestResult    `json:"load_tests"`
	Issues      []Issue             `json:"issues"`
	Ready       bool                `json:"ready"`
	Summary     string              `json:"summary"`
	ServerError string              `json:"server_error,omitempty"` // ошибка получения списка серверов
	// Stats — агрегированная статистика для UI.
	Stats *ReportStats `json:"stats,omitempty"`
}

// ReportStats — агрегированная статистика по проверке.
type ReportStats struct {
	TotalServers   int `json:"total_servers"`
	ScannedOK      int `json:"scanned_ok"`        // без ошибок сканирования
	ScanErrors     int `json:"scan_errors"`       // серверы с ошибкой сканирования
	TLS13Servers   int `json:"tls13_servers"`     // серверы с хотя бы одним портом TLS 1.3
	TLS12Only      int `json:"tls12_only"`        // серверы с TLS 1.2, но без TLS 1.3
	HTTPOnly       int `json:"http_only"`         // серверы только с HTTP (без TLS)
	NginxServers   int `json:"nginx_servers"`     // серверы с установленным nginx
	IISBackends    int `json:"iis_backends"`      // IIS-бэкенды
	BackendServers int `json:"backend_servers"`   // бэкенды за nginx (NAT)
	TotalPorts     int `json:"total_ports"`       // всего проверено портов
	TLS13Ports     int `json:"tls13_ports"`       // портов с TLS 1.3
	TLS12Ports     int `json:"tls12_ports"`       // портов с TLS 1.2
	HTTTPorts      int `json:"http_ports"`        // портов с HTTP без TLS
	WeakCipherPrt  int `json:"weak_cipher_ports"` // портов со слабыми cipher suites
	CriticalCnt    int `json:"critical_count"`
	WorkaroundCnt  int `json:"workaround_count"`
	RecommendCnt   int `json:"recommend_count"`
	LoadTestTotal  int `json:"load_test_total"`
	LoadTestOK     int `json:"load_test_ok"`
	LoadTestFail   int `json:"load_test_fail"`
	// Пункт 48: Docker-образы.
	DockerImagesTotal    int `json:"docker_images_total"`    // уникальных repo:tag на всех серверах
	DockerImagesMismatch int `json:"docker_images_mismatch"` // образов с расхождением digest
}

// Service — сервис проверки Staging-TLS.
type Service struct {
	cfg     *config.Config
	sc      *servercore.Service
	scanner *tlsscan.Scanner
}

// New создаёт сервис Staging-TLS.
func New(cfg *config.Config, sc *servercore.Service) *Service {
	return &Service{cfg: cfg, sc: sc, scanner: tlsscan.New(sc, nil)}
}

// ApplyConfig обновляет конфигурацию на лету.
func (s *Service) ApplyConfig(cfg *config.Config) {
	s.cfg = cfg
}

// isProdName — автоопределение PROD-сервера по имени.
func isProdName(name string) bool {
	return strings.Contains(strings.ToLower(name), "prod")
}

// ProdServers возвращает имена PROD-серверов из списка ServerCore (с ограничением).
// Берутся только серверы с "prod" в имени. Возвращает ошибку получения списка.
func (s *Service) ProdServers(ctx context.Context) ([]string, error) {
	servers, err := s.sc.GetServers(ctx)
	max := 20
	if s.cfg != nil && s.cfg.StagingTLS.MaxProdScan > 0 {
		max = s.cfg.StagingTLS.MaxProdScan
	}
	var out []string
	for _, sv := range servers {
		if isProdName(sv.Name) {
			out = append(out, sv.Name)
		}
		if len(out) >= max {
			break
		}
	}
	return out, err
}

// Probe выполняет полную проверку Staging-TLS и возвращает отчёт.
func (s *Service) Probe(ctx context.Context) *Report {
	return s.ProbeWithProgress(ctx, nil)
}

// ProbeWithProgress — проверка PROD-серверов с колбэком прогресса.
// Фазы: prod / versions / load / issues. Колбэк можно передать nil.
// Уважает отмену контекста: если контекст отменён между фазами, возвращает
// partial report (с тем, что успели собрать).
func (s *Service) ProbeWithProgress(ctx context.Context, cb func(phase string, done, total int)) *Report {
	report := &Report{GeneratedAt: time.Now().Format("2006-01-02 15:04:05")}
	var err error
	report.ProdNames, err = s.ProdServers(ctx)
	if err != nil {
		report.ServerError = fmt.Sprintf("Ошибка получения списка серверов: %v", err)
	}
	progress := func(phase string, done, total int) {
		if cb != nil {
			cb(phase, done, total)
		}
	}

	// Если список серверов пуст — нет смысла продолжать.
	if len(report.ProdNames) == 0 {
		progress("issues", 0, 1)
		if report.ServerError == "" {
			report.ServerError = "Серверы не найдены в ServerCore. Проверьте подключение и список серверов."
		}
		report.Issues = []Issue{{
			Severity: SeverityCritical,
			Category: "infra",
			Message:  report.ServerError,
		}}
		report.Ready = false
		report.Summary = report.ServerError
		progress("issues", 1, 1)
		return report
	}

	// 1. Сканирование TLS/HTTP/nginx/docker — PROD-серверы.
	report.Prod = s.scanConcurrent(ctx, report.ProdNames, "prod", progress)
	if ctx.Err() != nil {
		return s.finalizePartial(report, progress)
	}

	// 2. Версии ПО (SSH) — только для Linux-серверов, параллельно.
	linuxTargets := make([]string, 0, len(report.ProdNames))
	for _, name := range report.ProdNames {
		os := serverOS(report, name)
		if os == tlsscan.OSLinux || os == "" {
			linuxTargets = append(linuxTargets, name)
		}
	}
	report.Versions = s.collectVersionsConcurrent(ctx, linuxTargets, progress)
	if ctx.Err() != nil {
		return s.finalizePartial(report, progress)
	}

	// 3. Нагрузочный тест TLS 1.3 по TLS-портам PROD-серверов.
	report.LoadTests = s.runLoadTestsProgress(ctx, report.Prod, progress)

	// 4. Проблемы и готовность.
	progress("issues", 0, 1)
	report.Issues = s.buildIssues(report)
	report.Stats = s.computeStats(report)
	report.Ready = s.ready(report.Issues)
	report.Summary = s.summary(report)
	progress("issues", 1, 1)
	return report
}

// finalizePartial завершает отчёт при отмене контекста — формирует issues/summary
// с теми данными, что успели собрать.
func (s *Service) finalizePartial(report *Report, progress func(string, int, int)) *Report {
	progress("issues", 0, 1)
	report.Issues = s.buildIssues(report)
	report.Stats = s.computeStats(report)
	report.Ready = s.ready(report.Issues)
	report.Summary = s.summary(report) + " (проверка прервана по таймауту — данные могут быть неполными)"
	progress("issues", 1, 1)
	return report
}

// scanConcurrency возвращает лимит параллельных сканов из конфига (по умолчанию 4).
func (s *Service) scanConcurrency() int {
	if s.cfg != nil && s.cfg.StagingTLS.ScanConcurrency > 0 {
		return s.cfg.StagingTLS.ScanConcurrency
	}
	return 4
}

// perServerScanTimeout — таймаут на сканирование одного сервера в staging-проверке.
// Защищает от зависания всей фазы на одном нереспонсивном сервере.
const perServerScanTimeout = 90 * time.Second

// scanConcurrent сканирует серверы параллельно с ограничением конкуренции,
// сообщая прогресс через cb(phase, done, total).
//
// Ключевая защита от зависания: если контекст отменён (или истёк общий таймаут),
// функция НЕ ждёт зависшие горутины — она возвращается с частичными результатами.
// Семафорор context-aware: горутины, ожидающие семафор, прерываются по ctx.Done().
func (s *Service) scanConcurrent(ctx context.Context, names []string, phase string, cb func(string, int, int)) []tlsscan.ServerTLS {
	if len(names) == 0 {
		if cb != nil {
			cb(phase, 0, 0)
		}
		return nil
	}
	conc := s.scanConcurrency()
	if conc > len(names) {
		conc = len(names)
	}

	results := make([]tlsscan.ServerTLS, len(names))
	var (
		mu   sync.Mutex
		done int
	)
	if cb != nil {
		cb(phase, 0, len(names))
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, name := range names {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx int, n string) {
			defer wg.Done()
			// Context-aware semaphore: не блокируем на семафоре, если контекст отменён.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			// Per-server таймаут: один сервер не должен занимать больше perServerScanTimeout.
			serverCtx, serverCancel := context.WithTimeout(ctx, perServerScanTimeout)
			defer serverCancel()
			results[idx] = s.scanner.Scan(serverCtx, n)
			mu.Lock()
			done++
			if cb != nil {
				cb(phase, done, len(names))
			}
			mu.Unlock()
		}(i, name)
	}
	// Context-aware wait: не блокируем навсегда, если горутина зависла.
	wgWaitCtx(ctx, &wg)
	return results
}

// collectVersionsConcurrent собирает версии ПО параллельно с ограничением конкуренции.
// Context-aware: не блокирует навсегда на зависших горутинах.
func (s *Service) collectVersionsConcurrent(ctx context.Context, names []string, cb func(string, int, int)) []ServerVersions {
	if len(names) == 0 {
		if cb != nil {
			cb("versions", 0, 0)
		}
		return nil
	}
	conc := s.scanConcurrency()
	if conc > len(names) {
		conc = len(names)
	}

	results := make([]ServerVersions, len(names))
	var (
		mu   sync.Mutex
		done int
	)
	if cb != nil {
		cb("versions", 0, len(names))
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, name := range names {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx int, n string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			serverCtx, serverCancel := context.WithTimeout(ctx, perServerScanTimeout)
			defer serverCancel()
			results[idx] = s.collectVersions(serverCtx, n)
			mu.Lock()
			done++
			if cb != nil {
				cb("versions", done, len(names))
			}
			mu.Unlock()
		}(i, name)
	}
	wgWaitCtx(ctx, &wg)
	return results
}

// wgWaitCtx ждёт завершения WaitGroup, но не дольше ctx. Если контекст отменён,
// функция возвращается немедленно, оставляя горутины работать в фоне (они будут
// заблокированы на sem <- struct{}{} или в SSH-операции, но рано или поздно
// завершатся по своему per-server таймауту).
func wgWaitCtx(ctx context.Context, wg *sync.WaitGroup) {
	done := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// serverOS возвращает ОС сервера по результатам сканирования.
func serverOS(r *Report, name string) string {
	for _, sv := range r.Prod {
		if sv.ServerName == name {
			return sv.OS
		}
	}
	return ""
}

// collectVersions собирает версии ПО сервера через SSH.
func (s *Service) collectVersions(ctx context.Context, name string) ServerVersions {
	v := ServerVersions{ServerName: name}
	client, err := s.sc.GetSSHClient(ctx, name)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	defer client.Close()

	cmds := []struct {
		dst *string
		cmd string
	}{
		{&v.OSVersion, `grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"'`},
		{&v.Kernel, "uname -r"},
		{&v.Docker, "docker version --format '{{.Server.Version}}' 2>/dev/null"},
		{&v.Nginx, "nginx -v 2>&1"},
		{&v.OpenSSL, "openssl version"},
		{&v.Java, "java -version 2>&1 | head -1"},
		{&v.Node, "node -v 2>/dev/null"},
	}
	for _, c := range cmds {
		if ctx.Err() != nil {
			break
		}
		if out, err := client.RunContext(ctx, c.cmd); err == nil {
			*c.dst = strings.TrimSpace(out)
		}
	}
	// Пункт 48: Docker-образы/теги/digest (docker images --digests).
	if ctx.Err() == nil {
		if out, err := client.RunContext(ctx, `docker images --digests --format '{{.Repository}}|{{.Tag}}|{{.Digest}}|{{.ID}}' 2>/dev/null`); err == nil {
			v.DockerImages = parseDockerImages(out)
		}
	}
	return v
}

// parseDockerImages разбирает вывод `docker images --digests --format` в список образов.
func parseDockerImages(out string) []DockerImage {
	var images []DockerImage
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		img := DockerImage{Repository: strings.TrimSpace(parts[0])}
		if len(parts) > 1 {
			img.Tag = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			img.Digest = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			img.ID = strings.TrimSpace(parts[3])
		}
		if img.Repository == "" {
			continue
		}
		// Дедупликация по репозиторий:тег (digest может отличаться).
		key := img.FullName()
		if img.Digest != "" && img.Digest != "<none>" {
			key += "@" + img.Digest
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		images = append(images, img)
	}
	sort.Slice(images, func(i, j int) bool {
		return images[i].FullName() < images[j].FullName()
	})
	return images
}

// runLoadTestsProgress выполняет нагрузочный TLS 1.3 тест на TLS-портах staging,
// отдавая прогресс через cb("load", done, total).
func (s *Service) runLoadTestsProgress(ctx context.Context, staging []tlsscan.ServerTLS, cb func(phase string, done, total int)) []LoadTestResult {
	conns, conc := 20, 5
	timeoutSec := 60
	if s.cfg != nil {
		if s.cfg.StagingTLS.LoadTestConnections > 0 {
			conns = s.cfg.StagingTLS.LoadTestConnections
		}
		if s.cfg.StagingTLS.LoadTestConcurrency > 0 {
			conc = s.cfg.StagingTLS.LoadTestConcurrency
		}
		if s.cfg.StagingTLS.LoadTestTimeoutSec > 0 {
			timeoutSec = s.cfg.StagingTLS.LoadTestTimeoutSec
		}
	}
	testCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	// Считаем общее число тестов для прогресса.
	totalTests := 0
	for _, sv := range staging {
		if s.cfg != nil && s.cfg.StagingTLS.LoadTestTargetPort > 0 {
			totalTests++
		} else {
			totalTests += len(tls13Ports(sv))
		}
	}

	var results []LoadTestResult
	done := 0
	for _, sv := range staging {
		targetPort := 0
		if s.cfg != nil {
			targetPort = s.cfg.StagingTLS.LoadTestTargetPort
		}
		ports := tls13Ports(sv)
		if targetPort > 0 {
			// Проверяем только указанный порт.
			ports = []int{targetPort}
		}
		for _, p := range ports {
			cb("load", done, totalTests)
			addr := net.JoinHostPort(sv.IP, fmt.Sprint(p))
			results = append(results, tls13LoadTest(testCtx, sv.ServerName, sv.IP, p, addr, conns, conc))
			done++
		}
	}
	cb("load", done, totalTests)
	return results
}

// tls13Ports возвращает порты сервера, где поддерживается TLS 1.3.
func tls13Ports(sv tlsscan.ServerTLS) []int {
	var out []int
	for _, p := range sv.Ports {
		if p.Versions[tlsscan.TLS13] {
			out = append(out, p.Port)
		}
	}
	sort.Ints(out)
	return out
}

// tls13LoadTest — нагрузочный тест: conns TLS 1.3 рукопожатий, conc параллельно.
// Пункт 49: помимо avg/min/max считаются перцентили p50/p95/p99 и RPS.
func tls13LoadTest(ctx context.Context, server, ip string, port int, addr string, conns, conc int) LoadTestResult {
	res := LoadTestResult{Server: server, IP: ip, Port: port, Connections: conns}
	if conns <= 0 {
		conns = 20
	}
	if conc <= 0 {
		conc = 5
	}

	start := time.Now()
	var (
		mu      sync.Mutex
		times   []time.Duration
		success int
		failed  int
	)

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			t0 := time.Now()
			d := &net.Dialer{Timeout: 5 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			tconn := tls.Client(conn, &tls.Config{
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			})
			_ = tconn.SetDeadline(time.Now().Add(5 * time.Second))
			err = tconn.HandshakeContext(ctx)
			_ = tconn.Close()
			elapsed := time.Since(t0)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
			} else {
				success++
				times = append(times, elapsed)
			}
		}()
	}
	wg.Wait()

	elapsedTotal := time.Since(start)

	res.Success = success
	res.Failed = failed
	res.TotalSec = elapsedTotal.Seconds()
	if len(times) > 0 {
		var total time.Duration
		for _, t := range times {
			total += t
		}
		min, max := times[0], times[0]
		for _, t := range times {
			if t < min {
				min = t
			}
			if t > max {
				max = t
			}
		}
		res.AvgMs = float64(total.Nanoseconds()) / float64(len(times)) / 1e6
		res.MinMs = float64(min.Nanoseconds()) / 1e6
		res.MaxMs = float64(max.Nanoseconds()) / 1e6

		sorted := make([]time.Duration, len(times))
		copy(sorted, times)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		res.P50Ms = percentileMs(sorted, 50)
		res.P95Ms = percentileMs(sorted, 95)
		res.P99Ms = percentileMs(sorted, 99)
	}
	// RPS: успешных рукопожатий в секунду (по общему времени теста).
	if res.TotalSec > 0 {
		res.RPS = float64(success) / res.TotalSec
	}
	if success == 0 && conns > 0 {
		res.Error = "все TLS 1.3 рукопожатия завершились ошибкой"
	}
	return res
}

// percentileMs возвращает N-й перцентиль отсортированного списка длительностей.
func percentileMs(sorted []time.Duration, pct float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * pct / 100)
	return float64(sorted[idx].Nanoseconds()) / 1e6
}

// isNginxName — фронтовый nginx-сервер (наружу отдаёт TLS).
func isNginxName(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "ngx") || strings.Contains(l, "nginx")
}

// isIISName — сервер с IIS как бэкендом (nginx на нём нет).
func isIISName(name string) bool {
	return strings.Contains(strings.ToLower(name), "iis")
}

// buildIssues формирует проблемы отчёта: критические, с обходными путями,
// рекомендации — по результатам проверки PROD-серверов.
//
// Учитывается архитектура: всё за NAT + nginx (TLS 1.2/1.3) наружу.
// Если включён staging_tls.nginx_fronted, внутренние сервисы (бэкенды)
// не помечаются за отсутствие TLS 1.3 / HTTP без TLS — TLS терминирует
// фронтовый nginx. IIS-серверы (iis в имени) — бэкенды без nginx.
func (s *Service) buildIssues(r *Report) []Issue {
	var issues []Issue

	nginxFronted := s.cfg != nil && s.cfg.StagingTLS.NginxFronted

	// Критические: нет PROD-серверов.
	if len(r.Prod) == 0 {
		issues = append(issues, Issue{
			Severity: SeverityCritical,
			Category: "infra",
			Message:  "Не найдены PROD-серверы. Проверьте имена серверов в ServerCore (должны содержать «prod»).",
		})
	}

	for _, sv := range r.Prod {
		backend := nginxFronted && !isNginxName(sv.ServerName)
		iisBackend := isIISName(sv.ServerName)

		// Критические: на сервере нет TLS 1.3.
		// Для бэкендов за nginx (NAT) или IIS это НЕ критично — TLS терминирует
		// фронтовый nginx / IIS слушает внутри.
		if len(tls13Ports(sv)) == 0 && sv.Error == "" && !backend && !iisBackend {
			issues = append(issues, Issue{
				Severity: SeverityCritical,
				Category: "tls13",
				Server:   sv.ServerName,
				Message:  "На сервере нет ни одного порта с поддержкой TLS 1.3 — включение TLS 1.3 невозможно.",
			})
		}
		// Workaround: TLS 1.3 есть, но не на всех TLS-портах.
		// Для бэкендов за nginx это штатная ситуация (терминирует nginx).
		if len(tls13Ports(sv)) > 0 && !backend {
			for _, p := range sv.Ports {
				if p.Protocol == tlsscan.ProtoTLS || p.Protocol == tlsscan.ProtoHTTPS {
					if !p.Versions[tlsscan.TLS13] {
						issues = append(issues, Issue{
							Severity:   SeverityWorkaround,
							Category:   "tls13",
							Server:     sv.ServerName,
							Message:    fmt.Sprintf("Порт %d работает по TLS, но без TLS 1.3.", p.Port),
							Workaround: "Заверните сервис за nginx reverse proxy с ssl_protocols TLSv1.2 TLSv1.3.",
						})
					}
				}
			}
		}
		// Workaround: HTTP без TLS. Бэкенды за nginx/NAT — штатно.
		if !backend && !iisBackend {
			for _, p := range sv.Ports {
				if p.Protocol == tlsscan.ProtoHTTP {
					issues = append(issues, Issue{
						Severity:   SeverityWorkaround,
						Category:   "http",
						Server:     sv.ServerName,
						Message:    fmt.Sprintf("Порт %d отдаёт HTTP без TLS.", p.Port),
						Workaround: "Поставьте перед ним HTTPS-балансировщик (nginx) с TLS 1.3.",
					})
				}
			}
		}
		// Рекомендации nginx — только если nginx установлен на сервере
		// (на IIS-бэкендах его нет по определению).
		if sv.Nginx.Installed {
			for _, iss := range sv.Nginx.Issues {
				issues = append(issues, Issue{
					Severity: SeverityRecommend,
					Category: "nginx",
					Server:   sv.ServerName,
					Message:  "nginx: " + iss,
				})
			}
		}
		// Рекомендации: устаревшие TLS.
		for _, p := range sv.Ports {
			for ver, ok := range p.Versions {
				if !ok {
					continue
				}
				switch ver {
				case tlsscan.TLS10, tlsscan.TLS11:
					issues = append(issues, Issue{
						Severity: SeverityRecommend,
						Category: "tls",
						Server:   sv.ServerName,
						Message:  fmt.Sprintf("%s включён на порту %d (RFC 8996) — отключите.", ver, p.Port),
					})
				}
			}
		}
	}

	// Критические: версии ПО.
	for _, v := range r.Versions {
		if strings.Contains(strings.ToLower(v.OpenSSL), "openssl 1.0") || strings.Contains(strings.ToLower(v.OpenSSL), "openssl 1.0.2") {
			issues = append(issues, Issue{
				Severity: SeverityCritical,
				Category: "versions",
				Server:   v.ServerName,
				Message:  "OpenSSL " + v.OpenSSL + " — не поддерживает TLS 1.3 (нужен 1.1.1+).",
			})
		}
	}

	// Критические: нагрузочный тест полностью провалился.
	for _, lt := range r.LoadTests {
		if lt.Error != "" {
			issues = append(issues, Issue{
				Severity: SeverityCritical,
				Category: "load",
				Server:   lt.Server,
				Message:  fmt.Sprintf("Нагрузочный тест TLS 1.3 на порту %d провален (%d из %d успешных).", lt.Port, lt.Success, lt.Connections),
			})
		}
	}

	// Пункт 48: сравнение версий Docker-образов между PROD-серверами.
	issues = append(issues, s.buildDockerImageIssues(r)...)

	sort.SliceStable(issues, func(i, j int) bool {
		return severityRank(issues[i].Severity) < severityRank(issues[j].Severity)
	})
	return issues
}

// buildDockerImageIssues находит несоответствия Docker-образов между серверами:
// один и тот же образ (repo:tag) с разными digest на разных PROD-серверах —
// признак рассинхрона версий, а также образы без тега/устаревшие (<none>).
func (s *Service) buildDockerImageIssues(r *Report) []Issue {
	var issues []Issue

	// digest по ключу "repo:tag" → множество digest (server → digest).
	digests := map[string]map[string]string{} // key: repo:tag -> server -> digest
	tagged := map[string]int{}
	for _, v := range r.Versions {
		if v.Error != "" {
			continue
		}
		for _, img := range v.DockerImages {
			key := img.FullName()
			if img.Tag == "<none>" || img.Tag == "" {
				continue
			}
			tagged[key]++
			if img.Digest == "" || img.Digest == "<none>" {
				continue
			}
			if digests[key] == nil {
				digests[key] = map[string]string{}
			}
			digests[key][v.ServerName] = img.Digest
		}
	}

	// Образ присутствует на >1 сервере и с разными digest.
	for key, servers := range digests {
		if len(servers) < 2 {
			continue
		}
		distinct := map[string]string{}
		for _, d := range servers {
			distinct[d] = d
		}
		if len(distinct) > 1 {
			var parts []string
			for srv, d := range servers {
				parts = append(parts, srv+"="+shortDigest(d))
			}
			sort.Strings(parts)
			issues = append(issues, Issue{
				Severity:   SeverityWorkaround,
				Category:   "docker",
				Message:    fmt.Sprintf("Docker-образ %s имеет разные digest на серверах: %s — версии контейнеров рассинхронизированы.", key, strings.Join(parts, ", ")),
				Workaround: "Обновите образ до единой версии на всех серверах и пересоздайте контейнеры.",
			})
		}
	}

	// Образы только на части серверов — возможно, не весь кластер обновлён.
	serverCount := 0
	for _, v := range r.Versions {
		if v.Error == "" {
			serverCount++
		}
	}
	if serverCount > 1 {
		for key, n := range tagged {
			if n < serverCount {
				issues = append(issues, Issue{
					Severity: SeverityRecommend,
					Category: "docker",
					Message:  fmt.Sprintf("Docker-образ %s присутствует на %d из %d PROD-серверов — проверьте одинаковое развёртывание.", key, n, serverCount),
				})
			}
		}
	}

	return issues
}

// shortDigest сокращает полный digest до 12 символов.
func shortDigest(d string) string {
	if i := strings.LastIndex(d, ":"); i >= 0 {
		d = d[i+1:]
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// severityRank — порядок сортировки проблем.
func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityWorkaround:
		return 1
	default:
		return 2
	}
}

// computeStats агрегирует статистику по результатам проверки.
func (s *Service) computeStats(r *Report) *ReportStats {
	nginxFronted := s.cfg != nil && s.cfg.StagingTLS.NginxFronted
	st := &ReportStats{TotalServers: len(r.Prod)}

	for _, sv := range r.Prod {
		if sv.Error != "" {
			st.ScanErrors++
			continue
		}
		st.ScannedOK++

		isNginx := isNginxName(sv.ServerName)
		isIIS := isIISName(sv.ServerName)
		if isNginx {
			st.NginxServers++
		}
		if isIIS {
			st.IISBackends++
		}
		if nginxFronted && !isNginx {
			st.BackendServers++
		}

		hasTLS13 := false
		hasTLS12 := false
		hasHTTPOnly := true
		for _, p := range sv.Ports {
			st.TotalPorts++
			if p.Versions[tlsscan.TLS13] {
				hasTLS13 = true
				st.TLS13Ports++
			}
			if p.Versions[tlsscan.TLS12] {
				hasTLS12 = true
				st.TLS12Ports++
			}
			if p.Protocol == tlsscan.ProtoHTTP {
				st.HTTTPorts++
			}
			if p.Protocol == tlsscan.ProtoTLS || p.Protocol == tlsscan.ProtoHTTPS {
				hasHTTPOnly = false
			}
			if len(p.WeakCiphers) > 0 {
				st.WeakCipherPrt++
			}
		}
		if hasTLS13 {
			st.TLS13Servers++
		} else if hasTLS12 {
			st.TLS12Only++
		}
		if hasHTTPOnly && len(sv.Ports) > 0 {
			st.HTTPOnly++
		}
		if sv.Nginx.Installed {
			// уже учли в NginxServers по имени, но если nginx установлен
			// на сервере без "ngx" в имени — тоже считаем
			if !isNginx {
				st.NginxServers++
			}
		}
	}

	for _, i := range r.Issues {
		switch i.Severity {
		case SeverityCritical:
			st.CriticalCnt++
		case SeverityWorkaround:
			st.WorkaroundCnt++
		default:
			st.RecommendCnt++
		}
	}

	for _, lt := range r.LoadTests {
		st.LoadTestTotal++
		if lt.Error != "" {
			st.LoadTestFail++
		} else {
			st.LoadTestOK++
		}
	}

	// Пункт 48: статистика Docker-образов.
	digests := map[string]map[string]string{}
	seen := map[string]bool{}
	for _, v := range r.Versions {
		for _, img := range v.DockerImages {
			key := img.FullName()
			if img.Tag == "<none>" || img.Tag == "" {
				continue
			}
			if !seen[key] {
				seen[key] = true
				st.DockerImagesTotal++
			}
			if img.Digest != "" && img.Digest != "<none>" {
				if digests[key] == nil {
					digests[key] = map[string]string{}
				}
				digests[key][v.ServerName] = img.Digest
			}
		}
	}
	for _, servers := range digests {
		if len(servers) < 2 {
			continue
		}
		distinct := map[string]bool{}
		for _, d := range servers {
			distinct[d] = true
		}
		if len(distinct) > 1 {
			st.DockerImagesMismatch++
		}
	}

	return st
}

// ready — готовность PROD к включению TLS 1.3 (нет критических проблем).
func (s *Service) ready(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == SeverityCritical {
			return false
		}
	}
	return true
}

// summary формирует развёрнутое текстовое заключение.
func (s *Service) summary(r *Report) string {
	if r.Stats == nil {
		r.Stats = s.computeStats(r)
	}
	st := r.Stats

	verdict := "ГОТОВО"
	if !r.Ready {
		verdict = "НЕ ГОТОВО"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Вердикт: %s. Готовность PROD к включению TLS 1.3: %s.\n", verdict, verdict)
	fmt.Fprintf(&b, "PROD-серверов проверено: %d (успешно: %d, с ошибками сканирования: %d).\n",
		st.TotalServers, st.ScannedOK, st.ScanErrors)
	fmt.Fprintf(&b, "Архитектура: NAT + nginx (ssl_protocols TLSv1.2 TLSv1.3) наружу. "+
		"Фронтовых nginx: %d, бэкендов за nginx: %d, IIS-бэкендов: %d.\n",
		st.NginxServers, st.BackendServers, st.IISBackends)
	fmt.Fprintf(&b, "TLS 1.3 поддерживают %d серверов (%d портов), только TLS 1.2: %d серверов, "+
		"только HTTP: %d серверов.\n", st.TLS13Servers, st.TLS13Ports, st.TLS12Only, st.HTTPOnly)
	fmt.Fprintf(&b, "Всего портов проверено: %d (TLS 1.3: %d, TLS 1.2: %d, HTTP: %d, слабые cipher: %d).\n",
		st.TotalPorts, st.TLS13Ports, st.TLS12Ports, st.HTTTPorts, st.WeakCipherPrt)
	fmt.Fprintf(&b, "Проблем: критических %d, с обходными путями %d, рекомендаций %d.\n",
		st.CriticalCnt, st.WorkaroundCnt, st.RecommendCnt)
	if st.LoadTestTotal > 0 {
		fmt.Fprintf(&b, "Нагрузочный тест TLS 1.3: %d тестов (успешно: %d, провалено: %d).\n",
			st.LoadTestTotal, st.LoadTestOK, st.LoadTestFail)
	} else {
		b.WriteString("Нагрузочный тест TLS 1.3: не проводился.\n")
	}
	if st.DockerImagesTotal > 0 {
		fmt.Fprintf(&b, "Docker-образов: %d (расхождений digest: %d).\n",
			st.DockerImagesTotal, st.DockerImagesMismatch)
	}
	return b.String()
}
