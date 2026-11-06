// Package monitor — фоновый мониторинг: проверка контейнеров, Graylog, Zeebe,
// метрик серверов и отправка алертов/часовых отчётов в MS Teams.
package monitor

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"paylater-mon/internal/config"
	"paylater-mon/internal/graylog"
	"paylater-mon/internal/incidents"
	"paylater-mon/internal/metrics"
	"paylater-mon/internal/models"
	"paylater-mon/internal/msteams"
	"paylater-mon/internal/servercore"
	"paylater-mon/internal/storage"
	"paylater-mon/internal/zeebe"
)

const (
	checkInterval  = 5 * time.Minute
	reportInterval = time.Hour
	alertDedupTTL  = 10 * time.Minute
)

// Service — фоновый мониторинг с оповещениями в Teams.
type Service struct {
	cfg        *config.Config
	serverCore *servercore.Service
	graylog    *graylog.Service
	zeebe      *zeebe.Service
	teams      *msteams.Service
	incidents  *incidents.Store // JSONL fallback
	db         *storage.DB      // SQLite (пункт 21)
	metrics    *metrics.Collector

	mu sync.Mutex
	// Состояния для детекции переходов.
	containerStates map[string]bool
	graylogProdOk   bool
	graylogTestOk   bool
	zeebeOk         bool
	serverCpuStates map[string]float64
	serverRamStates map[string]float64
	serverAvailable map[string]bool
	lastReport      time.Time
	alertsSent      map[string]time.Time
	startupSent     time.Time
}

// New создаёт сервис мониторинга.
func New(cfg *config.Config, sc *servercore.Service, gl *graylog.Service, zb *zeebe.Service, tm *msteams.Service) *Service {
	return &Service{
		cfg: cfg, serverCore: sc, graylog: gl, zeebe: zb, teams: tm,
		containerStates: map[string]bool{}, graylogProdOk: true, graylogTestOk: true, zeebeOk: true,
		serverCpuStates: map[string]float64{}, serverRamStates: map[string]float64{},
		serverAvailable: map[string]bool{}, alertsSent: map[string]time.Time{},
	}
}

// ApplyConfig обновляет конфигурацию на лету (без перезапуска).
func (s *Service) ApplyConfig(cfg *config.Config) {
	s.cfg = cfg
}

// WithIncidents подключает хранилище инцидентов (пункт 4).
func (s *Service) WithIncidents(store *incidents.Store) *Service {
	s.incidents = store
	return s
}

// WithDB подключает SQLite-хранилище (пункт 21).
func (s *Service) WithDB(db *storage.DB) *Service {
	s.db = db
	return s
}

// WithMetrics подключает коллектор метрик (пункт 15).
func (s *Service) WithMetrics(mc *metrics.Collector) *Service {
	s.metrics = mc
	return s
}

// Run запускает цикл мониторинга (блокирующий, для goroutine).
func (s *Service) Run(ctx context.Context) {
	log.Println("monitor: запуск (проверка каждые 5 мин, отчёт каждый час)")
	s.sendStartup(ctx)
	time.Sleep(30 * time.Second)

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	// Первая проверка сразу.
	s.cycle(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cycle(ctx)
		}
	}
}

func (s *Service) cycle(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("monitor: panic в цикле: %v", r)
		}
	}()
	s.cleanupAlerts()
	now := time.Now()
	needReport := now.Sub(s.lastReport) >= reportInterval

	s.checkContainers(ctx)
	s.checkGraylog(ctx)
	s.checkZeebe(ctx)
	s.checkServerMetrics(ctx)

	if s.metrics != nil {
		s.metrics.IncMonitorCycle()
	}
	if needReport {
		s.sendHourlyReport(ctx)
		s.lastReport = now
	}
}

func (s *Service) sendStartup(ctx context.Context) {
	if !s.startupSent.IsZero() && time.Since(s.startupSent) < 24*time.Hour {
		return
	}
	if s.cfg.MSTeams.WebhookURL == "" {
		return
	}
	msg := fmt.Sprintf("Время запуска: %s\nИнтервал проверок: 5 мин\nИнтервал отчётов: 1 ч", tashkentNow())
	if ok, _ := s.teams.SendMessage("✅ Фоновый мониторинг запущен", msg, msteams.ColorGood); ok {
		s.startupSent = time.Now()
	}
}

// ── 5-минутные проверки ──

func (s *Service) checkContainers(ctx context.Context) {
	defer recoverLog("checkContainers")
	if !s.serverCore.IsMonitoringEnabled(ctx) {
		return
	}
	hosts, _ := s.serverCore.GetServers(ctx)
	for _, host := range hosts {
		containers, err := s.serverCore.GetContainers(ctx, host.Name)
		if err != nil {
			continue
		}
		for _, c := range containers {
			key := host.Name + ":" + c.Name
			wasRunning := true
			if v, ok := s.containerStates[key]; ok {
				wasRunning = v
			}
			if !c.Running && wasRunning {
				if s.alertSent("container_down:" + key) {
					continue
				}
				msg := fmt.Sprintf("Хост: %s\nКонтейнер: %s\nОписание: %s\nВремя: %s", host.Name, c.Name, c.Image, tashkentNow())
				s.teams.SendMessage("🔴 Контейнер упал", msg, msteams.ColorAttention)
				s.recordAlert("container_down:" + key)
				s.recordIncident("container_down", host.Name, c.Name+" ("+c.Image+")", "critical")
				s.containerStates[key] = false
			} else if c.Running && !wasRunning {
				if s.alertSent("container_recovered:" + key) {
					continue
				}
				msg := fmt.Sprintf("Хост: %s\nКонтейнер: %s\nВремя: %s", host.Name, c.Name, tashkentNow())
				s.teams.SendMessage("🟢 Контейнер восстановлен", msg, msteams.ColorGood)
				s.recordAlert("container_recovered:" + key)
				s.recordIncident("container_recovered", host.Name, c.Name, "info")
				s.containerStates[key] = true
			}
		}
	}
}

func (s *Service) checkGraylog(ctx context.Context) {
	defer recoverLog("checkGraylog")
	for _, env := range []string{"prod", "test"} {
		nodes, err := s.graylog.GetClusterNodes(ctx, env)
		if err != nil {
			continue
		}
		allRunning := len(nodes) > 0
		for _, n := range nodes {
			if n.Lifecycle != "" && !strings.EqualFold(n.Lifecycle, "running") {
				allRunning = false
				break
			}
		}
		var prevState *bool
		if env == "prod" {
			prevState = &s.graylogProdOk
		} else {
			prevState = &s.graylogTestOk
		}
		label := strings.ToUpper(env)
		if !allRunning && *prevState {
			if !s.alertSent("graylog_down:" + env) {
				msg := fmt.Sprintf("Окружение: Graylog %s\nВремя: %s", label, tashkentNow())
				s.teams.SendMessage("🔴 Graylog: неисправность кластера", msg, msteams.ColorAttention)
				s.recordAlert("graylog_down:" + env)
			}
		} else if allRunning && !*prevState {
			if !s.alertSent("graylog_recovered:" + env) {
				msg := fmt.Sprintf("Окружение: Graylog %s\nНод: %d\nВремя: %s", label, len(nodes), tashkentNow())
				s.teams.SendMessage("🟢 Graylog: кластер восстановлен", msg, msteams.ColorGood)
				s.recordAlert("graylog_recovered:" + env)
			}
		}
		*prevState = allRunning
	}
}

func (s *Service) checkZeebe(ctx context.Context) {
	defer recoverLog("checkZeebe")
	metrics, err := s.zeebe.GetMetrics(ctx)
	if err != nil {
		return
	}
	connected := metrics.IsConnected
	if !connected && s.zeebeOk {
		if !s.alertSent("zeebe_disconnected") {
			msg := fmt.Sprintf("Ошибка: %s\nВремя: %s", metrics.ErrorMessage, tashkentNow())
			s.teams.SendMessage("🔴 Zeebe (Camunda): нет подключения", msg, msteams.ColorAttention)
			s.recordAlert("zeebe_disconnected")
		}
	} else if connected && !s.zeebeOk {
		if !s.alertSent("zeebe_reconnected") {
			s.teams.SendMessage("🟢 Zeebe (Camunda): подключение восстановлено", "Время: "+tashkentNow(), msteams.ColorGood)
			s.recordAlert("zeebe_reconnected")
		}
	}
	s.zeebeOk = connected
}

func (s *Service) checkServerMetrics(ctx context.Context) {
	defer recoverLog("checkServerMetrics")
	if !s.serverCore.IsMonitoringEnabled(ctx) {
		return
	}
	hosts, _ := s.serverCore.GetServers(ctx)
	for _, host := range hosts {
		wasAvail := true
		if v, ok := s.serverAvailable[host.Name]; ok {
			wasAvail = v
		}
		avail := host.IsAvailable()
		if !avail && wasAvail {
			if !s.alertSent("server_down:" + host.Name) {
				msg := fmt.Sprintf("Хост: %s\nIP: %s\nСреда: %s\nВремя: %s\n\nСервер недоступен!", host.Name, host.IpAddress, envFromName(host.Name), tashkentNow())
				s.teams.SendMessage("🔴 Сервер недоступен", msg, msteams.ColorAttention)
				s.recordAlert("server_down:" + host.Name)
			}
		} else if avail && !wasAvail {
			if !s.alertSent("server_recovered:" + host.Name) {
				msg := fmt.Sprintf("Хост: %s\nIP: %s\nВремя: %s\n\nСервер восстановлен.", host.Name, host.IpAddress, tashkentNow())
				s.teams.SendMessage("🟢 Сервер восстановлен", msg, msteams.ColorGood)
				s.recordAlert("server_recovered:" + host.Name)
			}
		}
		s.serverAvailable[host.Name] = avail
		if !avail {
			continue
		}
		metrics, err := s.serverCore.GetServerMetrics(ctx, host.Name)
		if err != nil || metrics == nil {
			continue
		}
		// CPU
		if metrics.CpuUsagePercent > 0 {
			prevCpu := s.serverCpuStates[host.Name]
			s.serverCpuStates[host.Name] = metrics.CpuUsagePercent
			if metrics.CpuUsagePercent > 90 && prevCpu <= 90 {
				if !s.alertSent("cpu_high:" + host.Name) {
					msg := fmt.Sprintf("Хост: %s\nCPU: %.1f%%\nRAM: %.1f%%\nDisk: %.1f%%\nВремя: %s", host.Name, metrics.CpuUsagePercent, metrics.MemoryUsagePercent, metrics.DiskUsagePercent, tashkentNow())
					severity := "⚠️ Высокая загрузка CPU"
					if metrics.CpuUsagePercent > 98 {
						severity = "🔴 Критическая загрузка CPU"
					}
					s.teams.SendMessage(severity, msg, msteams.ColorAttention)
					s.recordAlert("cpu_high:" + host.Name)
				}
			} else if metrics.CpuUsagePercent <= 80 && prevCpu > 90 {
				if !s.alertSent("cpu_normal:" + host.Name) {
					msg := fmt.Sprintf("Хост: %s\nCPU: %.1f%% (было > 90%%)\nВремя: %s", host.Name, metrics.CpuUsagePercent, tashkentNow())
					s.teams.SendMessage("🟢 CPU в норме", msg, msteams.ColorGood)
					s.recordAlert("cpu_normal:" + host.Name)
				}
			}
		}
		// RAM
		if metrics.MemoryUsagePercent > 0 {
			prevRam := s.serverRamStates[host.Name]
			s.serverRamStates[host.Name] = metrics.MemoryUsagePercent
			if metrics.MemoryUsagePercent > 90 && prevRam <= 90 {
				if !s.alertSent("ram_high:" + host.Name) {
					msg := fmt.Sprintf("Хост: %s\nCPU: %.1f%%\nRAM: %.1f%% (%.1f / %.1f GB)\nDisk: %.1f%%\nВремя: %s", host.Name, metrics.CpuUsagePercent, metrics.MemoryUsagePercent, metrics.MemoryUsedGB, metrics.MemoryTotalGB, metrics.DiskUsagePercent, tashkentNow())
					s.teams.SendMessage("🔴 Критическая загрузка RAM", msg, msteams.ColorAttention)
					s.recordAlert("ram_high:" + host.Name)
				}
			} else if metrics.MemoryUsagePercent <= 80 && prevRam > 90 {
				if !s.alertSent("ram_normal:" + host.Name) {
					msg := fmt.Sprintf("Хост: %s\nRAM: %.1f%% (было > 90%%)\nВремя: %s", host.Name, metrics.MemoryUsagePercent, tashkentNow())
					s.teams.SendMessage("🟢 RAM в норме", msg, msteams.ColorGood)
					s.recordAlert("ram_normal:" + host.Name)
				}
			}
		}
		// Disk
		if metrics.DiskUsagePercent > 90 {
			if !s.alertSent("disk_high:" + host.Name) {
				msg := fmt.Sprintf("Хост: %s\nIP: %s\nDisk: %.1f%% (%.1f / %.1f GB)\nВремя: %s", host.Name, host.IpAddress, metrics.DiskUsagePercent, metrics.DiskUsedGB, metrics.DiskTotalGB, tashkentNow())
				s.teams.SendMessage("🔴 Критическая загрузка Disk", msg, msteams.ColorAttention)
				s.recordAlert("disk_high:" + host.Name)
			}
		}
		// Сохраняем историю метрик в SQLite (пункт 21).
		if s.db != nil {
			_ = s.db.InsertMetricPoint(storage.MetricPoint{
				Server: host.Name,
				CPU:    metrics.CpuUsagePercent,
				RAM:    metrics.MemoryUsagePercent,
				Disk:   metrics.DiskUsagePercent,
			})
		}
	}
}

// ── Часовой отчёт ──

func (s *Service) sendHourlyReport(ctx context.Context) {
	if s.cfg.MSTeams.WebhookURL == "" {
		return
	}
	if s.alertSent("hourly_report") {
		return
	}
	var sections []string

	// 1. Контейнеры
	sections = append(sections, s.reportContainers(ctx))

	// 2. ServerCore
	sections = append(sections, s.reportServerCore(ctx))

	// 3. Graylog
	sections = append(sections, s.reportGraylog(ctx))

	// 4. Zeebe
	sections = append(sections, s.reportZeebe(ctx))

	report := strings.Join(filterEmpty(sections), "\n\n---\n\n")
	title := "📊 Часовой отчёт мониторинга — " + tashkentNow()
	if ok, _ := s.teams.SendMessage(title, report, msteams.ColorAccent); ok {
		s.recordAlert("hourly_report")
	}
}

func (s *Service) reportContainers(ctx context.Context) string {
	if !s.serverCore.IsMonitoringEnabled(ctx) {
		return "🐳 Контейнеры Docker\n⚠️ ServerCore API не подключен."
	}
	hosts, _ := s.serverCore.GetServers(ctx)
	var down []string
	total, hostsChecked := 0, 0
	for _, host := range hosts {
		if !host.IsAvailable() {
			continue
		}
		containers, err := s.serverCore.GetContainers(ctx, host.Name)
		if err != nil || len(containers) == 0 {
			continue
		}
		hostsChecked++
		for _, c := range containers {
			total++
			if !c.Running {
				down = append(down, fmt.Sprintf("  • [%s] %s — %s", host.Name, c.Name, c.Status))
			}
		}
	}
	if len(down) == 0 {
		return fmt.Sprintf("🐳 Контейнеры Docker\nНа %s контейнеры Docker в порядке. (проверено: %d, хостов: %d)", tashkentNow(), total, hostsChecked)
	}
	return fmt.Sprintf("🐳 Контейнеры Docker\n⚠️ Упавших контейнеров: %d из %d\n%s", len(down), total, strings.Join(down, "\n"))
}

func (s *Service) reportServerCore(ctx context.Context) string {
	if !s.serverCore.IsMonitoringEnabled(ctx) {
		return "🖥 Мониторинг серверов\n⚠️ Мониторинг серверов не подключен."
	}
	servers, _ := s.serverCore.GetServers(ctx)
	avail := 0
	for _, sv := range servers {
		if sv.IsAvailable() {
			avail++
		}
	}
	return fmt.Sprintf("🖥 Мониторинг серверов\n✅ Подключено. Серверов: %d (доступно: %d).", len(servers), avail)
}

func (s *Service) reportGraylog(ctx context.Context) string {
	var lines []string
	for _, env := range []string{"prod", "test"} {
		label := strings.ToUpper(env)
		nodes, err := s.graylog.GetClusterNodes(ctx, env)
		if err != nil || len(nodes) == 0 {
			lines = append(lines, "  • "+label+": ноды не возвращены API")
			continue
		}
		down := 0
		masters := 0
		for _, n := range nodes {
			if n.Lifecycle != "" && !strings.EqualFold(n.Lifecycle, "running") {
				down++
			}
			if n.IsMaster {
				masters++
			}
		}
		if down == 0 {
			lines = append(lines, fmt.Sprintf("  • %s: ОК (нод: %d, master: %d)", label, len(nodes), masters))
		} else {
			lines = append(lines, fmt.Sprintf("  • %s: ⚠️ %d из %d нод не работают", label, down, len(nodes)))
		}
	}
	return "📓 Graylog\n" + strings.Join(lines, "\n")
}

func (s *Service) reportZeebe(ctx context.Context) string {
	metrics, err := s.zeebe.GetMetrics(ctx)
	if err != nil || !metrics.IsConnected {
		errMsg := "неизвестно"
		if metrics.ErrorMessage != "" {
			errMsg = metrics.ErrorMessage
		}
		return "⚙️ Zeebe (Camunda)\n🔴 Нет подключения: " + errMsg
	}
	active := s.zeebe.GetActiveProcessInstancesCount(ctx)
	var recordsProcessed int64
	for _, p := range metrics.Partitions {
		recordsProcessed += p.RecordsProcessed
	}
	incidents := s.zeebe.GetProcessesWithIncidents(ctx, 50)
	stuck := s.zeebe.GetStuckProcesses(ctx, 50)
	totalMetrics := len(metrics.Counters) + len(metrics.Gauges)
	return fmt.Sprintf("⚙️ Zeebe (Camunda)\n  • Статус подключения: ✅ Подключено\n  • Активные инстансы: %d\n  • Обработано записей: %d\n  • Ошибок (инцидентов): %d\n  • Зависших процессов: %d\n  • Всего метрик: %d\n  • Последнее обновление: %s",
		active, recordsProcessed, len(incidents), len(stuck), totalMetrics, tashkentNow())
}

// ── Вспомогательные ──

func (s *Service) alertSent(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.alertsSent[key]
	return ok && time.Since(t) < alertDedupTTL
}

func (s *Service) recordAlert(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertsSent[key] = time.Now()
	if s.metrics != nil {
		s.metrics.IncAlert()
	}
}

// recordIncident сохраняет инцидент в хранилище (пункт 4/21).
func (s *Service) recordIncident(incType, host, detail, status string) {
	if s.db != nil {
		_ = s.db.InsertIncident(storage.IncidentEntry{
			Type:      incType,
			Host:      host,
			Detail:    detail,
			Status:    status,
			Timestamp: time.Now(),
		})
		return
	}
	if s.incidents == nil {
		return
	}
	s.incidents.Record(models.Incident{
		Type:      incType,
		Host:      host,
		Detail:    detail,
		Status:    status,
		Timestamp: time.Now(),
	})
}

func (s *Service) cleanupAlerts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.alertsSent {
		if time.Since(t) > alertDedupTTL*3 {
			delete(s.alertsSent, k)
		}
	}
}

func envFromName(name string) string {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "prod"):
		return "prod"
	case strings.Contains(l, "test"):
		return "test"
	case strings.Contains(l, "adm"):
		return "adm"
	}
	return "other"
}

func tashkentNow() string {
	tz, err := time.LoadLocation("Asia/Tashkent")
	if err != nil {
		return time.Now().UTC().Format("2006-01-02 15:04:05")
	}
	return time.Now().In(tz).Format("2006-01-02 15:04:05")
}

func filterEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func recoverLog(name string) {
	if r := recover(); r != nil {
		log.Printf("monitor: %s panic: %v", name, r)
	}
}

var _ = models.ServerHost{}
