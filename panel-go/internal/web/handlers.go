package web

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// buildRouter регистрирует все маршруты.
func (a *App) buildRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// Статика.
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Страницы.
	mux.HandleFunc("/", a.pageHome)
	mux.HandleFunc("/servercore", a.pageServerCore)
	mux.HandleFunc("/containers", a.pageContainers)
	mux.HandleFunc("/containers/networks", a.pageContainerNetworks)
	mux.HandleFunc("/graylog", a.pageGraylog)
	mux.HandleFunc("/graylog/", a.pageGraylogEnv)
	mux.HandleFunc("/zeebe", a.pageZeebe)
	mux.HandleFunc("/zeebe-processes", a.pageZeebeProcesses)
	mux.HandleFunc("/camunda/", a.pageCamundaEnv)
	mux.HandleFunc("/vault", a.pageVault)
	mux.HandleFunc("/ai-diagnostics", a.pageAiDiagnostics)
	mux.HandleFunc("/ephemeral-access", a.pageEphemeral)
	mux.HandleFunc("/vm-manager", a.pageVmManager)
	mux.HandleFunc("/script-builder", a.pageScriptBuilder)
	mux.HandleFunc("/help", a.pageHelp)
	mux.HandleFunc("/system", a.pageSystem)
	mux.HandleFunc("/tls", a.pageTLS)
	mux.HandleFunc("/staging-tls", a.pageStagingTLS)
	mux.HandleFunc("/logs", a.pageLogs)

	// Асинхронные TLS/Staging-TLS сканирования (пункт: страницы рендерятся
	// мгновенно, проверка идёт в фоне с прогрессом и часами в браузере).
	mux.HandleFunc("/api/tls/status", a.apiTLSStatus)
	mux.HandleFunc("/api/tls/scan", a.apiTLSScan)
	mux.HandleFunc("/api/tls/stop", a.apiTLSStop)
	mux.HandleFunc("/api/tls/data", a.apiTLSData)
	mux.HandleFunc("/api/staging-tls/status", a.apiStagingStatus)
	mux.HandleFunc("/api/staging-tls/scan", a.apiStagingScan)
	mux.HandleFunc("/api/staging-tls/stop", a.apiStagingStop)
	mux.HandleFunc("/api/staging-tls/data", a.apiStagingData)

	// Auth (пункт 20).
	mux.HandleFunc("/login", a.pageLogin)
	mux.HandleFunc("/logout", a.handleLogout)
	mux.HandleFunc("/change-password", a.pageChangePassword)
	mux.HandleFunc("/users", a.pageUsers)

	// WebSocket/SSE (пункт 3).
	mux.HandleFunc("/ws", a.handleWS)

	// API-действия (POST).
	mux.HandleFunc("/api/container/action", a.apiContainerAction)
	mux.HandleFunc("/api/vm/action", a.apiVmAction)
	mux.HandleFunc("/api/vault/write", a.apiVaultWrite)
	mux.HandleFunc("/api/vault/delete", a.apiVaultDelete)
	mux.HandleFunc("/api/ai/diagnose", a.apiAiDiagnose)
	mux.HandleFunc("/api/ai/apply", a.apiAiApply)
	mux.HandleFunc("/api/ephemeral/create", a.apiEphemeralCreate)
	mux.HandleFunc("/api/ephemeral/revoke", a.apiEphemeralRevoke)

	// User management API (пункт 20).
	mux.HandleFunc("/api/users/create", a.apiUserCreate)
	mux.HandleFunc("/api/users/delete", a.apiUserDelete)
	mux.HandleFunc("/api/users/reset-password", a.apiUserResetPassword)
	mux.HandleFunc("/api/users/role", a.apiUserRole)

	// VM creation API (пункт 61: полноценная форма создания ВМ).
	mux.HandleFunc("/api/vm/create", a.apiVmCreate)

	// Staging clone API (пункт 45: автосоздание клона PROD).
	mux.HandleFunc("/api/staging-tls/clone", a.apiStagingClone)

	// Config & secrets API (пункты 20, 22).
	mux.HandleFunc("/api/config/update", a.apiConfigUpdate)
	mux.HandleFunc("/api/secrets/migrate", a.apiMigrateSecrets)

	// Decommissioned servers management (add/remove without restart).
	mux.HandleFunc("/api/servercore/decommissioned", a.apiDecommissionedServers)

	// VM name auto-generation (пункт 61: форма создания ВМ).
	mux.HandleFunc("/api/servercore/vm-name", a.apiVmName)

	// Audit & incidents (GET).
	mux.HandleFunc("/api/audit/recent", a.apiAuditRecent)
	mux.HandleFunc("/api/audit/search", a.apiAuditSearch)
	mux.HandleFunc("/api/incidents/recent", a.apiIncidentsRecent)
	mux.HandleFunc("/api/metrics/history", a.apiMetricsHistory)
	mux.HandleFunc("/api/logs/recent", a.apiLogsRecent)

	// Health-check (пункт 14: проверка всех зависимостей).
	mux.HandleFunc("/health", a.handleHealth)

	// Prometheus metrics (пункт 15).
	mux.HandleFunc("/metrics", a.handleMetrics)

	return mux
}

// render отрисовывает шаблон с общим контекстом.
func (a *App) render(w http.ResponseWriter, name string, data map[string]interface{}) {
	if data == nil {
		data = map[string]interface{}{}
	}
	data["ActivePage"] = name
	t, ok := a.templates[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *App) pageHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	servers := a.serverCore.GetServersWithMetrics(ctx)
	problems := a.detector.Detect(ctx)
	monitoringEnabled := a.serverCore.IsMonitoringEnabled(ctx)

	// Сводка контейнеров.
	totalContainers := 0
	downContainers := 0
	for _, sv := range servers {
		totalContainers += sv.TotalContainers
		downContainers += sv.TotalContainers - sv.RunningContainers
	}

	a.render(w, "home", map[string]interface{}{
		"Title":             "Dashboard",
		"Servers":           servers,
		"MonitoringEnabled": monitoringEnabled,
		"Problems":          problems,
		"TotalContainers":   totalContainers,
		"DownContainers":    downContainers,
		"ServerCount":       len(servers),
	})
}

func (a *App) pageServerCore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groups := a.serverCore.GetServersGrouped(ctx)
	enabled := a.serverCore.IsMonitoringEnabled(ctx)
	errMsg := ""
	if enabled && len(groups) == 0 {
		errMsg = "Серверы не получены из ServerCore API. Проверьте IAM-учётные данные и доступность cloud.api.servercore.com."
	}
	a.render(w, "servercore", map[string]interface{}{
		"Title": "Серверы (ServerCore)", "Groups": groups,
		"MonitoringEnabled": enabled, "ServerError": errMsg,
	})
}

func (a *App) pageContainers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers, _ := a.serverCore.GetServers(ctx)
	type hostContainers struct {
		Server     string
		IP         string
		Containers interface{}
		Error      string
	}
	var result []hostContainers
	for _, sv := range servers {
		if !sv.IsAvailable() {
			continue
		}
		containers, err := a.serverCore.GetContainers(ctx, sv.Name)
		if err != nil {
			result = append(result, hostContainers{Server: sv.Name, IP: sv.IpAddress, Error: err.Error()})
			continue
		}
		result = append(result, hostContainers{Server: sv.Name, IP: sv.IpAddress, Containers: containers})
	}
	a.render(w, "containers", map[string]interface{}{
		"Title": "Контейнеры Docker", "Hosts": result,
	})
}

func (a *App) pageContainerNetworks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers, _ := a.serverCore.GetServers(ctx)
	type hostNetworks struct {
		Server   string
		Networks interface{}
	}
	var result []hostNetworks
	for _, sv := range servers {
		if !sv.IsAvailable() {
			continue
		}
		networks, err := a.serverCore.GetContainerNetworks(ctx, sv.Name)
		if err != nil {
			continue
		}
		result = append(result, hostNetworks{Server: sv.Name, Networks: networks})
	}
	a.render(w, "networks", map[string]interface{}{
		"Title": "Docker Networks", "Hosts": result,
	})
}

func (a *App) pageGraylog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	type envStatus struct {
		Env   string
		Label string
		Nodes interface{}
		Ok    bool
		Error string
	}
	var statuses []envStatus
	for _, env := range []string{"prod", "test"} {
		nodes, err := a.graylog.GetClusterNodes(ctx, env)
		ok := err == nil && len(nodes) > 0
		msg := ""
		if err != nil {
			msg = err.Error()
		} else if len(nodes) == 0 {
			msg = "Ноды не возвращены API (проверьте доступность и учётные данные)."
		}
		for _, n := range nodes {
			if n.Lifecycle != "" && !strings.EqualFold(n.Lifecycle, "running") {
				ok = false
			}
		}
		statuses = append(statuses, envStatus{Env: env, Label: strings.ToUpper(env), Nodes: nodes, Ok: ok, Error: msg})
	}
	a.render(w, "graylog", map[string]interface{}{"Title": "Graylog", "Statuses": statuses})
}

func (a *App) pageGraylogEnv(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	env := "prod"
	if len(parts) >= 2 {
		env = parts[1]
	}
	if env != "prod" && env != "test" {
		env = "prod"
	}
	ctx := r.Context()
	nodes, nodeErr := a.graylog.GetClusterNodes(ctx, env)
	streams, streamErr := a.graylog.GetStreams(ctx, env)
	nodeErrMsg := ""
	if nodeErr != nil {
		nodeErrMsg = nodeErr.Error()
	} else if len(nodes) == 0 {
		nodeErrMsg = "Ноды не возвращены API (проверьте доступность и учётные данные)."
	}
	streamErrMsg := ""
	if streamErr != nil {
		streamErrMsg = streamErr.Error()
	}
	query := r.URL.Query().Get("q")
	rangeSec := 3600
	if v := r.URL.Query().Get("range"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			rangeSec = n
		}
	}
	var search interface{}
	if query != "" {
		res, err := a.graylog.SearchLogs(ctx, env, query, rangeSec, 100, "")
		if err == nil {
			search = res
		}
	}
	a.render(w, "graylog_env", map[string]interface{}{
		"Title": "Graylog " + strings.ToUpper(env), "Env": env, "Nodes": nodes, "Streams": streams,
		"NodeError": nodeErrMsg, "StreamError": streamErrMsg,
		"Query": query, "Range": rangeSec, "Search": search,
	})
}

func (a *App) pageZeebe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	metrics, _ := a.zeebe.GetMetrics(ctx)
	active := a.zeebe.GetActiveProcessInstancesCount(ctx)
	env := a.zeebe.GetTargetEnv()
	if env == "" {
		env = "prod"
	}
	a.render(w, "zeebe", map[string]interface{}{
		"Title":           "Zeebe (Camunda)",
		"Metrics":         metrics,
		"ActiveInstances": active,
		"Env":             env,
		"AvailableEnvs":   a.zeebe.AvailableEnvs(),
		"EnvURL":          a.zeebe.EnvURL(env),
	})
}

func (a *App) pageZeebeProcesses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	active := a.zeebe.GetActiveProcesses(ctx, 50)
	incidents := a.zeebe.GetProcessesWithIncidents(ctx, 50)
	stuck := a.zeebe.GetStuckProcesses(ctx, 50)
	a.render(w, "zeebe_processes", map[string]interface{}{
		"Title": "Процессы Zeebe", "Active": active, "Incidents": incidents, "Stuck": stuck,
	})
}

func (a *App) pageCamundaEnv(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	env := "prod"
	if len(parts) >= 2 {
		env = parts[1]
	}
	sub := "zeebe"
	if len(parts) >= 3 {
		sub = parts[2]
	}
	a.zeebe.SetTargetEnv(env)
	switch sub {
	case "zeebe":
		a.pageZeebe(w, r)
	case "processes":
		a.pageZeebeProcesses(w, r)
	case "system":
		a.render(w, "system", map[string]interface{}{"Title": "System " + strings.ToUpper(env), "Env": env})
	default:
		a.pageZeebe(w, r)
	}
}

func (a *App) pageVault(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connected, msg, version := a.vault.CheckConnection(ctx)
	catalog := a.vault.GetCatalog(ctx)
	a.render(w, "vault", map[string]interface{}{
		"Title": "Vault", "Connected": connected, "Message": msg, "Version": version, "Catalog": catalog,
	})
}

func (a *App) pageAiDiagnostics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	problems := a.detector.Detect(ctx)
	servers, _ := a.serverCore.GetServers(ctx)
	enabled := a.ai.Enabled()
	a.render(w, "ai_diagnostics", map[string]interface{}{
		"Title": "AI-диагностика", "Problems": problems, "Servers": servers, "AiEnabled": enabled,
		"AutoResolve": a.ai.AutoResolve(), "Providers": a.ai.Providers(),
	})
}

func (a *App) pageEphemeral(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers, _ := a.serverCore.GetServers(ctx)
	activeKeys := a.vault.GetActiveKeys()
	a.render(w, "ephemeral", map[string]interface{}{
		"Title": "Эфемерный доступ", "Servers": servers, "ActiveKeys": activeKeys,
	})
}

func (a *App) pageVmManager(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	templates, _ := a.serverCore.GetTemplates(ctx)
	// Пункт 61: полноценные образы ОС из Glance (с именем ОС, а не GUID).
	glanceImages, _ := a.serverCore.GetGlanceImages(ctx)
	if len(glanceImages) == 0 {
		glanceImages = templates
	}
	presets, _ := a.serverCore.GetPresets(ctx)
	networks, _ := a.serverCore.GetNetworks(ctx)
	secGroups, _ := a.serverCore.GetSecurityGroups(ctx)
	keyPairs, _ := a.serverCore.GetKeyPairs(ctx)
	servers, _ := a.serverCore.GetServers(ctx)
	a.render(w, "vm_manager", map[string]interface{}{
		"Title": "Управление ВМ", "Templates": templates, "GlanceImages": glanceImages,
		"Presets": presets, "Servers": servers, "Networks": networks,
		"SecurityGroups": secGroups, "KeyPairs": keyPairs,
	})
}

func (a *App) pageHelp(w http.ResponseWriter, r *http.Request) {
	a.render(w, "help", map[string]interface{}{"Title": "Помощь"})
}

// pageScriptBuilder — визуальный конструктор скриптов (пункт 60 IMPROVEMENTS.md).
// Страница позволяет выбрать модули/функции для bash/powershell/ansible/terraform
// и сформировать готовый скрипт. Генерация происходит на клиенте в JS.
func (a *App) pageScriptBuilder(w http.ResponseWriter, r *http.Request) {
	a.render(w, "script_builder", map[string]interface{}{"Title": "Конструктор скриптов"})
}

func (a *App) pageSystem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := a.currentUser(r)
	canEdit := user != nil && (string(user.Role) == "superadmin" || string(user.Role) == "admin")
	if a.cfg.Auth.Enabled && a.userStore == nil && user == nil {
		// basic-auth fallback — allow if auth enabled but no user store
		canEdit = true
	}

	// Конфигурация для графического редактора (JSON).
	configJSON := template.JS("{}")
	if canEdit {
		if b, err := json.Marshal(a.cfg); err == nil {
			configJSON = template.JS(b)
		}
	}

	// Статусы сервисов.
	vaultOk, _, _ := a.vault.CheckConnection(ctx)
	teamsOk := a.cfg.MSTeams.WebhookURL != ""

	a.render(w, "system", map[string]interface{}{
		"Title":             "Система",
		"MonitoringEnabled": a.serverCore.IsMonitoringEnabled(ctx),
		"VaultOk":           vaultOk,
		"TeamsOk":           teamsOk,
		"AiEnabled":         a.ai.Enabled(),
		"CanEdit":           canEdit,
		"ConfigJSON":        configJSON,
	})
}

func (a *App) pageLogs(w http.ResponseWriter, r *http.Request) {
	a.render(w, "logs", map[string]interface{}{"Title": "Логи", "LogPath": a.logPath})
}

// pageTLS — проверка TLS-конфигурации серверов (пункт 29 IMPROVEMENTS.md).
// Страница рендерится МГНОВЕННО: сканирование выполняется асинхронно
// (см. scanjobs.go), браузер опрашивает /api/tls/status и показывает
// часы + прогресс, пока идёт проверка.
func (a *App) pageTLS(w http.ResponseWriter, r *http.Request) {
	a.render(w, "tls", map[string]interface{}{
		"Title": "TLS",
		"Tips":  generalTLSTips(),
	})
}

// pageStagingTLS — раздел «Staging-TLS»: изолированный клон PROD для
// нагрузочного тестирования и проверки готовности к включению TLS 1.3.
// Тоже рендерится мгновенно, проверка идёт в фоне (scanjobs.go).
func (a *App) pageStagingTLS(w http.ResponseWriter, r *http.Request) {
	a.render(w, "staging_tls", map[string]interface{}{
		"Title": "Staging-TLS",
	})
}

// ── API асинхронных TLS/Staging-TLS сканирований ──

func (a *App) apiTLSStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.tlsJob.status())
}

func (a *App) apiTLSScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.startTLSScan())
}

func (a *App) apiTLSStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.stopTLSScan())
}

func (a *App) apiTLSData(w http.ResponseWriter, r *http.Request) {
	a.tlsJob.mu.Lock()
	defer a.tlsJob.mu.Unlock()
	if a.tlsJob.state != "done" {
		writeJSON(w, map[string]interface{}{"error": "scan not finished", "state": a.tlsJob.state})
		return
	}
	writeJSON(w, map[string]interface{}{
		"servers":      a.tlsJob.results,
		"tips":         a.tlsJob.tips,
		"generated_at": a.tlsJob.finishedAt.UTC().Format(time.RFC3339),
	})
}

func (a *App) apiStagingStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.stagingJob.status())
}

func (a *App) apiStagingScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.startStagingScan())
}

func (a *App) apiStagingStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.stopStagingScan())
}

func (a *App) apiStagingData(w http.ResponseWriter, r *http.Request) {
	a.stagingJob.mu.Lock()
	defer a.stagingJob.mu.Unlock()
	if a.stagingJob.state != "done" {
		writeJSON(w, map[string]interface{}{"error": "scan not finished", "state": a.stagingJob.state})
		return
	}
	writeJSON(w, map[string]interface{}{
		"report":       a.stagingJob.report,
		"generated_at": a.stagingJob.finishedAt.UTC().Format(time.RFC3339),
	})
}

// ── Health-check (пункт 14) ──

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	type depStatus struct {
		Name    string `json:"name"`
		Healthy bool   `json:"healthy"`
		Detail  string `json:"detail,omitempty"`
	}
	var deps []depStatus

	// ServerCore
	scOk := a.serverCore.IsMonitoringEnabled(ctx)
	deps = append(deps, depStatus{Name: "servercore", Healthy: scOk})

	// Graylog
	for _, env := range []string{"prod", "test"} {
		nodes, err := a.graylog.GetClusterNodes(ctx, env)
		ok := err == nil && len(nodes) > 0
		deps = append(deps, depStatus{Name: "graylog_" + env, Healthy: ok})
	}

	// Zeebe
	metrics, _ := a.zeebe.GetMetrics(ctx)
	deps = append(deps, depStatus{Name: "zeebe", Healthy: metrics.IsConnected})

	// Vault
	vOk, _, _ := a.vault.CheckConnection(ctx)
	deps = append(deps, depStatus{Name: "vault", Healthy: vOk})

	allHealthy := true
	for _, d := range deps {
		if !d.Healthy {
			allHealthy = false
			break
		}
	}
	status := "Healthy"
	if !allHealthy {
		status = "Degraded"
	}
	writeJSON(w, map[string]interface{}{
		"status":       status,
		"dependencies": deps,
		"uptime":       time.Since(a.metrics.UptimeSeconds).String(),
	})
}

// ── Prometheus metrics (пункт 15) ──

func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(a.metrics.Render()))
}

// ── Audit recent (пункт 7/21) ──

func (a *App) apiAuditRecent(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		writeJSON(w, []interface{}{})
		return
	}
	entries := a.db.RecentAudit(100)
	writeJSON(w, entries)
}

func (a *App) apiAuditSearch(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		writeJSON(w, []interface{}{})
		return
	}
	query := r.URL.Query().Get("q")
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	entries := a.db.SearchAudit(query, limit)
	writeJSON(w, entries)
}

// ── Incidents recent (пункт 4/21) ──

func (a *App) apiIncidentsRecent(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		writeJSON(w, []interface{}{})
		return
	}
	entries := a.db.RecentIncidents(100)
	writeJSON(w, entries)
}

// ── Metrics history (пункт 8/21: графики из SQLite) ──

func (a *App) apiMetricsHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers := a.serverCore.GetServersWithMetrics(ctx)
	type serverMetric struct {
		Name string  `json:"name"`
		CPU  float64 `json:"cpu"`
		RAM  float64 `json:"ram"`
		Disk float64 `json:"disk"`
	}
	var metrics []serverMetric
	for _, s := range servers {
		metrics = append(metrics, serverMetric{
			Name: s.Name, CPU: s.CpuUsagePercent, RAM: s.MemoryUsagePercent, Disk: s.DiskUsagePercent,
		})
	}

	// История из SQLite для графиков (пункт 21).
	type point struct {
		Timestamp string  `json:"timestamp"`
		Server    string  `json:"server"`
		CPU       float64 `json:"cpu"`
		RAM       float64 `json:"ram"`
		Disk      float64 `json:"disk"`
	}
	var history []point
	if a.db != nil {
		for _, s := range servers {
			for _, p := range a.db.MetricHistory(s.Name, 24) {
				history = append(history, point{
					Timestamp: p.Timestamp.Format("15:04"),
					Server:    p.Server,
					CPU:       p.CPU,
					RAM:       p.RAM,
					Disk:      p.Disk,
				})
			}
		}
	}

	writeJSON(w, map[string]interface{}{
		"timestamp": time.Now().Format("15:04:05"),
		"servers":   metrics,
		"history":   history,
	})
}
