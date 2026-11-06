package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"paylater-mon/internal/aidiag"
	"paylater-mon/internal/models"
	"paylater-mon/internal/msteams"
)

// currentUser извлекает имя пользователя из basic-auth или возвращает "anonymous".
func currentUser(r *http.Request) string {
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		return u
	}
	return "anonymous"
}

// apiContainerAction — start/stop/restart контейнера.
func (a *App) apiContainerAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Server    string `json:"server"`
		Container string `json:"container"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	var result interface{}
	var err error
	switch req.Action {
	case "start":
		result, err = a.serverCore.StartContainer(ctx, req.Server, req.Container)
	case "stop":
		result, err = a.serverCore.StopContainer(ctx, req.Server, req.Container)
	case "restart":
		result, err = a.serverCore.RestartContainer(ctx, req.Server, req.Container)
	default:
		writeJSONError(w, http.StatusBadRequest, "unknown action")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Audit + metrics (пункты 7, 15).
	success := true
	detail := ""
	if vmRes, ok := result.(models.VmOperationResult); ok {
		success = vmRes.Success
		detail = vmRes.Message
	}
	a.auditLog("container_"+req.Action, currentUser(r), req.Server+"/"+req.Container, detail, success, r.RemoteAddr)
	a.metrics.IncOperation("container_"+req.Action, success)
	writeJSON(w, result)
}

// apiVmAction — delete/start/stop/restart ВМ.
func (a *App) apiVmAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		VmID   string `json:"vm_id"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	var result interface{}
	var err error
	switch req.Action {
	case "delete":
		result, err = a.serverCore.DeleteVM(ctx, req.VmID)
	case "start":
		result, err = a.serverCore.StartVM(ctx, req.VmID)
	case "stop":
		result, err = a.serverCore.StopVM(ctx, req.VmID)
	case "restart":
		result, err = a.serverCore.RestartVM(ctx, req.VmID)
	default:
		writeJSONError(w, http.StatusBadRequest, "unknown action")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	success := true
	detail := ""
	if vmRes, ok := result.(models.VmOperationResult); ok {
		success = vmRes.Success
		detail = vmRes.Message
	}
	a.auditLog("vm_"+req.Action, currentUser(r), req.VmID, detail, success, r.RemoteAddr)
	a.metrics.IncOperation("vm_"+req.Action, success)
	writeJSON(w, result)
}

// apiVmCreate — создание новой ВМ (пункт 61: полноценная форма).
func (a *App) apiVmCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req models.VmCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	result, err := a.serverCore.CreateVM(ctx, req)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("vm_create", currentUser(r), req.Name, result.Message, result.Success, r.RemoteAddr)
	a.metrics.IncOperation("vm_create", result.Success)
	writeJSON(w, result)
}

// apiVmName — автогенерация имени ВМ по шаблону uz-{env}-{app}-{number}.
func (a *App) apiVmName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Env string `json:"env"`
		App string `json:"app"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Env == "" {
		req.Env = "test"
	}
	if req.App == "" {
		req.App = "app"
	}
	ctx := r.Context()
	name, err := a.serverCore.GenerateVMName(ctx, req.Env, req.App)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]string{"name": name})
}

// apiStagingClone — автосоздание клона PROD-сервера (пункт 45 IMPROVEMENTS.md).
// Принимает server_name (PROD-сервер для клонирования) и clone_name (имя клона).
// Создаёт ВМ с тем же образом/flavor, копирует nginx-конфиг и docker-compose
// через SSH, возвращает результат.
func (a *App) apiStagingClone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		ServerName string `json:"server_name"`
		CloneName  string `json:"clone_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	result, err := a.serverCore.CloneServer(ctx, req.ServerName, req.CloneName)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("staging_clone", currentUser(r), req.ServerName+"→"+req.CloneName, result.Message, result.Success, r.RemoteAddr)
	a.metrics.IncOperation("staging_clone", result.Success)
	writeJSON(w, result)
}

// apiVaultWrite — запись секрета в Vault.
func (a *App) apiVaultWrite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path  string                 `json:"path"`
		Data  map[string]interface{} `json:"data"`
		Mount string                 `json:"mount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	ok, err := a.vault.WriteSecret(ctx, req.Path, req.Data, req.Mount)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.vault.InvalidateCache()
	a.auditLog("vault_write", currentUser(r), req.Path, "", ok, r.RemoteAddr)
	a.metrics.IncOperation("vault_write", ok)
	writeJSON(w, map[string]bool{"success": ok})
}

// apiVaultDelete — удаление секрета из Vault.
func (a *App) apiVaultDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path  string `json:"path"`
		Mount string `json:"mount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	ok, err := a.vault.DeleteSecret(ctx, req.Path, req.Mount)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.vault.InvalidateCache()
	a.auditLog("vault_delete", currentUser(r), req.Path, "", ok, r.RemoteAddr)
	a.metrics.IncOperation("vault_delete", ok)
	writeJSON(w, map[string]bool{"success": ok})
}

// apiAiDiagnose — диагностика проблемы через ИИ.
func (a *App) apiAiDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ServerName string           `json:"server_name"`
		Query      string           `json:"query"`
		Detection  *aidiagDetection `json:"detection"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	var d aidiag.Detection
	if req.Detection != nil {
		d = req.Detection.toDetection()
	} else if req.Query != "" {
		serverCtx := ""
		if req.ServerName != "" {
			serverCtx = a.detector.GetServerContext(ctx, req.ServerName)
		}
		diag, err := a.ai.DiagnoseManual(ctx, req.Query, serverCtx)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, diag)
		return
	} else {
		writeJSONError(w, http.StatusBadRequest, "no query or detection")
		return
	}
	diag, err := a.ai.Diagnose(ctx, d)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, diag)
}

// apiAiApply — применение remediation-команд (через SSH).
func (a *App) apiAiApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Server    string   `json:"server"`
		Container string   `json:"container"`
		Commands  []string `json:"commands"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	type result struct {
		Command string `json:"command"`
		Output  string `json:"output"`
		Safe    bool   `json:"safe"`
		Success bool   `json:"success"`
	}
	var results []result
	for _, cmd := range req.Commands {
		if !aidiag.IsCommandSafe(cmd) {
			results = append(results, result{Command: cmd, Output: "Пропущено (небезопасная команда)", Safe: false})
			continue
		}
		// Контейнерные операции через ServerCore.
		lower := strings.ToLower(strings.TrimSpace(cmd))
		if strings.HasPrefix(lower, "docker restart ") || strings.HasPrefix(lower, "docker start ") || strings.HasPrefix(lower, "docker stop ") {
			parts := strings.Fields(cmd)
			if len(parts) >= 3 {
				action := parts[1]
				container := parts[2]
				var res interface{}
				var err error
				switch action {
				case "restart":
					res, err = a.serverCore.RestartContainer(ctx, req.Server, container)
				case "start":
					res, err = a.serverCore.StartContainer(ctx, req.Server, container)
				case "stop":
					res, err = a.serverCore.StopContainer(ctx, req.Server, container)
				}
				msg := ""
				success := false
				if vmRes, ok := res.(models.VmOperationResult); ok {
					msg = vmRes.Message
					success = vmRes.Success
				}
				if err != nil {
					msg = err.Error()
				}
				results = append(results, result{Command: cmd, Output: msg, Safe: true, Success: success})
			}
		} else {
			results = append(results, result{Command: cmd, Output: "Команда не может быть выполнена автоматически", Safe: true})
		}
	}
	writeJSON(w, results)
}

// apiEphemeralCreate — создание эфемерного ключа.
func (a *App) apiEphemeralCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Template string `json:"template"`
		Duration int    `json:"duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	key, ok, msg := a.vault.CreateEphemeralKey(ctx, req.Template, req.Duration)
	writeJSON(w, map[string]interface{}{"success": ok, "message": msg, "key": key})
}

// apiEphemeralRevoke — отзыв эфемерного ключа.
func (a *App) apiEphemeralRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		LeaseID string `json:"lease_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	ok, msg := a.vault.RevokeEphemeralKey(ctx, req.LeaseID)
	writeJSON(w, map[string]interface{}{"success": ok, "message": msg})
}

// ── Логи приложения (просмотр лог-файла в панели) ──

func (a *App) apiLogsRecent(w http.ResponseWriter, r *http.Request) {
	lines := 500
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			lines = n
		}
	}
	content := ""
	if a.logPath != "" {
		data, err := os.ReadFile(a.logPath)
		if err == nil {
			content = lastNLines(string(data), lines)
		} else {
			content = "Не удалось прочитать лог-файл: " + err.Error()
		}
	} else {
		content = "Лог-файл не настроен."
	}
	writeJSON(w, map[string]interface{}{"path": a.logPath, "content": content})
}

func lastNLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

// ── Decommissioned servers management ──

// apiDecommissionedServers — управление списком выведенных из эксплуатации
// серверов без перезагрузки. Поддерживает:
//
//	GET  — вернуть текущий список;
//	POST — добавить (action=add) или убрать (action=remove) сервер по имени/IP.
//
// При добавлении/удалении отправляется однократное оповещение в MS Teams.
func (a *App) apiDecommissionedServers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg := a.cfg
		writeJSON(w, map[string]interface{}{
			"excluded_servers": cfg.ServerCore.ExcludedServers,
		})
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	caller := a.currentUser(r)
	if caller == nil || (string(caller.Role) != "superadmin" && string(caller.Role) != "admin") {
		writeJSON(w, map[string]interface{}{"success": false, "message": "Forbidden: admin access required"})
		return
	}
	var req struct {
		Action string `json:"action"`
		Server string `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Server = strings.TrimSpace(req.Server)
	if req.Server == "" {
		writeJSONError(w, http.StatusBadRequest, "server is required")
		return
	}

	// Клонируем текущий конфиг.
	cfg := *a.cfg
	list := make([]string, len(cfg.ServerCore.ExcludedServers))
	copy(list, cfg.ServerCore.ExcludedServers)

	switch req.Action {
	case "add":
		// Проверяем, нет ли уже в списке.
		for _, e := range list {
			if strings.EqualFold(strings.TrimSpace(e), req.Server) {
				writeJSON(w, map[string]interface{}{"success": true, "message": "Уже в списке", "excluded_servers": list})
				return
			}
		}
		list = append(list, req.Server)
	case "remove":
		var newList []string
		found := false
		for _, e := range list {
			if strings.EqualFold(strings.TrimSpace(e), req.Server) {
				found = true
				continue
			}
			newList = append(newList, e)
		}
		if !found {
			writeJSON(w, map[string]interface{}{"success": true, "message": "Не найден в списке", "excluded_servers": list})
			return
		}
		list = newList
	default:
		writeJSONError(w, http.StatusBadRequest, "unknown action (use 'add' or 'remove')")
		return
	}

	cfg.ServerCore.ExcludedServers = list
	if err := a.store.Set(&cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.applyConfig(&cfg)
	a.serverCore.InvalidateCaches()

	// Audit.
	action := "decommission_" + req.Action
	detail := fmt.Sprintf("server=%s action=%s", req.Server, req.Action)
	a.auditLog(action, caller.Username, req.Server, detail, true, r.RemoteAddr)

	// Однократное оповещение в Teams.
	if a.cfg.MSTeams.WebhookURL != "" {
		var title, msg string
		if req.Action == "add" {
			title = "🚫 Сервер выведен из эксплуатации"
			msg = fmt.Sprintf("Сервер: %s\nИсключён из мониторинга.\nВремя: %s\nПользователь: %s", req.Server, tashkentNowStr(), caller.Username)
			a.teams.SendMessage(title, msg, msteams.ColorWarning)
		} else {
			title = "✅ Сервер введён в эксплуатацию"
			msg = fmt.Sprintf("Сервер: %s\nВозвращён в мониторинг.\nВремя: %s\nПользователь: %s", req.Server, tashkentNowStr(), caller.Username)
			a.teams.SendMessage(title, msg, msteams.ColorGood)
		}
	}

	writeJSON(w, map[string]interface{}{
		"success":          true,
		"message":          "Список обновлён",
		"excluded_servers": list,
	})
}

func tashkentNowStr() string {
	loc, err := time.LoadLocation("Asia/Tashkent")
	if err != nil {
		return time.Now().UTC().Format("2006-01-02 15:04:05")
	}
	return time.Now().In(loc).Format("2006-01-02 15:04:05")
}

// ── Вспомогательные ──

type aidiagDetection struct {
	ServerName  string `json:"server_name"`
	ServerIP    string `json:"server_ip"`
	Env         string `json:"env"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Context     string `json:"context"`
}

func (d *aidiagDetection) toDetection() aidiag.Detection {
	return aidiag.Detection{
		ServerName: d.ServerName, ServerIP: d.ServerIP, Env: d.Env,
		Type: d.Type, Severity: d.Severity, Title: d.Title,
		Description: d.Description, Context: d.Context,
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError отдаёт JSON-ошибку (чтобы клиентский fetch().json() не падал
// с "Unexpected token" при plain-text http.Error).
func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

var _ = context.Background
