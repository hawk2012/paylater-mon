package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"paylater-mon/internal/config"
	"paylater-mon/internal/storage"
	"paylater-mon/internal/users"

	"gopkg.in/yaml.v3"
)

func yamlUnmarshal(data []byte, out interface{}) error {
	return yaml.Unmarshal(data, out)
}

// ── Login / Logout (пункт 20) ──

func (a *App) pageLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		if a.userStore != nil {
			u, ok := a.userStore.Authenticate(username, password)
			if !ok {
				a.render(w, "login", map[string]interface{}{"Title": "Вход", "Error": "Неверный логин или пароль"})
				return
			}
			sess := a.sessions.Create(u.Username)
			http.SetCookie(w, &http.Cookie{
				Name:     "plmon_session",
				Value:    sess.Token,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   43200, // 12 часов
			})
			if u.MustChangePassword {
				http.Redirect(w, r, "/change-password", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	a.render(w, "login", map[string]interface{}{"Title": "Вход"})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("plmon_session")
	if err == nil && a.sessions != nil {
		a.sessions.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "plmon_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ── Change password (пункт 20) ──

func (a *App) pageChangePassword(w http.ResponseWriter, r *http.Request) {
	user := a.currentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		oldPass := r.FormValue("old_password")
		newPass := r.FormValue("new_password")
		confirm := r.FormValue("confirm_password")
		if newPass != confirm {
			a.render(w, "change_password", map[string]interface{}{"Title": "Смена пароля", "Error": "Пароли не совпадают"})
			return
		}
		if len(newPass) < 6 {
			a.render(w, "change_password", map[string]interface{}{"Title": "Смена пароля", "Error": "Пароль слишком короткий (мин. 6 символов)"})
			return
		}
		if err := a.userStore.UpdatePassword(context.Background(), user.Username, oldPass, newPass); err != nil {
			a.render(w, "change_password", map[string]interface{}{"Title": "Смена пароля", "Error": err.Error()})
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.render(w, "change_password", map[string]interface{}{"Title": "Смена пароля", "MustChange": user.MustChangePassword})
}

// ── User management (пункт 20) ──

func (a *App) pageUsers(w http.ResponseWriter, r *http.Request) {
	user := a.currentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !users.CanManageUsers(user.Role) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	a.render(w, "users", map[string]interface{}{
		"Title":       "Пользователи",
		"Users":       a.userStore.List(),
		"CurrentUser": user.Username,
		"CurrentRole": string(user.Role),
	})
}

func (a *App) apiUserCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller := a.currentUser(r)
	if caller == nil || !users.CanManageUsers(caller.Role) {
		writeJSON(w, map[string]interface{}{"success": false, "message": "Forbidden"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	if req.Password == "" {
		req.Password = users.GenerateRandomPassword(12)
	}
	err := a.userStore.Create(context.Background(), req.Username, req.Password, users.Role(req.Role), true)
	if err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	a.auditLog("user_create", caller.Username, req.Username, "role="+req.Role, true, r.RemoteAddr)
	writeJSON(w, map[string]interface{}{"success": true, "password": req.Password, "message": "Пользователь создан. Пароль: " + req.Password})
}

func (a *App) apiUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller := a.currentUser(r)
	if caller == nil || !users.CanManageUsers(caller.Role) {
		writeJSON(w, map[string]interface{}{"success": false, "message": "Forbidden"})
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	err := a.userStore.Delete(context.Background(), caller.Role, req.Username)
	if err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	a.auditLog("user_delete", caller.Username, req.Username, "", true, r.RemoteAddr)
	writeJSON(w, map[string]interface{}{"success": true})
}

func (a *App) apiUserResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller := a.currentUser(r)
	if caller == nil || !users.CanManageUsers(caller.Role) {
		writeJSON(w, map[string]interface{}{"success": false, "message": "Forbidden"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	if req.Password == "" {
		req.Password = users.GenerateRandomPassword(12)
	}
	err := a.userStore.AdminResetPassword(context.Background(), caller.Role, req.Username, req.Password, true)
	if err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	a.auditLog("user_reset_password", caller.Username, req.Username, "", true, r.RemoteAddr)
	writeJSON(w, map[string]interface{}{"success": true, "password": req.Password})
}

func (a *App) apiUserRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller := a.currentUser(r)
	if caller == nil || !users.CanManageUsers(caller.Role) {
		writeJSON(w, map[string]interface{}{"success": false, "message": "Forbidden"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	err := a.userStore.UpdateRole(context.Background(), caller.Role, req.Username, users.Role(req.Role))
	if err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	a.auditLog("user_role_change", caller.Username, req.Username, "role="+req.Role, true, r.RemoteAddr)
	writeJSON(w, map[string]interface{}{"success": true})
}

// ── Config editing (пункт 20: изменение config.yaml без перезагрузки) ──

func (a *App) apiConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller := a.currentUser(r)
	if caller == nil || !users.CanEditConfig(caller.Role) {
		writeJSON(w, map[string]interface{}{"success": false, "message": "Forbidden: admin access required"})
		return
	}
	var req struct {
		YAML   string          `json:"yaml"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Поддерживаем два способа: YAML (старый) и JSON-объект (графический редактор).
	var newCfg *config.Config
	if len(req.Config) > 0 {
		newCfg = config.Default()
		if err := json.Unmarshal(req.Config, newCfg); err != nil {
			writeJSONError(w, http.StatusBadRequest, "config parse error: "+err.Error())
			return
		}
	} else if req.YAML != "" {
		var err error
		newCfg, err = configFromYAML(req.YAML)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "YAML parse error: "+err.Error())
			return
		}
	} else {
		writeJSONError(w, http.StatusBadRequest, "empty config")
		return
	}
	// Сохраняем через Store (перезаписывает config.yaml).
	if err := a.store.Set(newCfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Применяем ко всем сервисам без перезапуска.
	a.applyConfig(newCfg)
	a.auditLog("config_update", caller.Username, "config.yaml", "", true, r.RemoteAddr)
	writeJSON(w, map[string]interface{}{"success": true, "message": "Конфигурация обновлена. Перезапуск не требуется."})
}

// ── Migrate secrets to Vault (пункт 22) ──

func (a *App) apiMigrateSecrets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller := a.currentUser(r)
	if caller == nil || !users.CanManageUsers(caller.Role) {
		writeJSON(w, map[string]interface{}{"success": false, "message": "Forbidden: superadmin access required"})
		return
	}
	if a.secretResolver == nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": "Secret resolver not initialized"})
		return
	}
	err := a.secretResolver.MigrateToVault(context.Background())
	if err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	// Сохраняем обновлённый конфиг с vault: ссылками.
	if err := a.store.Set(a.cfg); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "message": "Config save error: " + err.Error()})
		return
	}
	a.auditLog("secrets_migrate", caller.Username, "config.yaml", "secrets moved to Vault", true, r.RemoteAddr)
	writeJSON(w, map[string]interface{}{"success": true, "message": "Секреты мигрированы в Vault. config.yaml обновлён."})
}

// ── Helper: auditLog ──

func (a *App) auditLog(action, user, target, detail string, success bool, sourceIP string) {
	if a.db != nil {
		_ = a.db.InsertAudit(storage.AuditEntry{
			Timestamp: time.Now(),
			Action:    action,
			User:      user,
			Target:    target,
			Detail:    detail,
			Success:   success,
			SourceIP:  sourceIP,
		})
	}
}

// configFromYAML парсит YAML-строку в Config.
func configFromYAML(yamlStr string) (*config.Config, error) {
	cfg := config.Default()
	if err := yamlUnmarshal([]byte(yamlStr), cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
