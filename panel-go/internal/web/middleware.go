package web

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"paylater-mon/internal/users"
)

// middleware оборачивает router в auth + request-logging middleware.
func (a *App) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Пропускаем health/metrics без auth.
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		// Пропускаем login/logout без auth.
		if r.URL.Path == "/login" || r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}

		// Статика (CSS/JS/картинки) доступна без auth — иначе браузер не
		// получает стили до входа и страница рендерится «белой».
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		// Если включена система пользователей — session-based auth.
		if a.userStore != nil {
			user := a.currentUser(r)
			if user == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			// Проверяем права на изменение настроек.
			if r.URL.Path == "/system" && r.Method != http.MethodGet && !users.CanEditConfig(user.Role) {
				http.Error(w, "Forbidden: admin access required", http.StatusForbidden)
				return
			}
			// Проверяем права на управление пользователями.
			if strings.HasPrefix(r.URL.Path, "/api/users/") && !users.CanManageUsers(user.Role) {
				http.Error(w, "Forbidden: superadmin access required", http.StatusForbidden)
				return
			}
		} else if a.cfg.Auth.Enabled {
			// Fallback: basic-auth (если система пользователей не подключена).
			user, pass, ok := r.BasicAuth()
			if !ok ||
				subtle.ConstantTimeCompare([]byte(user), []byte(a.cfg.Auth.Username)) != 1 ||
				subtle.ConstantTimeCompare([]byte(pass), []byte(a.cfg.Auth.Password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Paylater Monitor"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// Оборачиваем ResponseWriter для перехвата статус-кода.
		ww := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)

		// Метрики запросов (пункт 15).
		route := normalizeRoute(r.URL.Path)
		a.metrics.IncHTTPRequest(route, ww.status, time.Since(start))
	})
}

// currentUser извлекает пользователя из сессии (cookie).
func (a *App) currentUser(r *http.Request) *users.User {
	if a.sessions == nil {
		return nil
	}
	cookie, err := r.Cookie("plmon_session")
	if err != nil {
		return nil
	}
	username := a.sessions.Get(cookie.Value)
	if username == "" {
		return nil
	}
	u, ok := a.userStore.Get(username)
	if !ok || u.Disabled {
		return nil
	}
	return u
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// normalizeRoute группирует пути для метрик (/graylog/prod → /graylog/:env).
func normalizeRoute(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "/"
	}
	base := "/" + parts[0]
	switch base {
	case "/graylog", "/camunda":
		if len(parts) >= 2 {
			return base + "/:env"
		}
	case "/api":
		return path
	}
	return base
}
