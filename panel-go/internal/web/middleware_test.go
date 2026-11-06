package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"paylater-mon/internal/metrics"
	"paylater-mon/internal/users"
)

// TestMiddlewareSkipsStaticWithoutAuth проверяет, что статические файлы
// (/static/*) доступны без аутентификации, а защищённые пути редиректят
// на /login. Иначе браузер не может загрузить CSS до входа и страница
// рендерится «белой».
func TestMiddlewareSkipsStaticWithoutAuth(t *testing.T) {
	app := &App{
		userStore: &users.Store{},
		metrics:   metrics.NewCollector(),
	}

	// /static/ не должен редиректить на login.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("static-ok"))
	})
	handler := app.middleware(next)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/css/app.css", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/static/css/app.css: expected 200, got %d", rr.Code)
	}
	if rr.Body.String() != "static-ok" {
		t.Errorf("/static/css/app.css: expected next handler to run, got %q", rr.Body.String())
	}

	// Защищённый путь без сессии должен редиректить на /login.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusSeeOther {
		t.Errorf("/: expected 303 redirect, got %d", rr2.Code)
	}
	if loc := rr2.Header().Get("Location"); loc != "/login" {
		t.Errorf("/: expected redirect to /login, got %q", loc)
	}
}
