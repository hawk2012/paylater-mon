// Package web — HTTP-слой панели мониторинга (net/http + html/template).
package web

import (
	"context"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"paylater-mon/internal/aidiag"
	"paylater-mon/internal/config"
	"paylater-mon/internal/graylog"
	"paylater-mon/internal/incidents"
	"paylater-mon/internal/metrics"
	"paylater-mon/internal/monitor"
	"paylater-mon/internal/msteams"
	"paylater-mon/internal/secrets"
	"paylater-mon/internal/servercore"
	"paylater-mon/internal/sessions"
	"paylater-mon/internal/stagingtls"
	"paylater-mon/internal/storage"
	"paylater-mon/internal/tlsscan"
	"paylater-mon/internal/users"
	"paylater-mon/internal/vault"
	"paylater-mon/internal/zeebe"
)

// App — корневое приложение панели.
type App struct {
	store      *config.Store
	cfg        *config.Config
	serverCore *servercore.Service
	graylog    *graylog.Service
	zeebe      *zeebe.Service
	teams      *msteams.Service
	vault      *vault.Service
	ai         *aidiag.Service
	detector   *aidiag.Detector
	monitor    *monitor.Service
	metrics    *metrics.Collector
	wsHub      *wsHub
	router     *http.ServeMux
	templates  map[string]*template.Template
	cancel     context.CancelFunc
	server     *http.Server

	// Файловый логгер (пункт: логи в панели).
	logFile *os.File
	logPath string

	// SQLite storage (пункт 21).
	db *storage.DB

	// Users & sessions (пункт 20).
	userStore *users.Store
	sessions  *sessions.Store

	// Secret resolver (пункт 22).
	secretResolver *secrets.Resolver

	// TLS-сканер (пункт 29 IMPROVEMENTS.md).
	tlsScanner *tlsscan.Scanner

	// Staging-TLS: изолированный клон PROD для проверки TLS 1.3.
	stagingSvc *stagingtls.Service

	// Асинхронные скан-джобы (страницы /tls и /staging-tls рендерятся
	// мгновенно, сканирование выполняется в фоне с прогрессом).
	tlsJob     *tlsScanJob
	stagingJob *stagingScanJob
}

// NewApp создаёт приложение.
func NewApp(store *config.Store) *App {
	cfg := store.Get()
	logger := &stdLogger{}

	sc := servercore.New(cfg, logger)
	gl := graylog.New(cfg, sc)
	zb := zeebe.New(cfg, sc)
	tm := msteams.New(cfg)
	vt := vault.New(cfg)
	ai := aidiag.New(cfg)
	det := aidiag.NewDetector(sc)
	mon := monitor.New(cfg, sc, gl, zb, tm)
	mc := metrics.NewCollector()

	// SQLite storage (пункт 21).
	db, err := storage.Open("data/paylater-mon.db")
	if err != nil {
		log.Printf("WARNING: SQLite init failed, falling back to JSONL: %v", err)
		db = nil
	}

	// Incidents store (JSONL fallback или SQLite).
	var incStore *incidents.Store
	if db == nil {
		incStore = incidents.New("logs/incidents.json", 5*1024*1024)
	}
	mon.WithIncidents(incStore).WithMetrics(mc)
	if db != nil {
		mon.WithDB(db)
	}

	// Users & sessions (пункт 20).
	userStore := users.New(vt)
	if vt.Enabled() {
		if err := userStore.Load(context.Background()); err != nil {
			log.Printf("WARNING: users load failed: %v", err)
		}
	}
	sessStore := sessions.New()

	// Secret resolver (пункт 22).
	secretRes := secrets.New(cfg, vt)
	if secretRes.Enabled() {
		if err := secretRes.ResolveAll(context.Background()); err != nil {
			log.Printf("WARNING: secret resolution failed: %v", err)
		}
	}

	// TLS-сканер (пункт 29 IMPROVEMENTS.md).
	tlsScan := tlsscan.New(sc, nil)

	// Staging-TLS (раздел проверки TLS 1.3 на изолированном клоне PROD).
	staging := stagingtls.New(cfg, sc)

	app := &App{
		store: store, cfg: cfg,
		serverCore: sc, graylog: gl, zeebe: zb, teams: tm,
		vault: vt, ai: ai, detector: det, monitor: mon,
		metrics: mc, wsHub: newWSHub(),
		db: db, userStore: userStore, sessions: sessStore,
		secretResolver: secretRes,
		tlsScanner:     tlsScan,
		stagingSvc:     staging,
		tlsJob:         newTLSScanJob(),
		stagingJob:     newStagingScanJob(),
	}

	tpl, err := app.loadTemplates()
	if err != nil {
		log.Fatalf("ошибка загрузки шаблонов: %v", err)
	}
	app.templates = tpl
	app.router = app.buildRouter()

	// Файловый логгер (просмотр логов в панели).
	app.initLogFile()

	return app
}

// initLogFile открывает logs/app.log для записи и просмотра в панели.
func (a *App) initLogFile() {
	if err := os.MkdirAll("logs", 0o755); err != nil {
		return
	}
	path := filepath.Join("logs", "app.log")
	// Простая ротация: если файл больше 10 МБ — переименовываем в .1.
	if fi, err := os.Stat(path); err == nil && fi.Size() > 10*1024*1024 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	a.logFile = f
	a.logPath = path
}

// applyConfig применяет новую конфигурацию ко всем сервисам без перезапуска.
func (a *App) applyConfig(cfg *config.Config) {
	a.cfg = cfg
	if a.serverCore != nil {
		a.serverCore.ApplyConfig(cfg)
	}
	if a.graylog != nil {
		a.graylog.ApplyConfig(cfg)
	}
	if a.zeebe != nil {
		a.zeebe.ApplyConfig(cfg)
	}
	if a.vault != nil {
		a.vault.ApplyConfig(cfg)
	}
	if a.ai != nil {
		a.ai.ApplyConfig(cfg)
	}
	if a.teams != nil {
		a.teams.ApplyConfig(cfg)
	}
	if a.monitor != nil {
		a.monitor.ApplyConfig(cfg)
	}
	if a.stagingSvc != nil {
		a.stagingSvc.ApplyConfig(cfg)
	}
	if a.secretResolver != nil {
		a.secretResolver.ApplyConfig(cfg)
	}
	if a.serverCore != nil {
		a.serverCore.InvalidateCaches()
	}
}

// Start запускает HTTP-сервер и фоновый мониторинг.
func (a *App) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	// Фоновый мониторинг.
	go a.monitor.Run(ctx)

	// WebSocket/SSE hub (пункт 3).
	go a.wsHub.Run(ctx, a)

	// Файловый логгер: дублируем стандартный лог в logs/app.log.
	if a.logFile != nil {
		log.SetOutput(io.MultiWriter(os.Stdout, a.logFile))
	}

	addr := a.cfg.Server.ListenAddr
	if addr == "" {
		addr = "0.0.0.0:9090"
	}
	handler := a.middleware(a.router)
	a.server = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("═══════════════════════════════════════════")
	log.Printf("  Paylater Monitor")
	log.Printf("  URL: %s", addr)
	if a.cfg.Auth.Enabled {
		log.Printf("  Auth: basic-auth (%s)", a.cfg.Auth.Username)
	}
	log.Printf("═══════════════════════════════════════════")
	go func() {
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
}

// Stop корректно останавливает приложение (graceful shutdown, пункт 19).
func (a *App) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	a.zeebe.Close()
	if a.db != nil {
		a.db.Close()
	}
	if a.logFile != nil {
		_ = a.logFile.Close()
	}
	if a.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		log.Println("ожидание завершения активных запросов (15с)...")
		if err := a.server.Shutdown(ctx); err != nil {
			log.Printf("HTTP shutdown error: %v", err)
			_ = a.server.Close()
		}
		log.Println("HTTP-сервер остановлен.")
	}
}

// logger — адаптер для сервисов.
type stdLogger struct{}

func (l *stdLogger) Infof(f string, a ...interface{})  { log.Printf("INFO  "+f, a...) }
func (l *stdLogger) Warnf(f string, a ...interface{})  { log.Printf("WARN  "+f, a...) }
func (l *stdLogger) Errorf(f string, a ...interface{}) { log.Printf("ERROR "+f, a...) }
