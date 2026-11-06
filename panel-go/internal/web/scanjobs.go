// Асинхронные TLS/Staging-TLS сканирования с прогрессом и кэшем результатов.
//
// Страницы /tls и /staging-tls рендерятся МГНОВЕННО, без синхронного сканирования:
// проверка выполняется в фоне (goroutine), а браузер опрашивает статус и видит
// часы (таймер) + прогресс, пока идёт тест. Готовый результат кэшируется на
// scanResultTTL, чтобы повторный заход на страницу не запускал скан заново.
package web

import (
	"context"
	"sync"
	"time"

	"paylater-mon/internal/stagingtls"
	"paylater-mon/internal/tlsscan"
)

// scanResultTTL — время, в течение которого готовый результат считается свежим.
const scanResultTTL = 10 * time.Minute

// maxTLSScanServers — ограничение числа сканируемых серверов на странице /tls.
const maxTLSScanServers = 12

// tlsScanJob — состояние асинхронного TLS-сканирования.
type tlsScanJob struct {
	mu         sync.Mutex
	state      string // idle | running | done | error
	startedAt  time.Time
	finishedAt time.Time
	err        string
	total      int
	done       int
	current    string // имя сервера, который сканируется сейчас
	results    []tlsscan.ServerTLS
	tips       []string
	cancel     context.CancelFunc
}

func newTLSScanJob() *tlsScanJob {
	return &tlsScanJob{state: "idle", tips: generalTLSTips()}
}

// status возвращает JSON-статус для API.
func (j *tlsScanJob) status() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	st := map[string]interface{}{
		"state":   j.state,
		"total":   j.total,
		"done":    j.done,
		"current": j.current,
		"error":   j.err,
		"fresh":   j.state == "done" && time.Since(j.finishedAt) < scanResultTTL,
	}
	if !j.startedAt.IsZero() {
		st["started_at"] = j.startedAt.UTC().Format(time.RFC3339)
		st["elapsed_ms"] = int(time.Since(j.startedAt).Milliseconds())
	}
	return st
}

// start запускает новый скан (если уже идёт — возвращает текущий статус).
func (j *tlsScanJob) start(run func(ctx context.Context)) map[string]interface{} {
	j.mu.Lock()
	if j.state == "running" {
		st := j.status()
		j.mu.Unlock()
		return st
	}
	if j.cancel != nil {
		j.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	j.state = "running"
	j.err = ""
	j.results = nil
	j.total = 0
	j.done = 0
	j.current = ""
	j.startedAt = time.Now()
	j.finishedAt = time.Time{}
	j.mu.Unlock()

	go run(ctx)
	return j.status()
}

// setProgress обновляет прогресс сканирования.
func (j *tlsScanJob) setProgress(done, total int, current string) {
	j.mu.Lock()
	j.done = done
	j.total = total
	j.current = current
	j.mu.Unlock()
}

// finish завершает скан результатом.
func (j *tlsScanJob) finish(results []tlsscan.ServerTLS, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.finishedAt = time.Now()
	j.current = ""
	if err != nil {
		j.state = "error"
		j.err = err.Error()
		return
	}
	j.results = results
	j.state = "done"
}

// stagingScanJob — состояние асинхронного Staging-TLS сканирования.
type stagingScanJob struct {
	mu         sync.Mutex
	state      string // idle | running | done | error
	startedAt  time.Time
	finishedAt time.Time
	err        string
	phase      string // текущая фаза: staging / prod / versions / load / issues
	done       int
	total      int
	report     *stagingtls.Report
	cancel     context.CancelFunc
}

func newStagingScanJob() *stagingScanJob {
	return &stagingScanJob{state: "idle"}
}

// status возвращает JSON-статус для API.
func (j *stagingScanJob) status() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	st := map[string]interface{}{
		"state": j.state,
		"phase": j.phase,
		"done":  j.done,
		"total": j.total,
		"error": j.err,
		"fresh": j.state == "done" && time.Since(j.finishedAt) < scanResultTTL,
	}
	if !j.startedAt.IsZero() {
		st["started_at"] = j.startedAt.UTC().Format(time.RFC3339)
		st["elapsed_ms"] = int(time.Since(j.startedAt).Milliseconds())
	}
	return st
}

// start запускает новый скан (если уже идёт — возвращает текущий статус).
func (j *stagingScanJob) start(run func(ctx context.Context)) map[string]interface{} {
	j.mu.Lock()
	if j.state == "running" {
		st := j.status()
		j.mu.Unlock()
		return st
	}
	if j.cancel != nil {
		j.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	j.state = "running"
	j.err = ""
	j.report = nil
	j.phase = ""
	j.done = 0
	j.total = 0
	j.startedAt = time.Now()
	j.finishedAt = time.Time{}
	j.mu.Unlock()

	go run(ctx)
	return j.status()
}

// setProgress обновляет фазу/прогресс сканирования.
func (j *stagingScanJob) setProgress(phase string, done, total int) {
	j.mu.Lock()
	j.phase = phase
	j.done = done
	j.total = total
	j.mu.Unlock()
}

// finish завершает скан результатом.
func (j *stagingScanJob) finish(report *stagingtls.Report, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.finishedAt = time.Now()
	if err != nil {
		j.state = "error"
		j.err = err.Error()
		return
	}
	j.report = report
	j.state = "done"
}

// generalTLSTips — глобальные советы по TLS (не зависят от сервера).
func generalTLSTips() []string {
	return []string{
		"TLS 1.0 и TLS 1.1 признаны устаревшими (RFC 8996) и должны быть отключены.",
		"Используйте TLS 1.2 как минимальную версию, TLS 1.3 — как предпочтительную.",
		"Исключите слабые cipher suites: RC4, 3DES, CBC-SHA1.",
		"Для Camunda 8 / Zeebe и Graylog настройте HTTPS с TLS 1.2+.",
	}
}

// startTLSScan запускает фоновое TLS-сканирование и возвращает статус.
func (a *App) startTLSScan() map[string]interface{} {
	return a.tlsJob.start(a.runTLSScan)
}

// stopTLSScan отменяет текущее TLS-сканирование.
func (a *App) stopTLSScan() map[string]interface{} {
	a.tlsJob.mu.Lock()
	defer a.tlsJob.mu.Unlock()
	if a.tlsJob.state != "running" {
		return a.tlsJob.status()
	}
	if a.tlsJob.cancel != nil {
		a.tlsJob.cancel()
	}
	a.tlsJob.state = "error"
	a.tlsJob.err = "сканирование остановлено пользователем"
	a.tlsJob.finishedAt = time.Now()
	a.tlsJob.current = ""
	return a.tlsJob.status()
}

// runTLSScan выполняет TLS-сканирование всех серверов с прогрессом.
func (a *App) runTLSScan(ctx context.Context) {
	servers, _ := a.serverCore.GetServers(ctx)
	names := make([]string, 0, len(servers))
	for i, sv := range servers {
		if i >= maxTLSScanServers {
			break
		}
		names = append(names, sv.Name)
	}

	a.tlsJob.setProgress(0, len(names), "")

	var results []tlsscan.ServerTLS
	for i, name := range names {
		if ctx.Err() != nil {
			a.tlsJob.finish(nil, ctx.Err())
			return
		}
		a.tlsJob.setProgress(i, len(names), name)
		res := a.tlsScanner.Scan(ctx, name)
		results = append(results, res)
		a.tlsJob.setProgress(i+1, len(names), "")
	}
	a.tlsJob.finish(results, nil)
}

// startStagingScan запускает фоновое Staging-TLS сканирование и возвращает статус.
func (a *App) startStagingScan() map[string]interface{} {
	return a.stagingJob.start(a.runStagingScan)
}

// stopStagingScan отменяет текущее Staging-TLS сканирование.
func (a *App) stopStagingScan() map[string]interface{} {
	a.stagingJob.mu.Lock()
	defer a.stagingJob.mu.Unlock()
	if a.stagingJob.state != "running" {
		return a.stagingJob.status()
	}
	if a.stagingJob.cancel != nil {
		a.stagingJob.cancel()
	}
	a.stagingJob.state = "error"
	a.stagingJob.err = "сканирование остановлено пользователем"
	a.stagingJob.finishedAt = time.Now()
	return a.stagingJob.status()
}

// stagingScanTimeout — общий таймаут на всю Staging-TLS проверку.
const stagingScanTimeout = 5 * time.Minute

// runStagingScan выполняет Staging-TLS проверку с прогрессом по фазам.
func (a *App) runStagingScan(ctx context.Context) {
	// Общий таймаут: вся проверка не может длиться дольше stagingScanTimeout.
	scanCtx, cancel := context.WithTimeout(ctx, stagingScanTimeout)
	defer cancel()

	report := a.stagingSvc.ProbeWithProgress(scanCtx, func(phase string, done, total int) {
		a.stagingJob.setProgress(phase, done, total)
	})
	// ProbeWithProgress всегда возвращает report (возможно partial при таймауте).
	// Если report есть — показываем его (даже при таймауте, с пометкой в summary).
	if report != nil {
		a.stagingJob.finish(report, nil)
		return
	}
	if scanCtx.Err() != nil {
		a.stagingJob.finish(nil, scanCtx.Err())
		return
	}
	a.stagingJob.finish(report, nil)
}
