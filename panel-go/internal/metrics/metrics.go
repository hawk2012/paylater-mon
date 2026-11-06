// Package metrics — коллектор метрик самой панели (Prometheus /metrics endpoint).
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Counter — простой счётчик.
type Counter struct {
	Name string
	Help string
	mu   sync.Mutex
	vals map[string]float64
}

// Gauge — значение с метками.
type Gauge struct {
	Name string
	Help string
	mu   sync.Mutex
	vals map[string]float64
}

// Collector — набор метрик панели.
type Collector struct {
	mu sync.Mutex

	HTTPRequestsTotal    *Counter
	HTTPRequestDuration  *Gauge // histogram-ish (среднее/макс по route)
	OperationsTotal      *Counter
	MonitorCyclesTotal   *Counter
	AlertsSentTotal      *Counter
	UptimeSeconds        time.Time
	LastMonitorCycle     time.Time
	ActiveSSHConnections int
}

// NewCollector создаёт коллектор.
func NewCollector() *Collector {
	return &Collector{
		HTTPRequestsTotal:   &Counter{Name: "paylater_http_requests_total", Help: "Всего HTTP-запросов", vals: map[string]float64{}},
		HTTPRequestDuration: &Gauge{Name: "paylater_http_request_seconds", Help: "Время обработки запроса (среднее по route)", vals: map[string]float64{}},
		OperationsTotal:     &Counter{Name: "paylater_operations_total", Help: "Операции (restart, delete, write...) по типу", vals: map[string]float64{}},
		MonitorCyclesTotal:  &Counter{Name: "paylater_monitor_cycles_total", Help: "Циклы фонового мониторинга", vals: map[string]float64{}},
		AlertsSentTotal:     &Counter{Name: "paylater_alerts_sent_total", Help: "Отправлено алертов в Teams", vals: map[string]float64{}},
		UptimeSeconds:       time.Now(),
	}
}

// IncHTTPRequest увеличивает счётчик HTTP-запросов по маршруту и коду.
func (c *Collector) IncHTTPRequest(route string, status int, dur time.Duration) {
	if c == nil {
		return
	}
	labels := fmt.Sprintf(`route="%s",status="%d"`, route, status)
	c.HTTPRequestsTotal.mu.Lock()
	c.HTTPRequestsTotal.vals[labels]++
	c.HTTPRequestsTotal.mu.Unlock()

	c.HTTPRequestDuration.mu.Lock()
	key := fmt.Sprintf(`route="%s"`, route)
	if _, ok := c.HTTPRequestDuration.vals[key]; !ok {
		c.HTTPRequestDuration.vals[key] = dur.Seconds()
	} else {
		// экспоненциальное сглаживание
		c.HTTPRequestDuration.vals[key] = c.HTTPRequestDuration.vals[key]*0.9 + dur.Seconds()*0.1
	}
	c.HTTPRequestDuration.mu.Unlock()
}

// IncOperation увеличивает счётчик операций по типу и результату.
func (c *Collector) IncOperation(op string, success bool) {
	if c == nil {
		return
	}
	labels := fmt.Sprintf(`operation="%s",success="%t"`, op, success)
	c.OperationsTotal.mu.Lock()
	c.OperationsTotal.vals[labels]++
	c.OperationsTotal.mu.Unlock()
}

// IncMonitorCycle отмечает цикл мониторинга.
func (c *Collector) IncMonitorCycle() {
	if c == nil {
		return
	}
	c.MonitorCyclesTotal.mu.Lock()
	c.MonitorCyclesTotal.vals[`{}`]++
	c.MonitorCyclesTotal.mu.Unlock()
	c.mu.Lock()
	c.LastMonitorCycle = time.Now()
	c.mu.Unlock()
}

// IncAlert отмечает отправленный алерт.
func (c *Collector) IncAlert() {
	if c == nil {
		return
	}
	c.AlertsSentTotal.mu.Lock()
	c.AlertsSentTotal.vals[`{}`]++
	c.AlertsSentTotal.mu.Unlock()
}

// Render генерирует текст в формате Prometheus.
func (c *Collector) Render() string {
	if c == nil {
		return ""
	}
	var sb strings.Builder
	c.mu.Lock()
	uptime := time.Since(c.UptimeSeconds).Seconds()
	lastCycle := "0"
	if !c.LastMonitorCycle.IsZero() {
		lastCycle = fmt.Sprintf("%d", c.LastMonitorCycle.Unix())
	}
	ssh := c.ActiveSSHConnections
	c.mu.Unlock()

	fmt.Fprintf(&sb, "# HELP paylater_uptime_seconds Время работы панели\n")
	fmt.Fprintf(&sb, "# TYPE paylater_uptime_seconds gauge\n")
	fmt.Fprintf(&sb, "paylater_uptime_seconds %f\n", uptime)
	fmt.Fprintf(&sb, "# HELP paylater_last_monitor_cycle_unix Время последнего цикла мониторинга\n")
	fmt.Fprintf(&sb, "# TYPE paylater_last_monitor_cycle_unix gauge\n")
	fmt.Fprintf(&sb, "paylater_last_monitor_cycle_unix %s\n", lastCycle)
	fmt.Fprintf(&sb, "# HELP paylater_active_ssh_connections Активные SSH-соединения\n")
	fmt.Fprintf(&sb, "# TYPE paylater_active_ssh_connections gauge\n")
	fmt.Fprintf(&sb, "paylater_active_ssh_connections %d\n", ssh)

	renderCounter(&sb, c.HTTPRequestsTotal)
	renderGauge(&sb, c.HTTPRequestDuration)
	renderCounter(&sb, c.OperationsTotal)
	renderCounter(&sb, c.MonitorCyclesTotal)
	renderCounter(&sb, c.AlertsSentTotal)
	return sb.String()
}

func renderCounter(sb *strings.Builder, c *Counter) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(sb, "# HELP %s %s\n", c.Name, c.Help)
	fmt.Fprintf(sb, "# TYPE %s counter\n", c.Name)
	keys := sortedKeys(c.vals)
	for _, k := range keys {
		labels := k
		if labels == "{}" {
			labels = ""
		} else {
			labels = "{" + labels + "}"
		}
		fmt.Fprintf(sb, "%s%s %v\n", c.Name, labels, c.vals[k])
	}
}

func renderGauge(sb *strings.Builder, g *Gauge) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	fmt.Fprintf(sb, "# HELP %s %s\n", g.Name, g.Help)
	fmt.Fprintf(sb, "# TYPE %s gauge\n", g.Name)
	keys := sortedKeys(g.vals)
	for _, k := range keys {
		labels := "{" + k + "}"
		fmt.Fprintf(sb, "%s%s %v\n", g.Name, labels, g.vals[k])
	}
}

func sortedKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
