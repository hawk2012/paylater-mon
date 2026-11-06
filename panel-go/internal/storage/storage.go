// Package storage — SQLite-хранилище для аудита и инцидентов (пункт 21 IMPROVEMENTS.md).
// Использует pure-Go драйвер modernc.org/sqlite (без CGO).
package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DB — обёртка над *sql.DB для SQLite.
type DB struct {
	mu sync.Mutex
	db *sql.DB
}

// Open открывает (или создаёт) SQLite-файл и инициализирует схемы.
func Open(path string) (*DB, error) {
	if path == "" {
		path = "data/paylater-mon.db"
	}
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0o755)

	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite не поддерживает параллельные писатели
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: ping: %w", err)
	}
	d := &DB{db: db}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: migrate: %w", err)
	}
	return d, nil
}

// Close закрывает соединение.
func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) migrate() error {
	_, err := d.db.Exec(`
CREATE TABLE IF NOT EXISTS audit_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    user       TEXT    NOT NULL,
    target     TEXT    NOT NULL,
    detail     TEXT    DEFAULT '',
    success    INTEGER NOT NULL DEFAULT 0,
    source_ip  TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_entries(user);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries(action);

CREATE TABLE IF NOT EXISTS incidents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT    NOT NULL,
    type       TEXT    NOT NULL,
    host       TEXT    NOT NULL,
    detail     TEXT    DEFAULT '',
    status     TEXT    NOT NULL DEFAULT 'info'
);
CREATE INDEX IF NOT EXISTS idx_inc_ts ON incidents(timestamp);
CREATE INDEX IF NOT EXISTS idx_inc_type ON incidents(type);
CREATE INDEX IF NOT EXISTS idx_inc_host ON incidents(host);

CREATE TABLE IF NOT EXISTS server_metrics_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT    NOT NULL,
    server     TEXT    NOT NULL,
    cpu        REAL    DEFAULT 0,
    ram        REAL    DEFAULT 0,
    disk       REAL    DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mh_ts ON server_metrics_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_mh_server ON server_metrics_history(server);
`)
	return err
}

// ── Audit ──

// AuditEntry — запись аудита.
type AuditEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	User      string    `json:"user"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail,omitempty"`
	Success   bool      `json:"success"`
	SourceIP  string    `json:"source_ip,omitempty"`
}

// InsertAudit вставляет запись аудита.
func (d *DB) InsertAudit(e AuditEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	_, err := d.db.Exec(
		`INSERT INTO audit_entries (timestamp, action, user, target, detail, success, source_ip) VALUES (?,?,?,?,?,?,?)`,
		e.Timestamp.UTC().Format(time.RFC3339Nano), e.Action, e.User, e.Target, e.Detail, e.Success, e.SourceIP,
	)
	return err
}

// RecentAudit возвращает последние n записей аудита.
func (d *DB) RecentAudit(n int) []AuditEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n <= 0 || n > 1000 {
		n = 100
	}
	rows, err := d.db.Query(
		`SELECT id, timestamp, action, user, target, detail, success, source_ip
		 FROM audit_entries ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		var success int
		if err := rows.Scan(&e.ID, &ts, &e.Action, &e.User, &e.Target, &e.Detail, &success, &e.SourceIP); err != nil {
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		e.Success = success != 0
		result = append(result, e)
	}
	return result
}

// SearchAudit — полнотекстовый поиск по аудиту.
func (d *DB) SearchAudit(query string, limit int) []AuditEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := "%" + query + "%"
	rows, err := d.db.Query(
		`SELECT id, timestamp, action, user, target, detail, success, source_ip
		 FROM audit_entries WHERE action LIKE ? OR user LIKE ? OR target LIKE ? OR detail LIKE ?
		 ORDER BY id DESC LIMIT ?`, q, q, q, q, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		var success int
		if err := rows.Scan(&e.ID, &ts, &e.Action, &e.User, &e.Target, &e.Detail, &success, &e.SourceIP); err != nil {
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		e.Success = success != 0
		result = append(result, e)
	}
	return result
}

// ── Incidents ──

// IncidentEntry — запись инцидента.
type IncidentEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Host      string    `json:"host"`
	Detail    string    `json:"detail"`
	Status    string    `json:"status"`
}

// InsertIncident вставляет инцидент.
func (d *DB) InsertIncident(e IncidentEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	_, err := d.db.Exec(
		`INSERT INTO incidents (timestamp, type, host, detail, status) VALUES (?,?,?,?,?)`,
		e.Timestamp.UTC().Format(time.RFC3339Nano), e.Type, e.Host, e.Detail, e.Status,
	)
	return err
}

// RecentIncidents возвращает последние n инцидентов.
func (d *DB) RecentIncidents(n int) []IncidentEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n <= 0 || n > 1000 {
		n = 100
	}
	rows, err := d.db.Query(
		`SELECT id, timestamp, type, host, detail, status FROM incidents ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []IncidentEntry
	for rows.Next() {
		var e IncidentEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Type, &e.Host, &e.Detail, &e.Status); err != nil {
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		result = append(result, e)
	}
	return result
}

// IncidentsByType — инциденты по типу.
func (d *DB) IncidentsByType(incType string, limit int) []IncidentEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.db.Query(
		`SELECT id, timestamp, type, host, detail, status FROM incidents WHERE type=? ORDER BY id DESC LIMIT ?`,
		incType, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []IncidentEntry
	for rows.Next() {
		var e IncidentEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Type, &e.Host, &e.Detail, &e.Status); err != nil {
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		result = append(result, e)
	}
	return result
}

// ── Server Metrics History ──

// MetricPoint — точка метрик сервера.
type MetricPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Server    string    `json:"server"`
	CPU       float64   `json:"cpu"`
	RAM       float64   `json:"ram"`
	Disk      float64   `json:"disk"`
}

// InsertMetricPoint сохраняет метрику сервера.
func (d *DB) InsertMetricPoint(p MetricPoint) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p.Timestamp.IsZero() {
		p.Timestamp = time.Now()
	}
	_, err := d.db.Exec(
		`INSERT INTO server_metrics_history (timestamp, server, cpu, ram, disk) VALUES (?,?,?,?,?)`,
		p.Timestamp.UTC().Format(time.RFC3339Nano), p.Server, p.CPU, p.RAM, p.Disk,
	)
	return err
}

// MetricHistory — история метрик сервера за последние hours часов.
func (d *DB) MetricHistory(server string, hours int) []MetricPoint {
	d.mu.Lock()
	defer d.mu.Unlock()
	if hours <= 0 {
		hours = 1
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UTC().Format(time.RFC3339Nano)
	rows, err := d.db.Query(
		`SELECT timestamp, server, cpu, ram, disk FROM server_metrics_history
		 WHERE server=? AND timestamp >= ? ORDER BY timestamp ASC`, server, since)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []MetricPoint
	for rows.Next() {
		var p MetricPoint
		var ts string
		if err := rows.Scan(&ts, &p.Server, &p.CPU, &p.RAM, &p.Disk); err != nil {
			continue
		}
		p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		result = append(result, p)
	}
	return result
}

// CleanupOldMetrics удаляет метрики старше maxDays дней.
func (d *DB) CleanupOldMetrics(maxDays int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if maxDays <= 0 {
		maxDays = 30
	}
	cutoff := time.Now().Add(-time.Duration(maxDays) * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	_, err := d.db.Exec(`DELETE FROM server_metrics_history WHERE timestamp < ?`, cutoff)
	return err
}
