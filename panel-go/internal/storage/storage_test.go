package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenAndMigrate(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected db file to exist: %v", err)
	}
}

func TestAuditInsertAndQuery(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	for i := 0; i < 5; i++ {
		err := db.InsertAudit(AuditEntry{
			Timestamp: time.Now(),
			Action:    "container_restart",
			User:      "admin",
			Target:    "server1/app",
			Detail:    "test entry",
			Success:   true,
			SourceIP:  "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("InsertAudit failed: %v", err)
		}
	}

	entries := db.RecentAudit(10)
	if len(entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(entries))
	}

	// Search
	results := db.SearchAudit("container", 10)
	if len(results) != 5 {
		t.Errorf("expected 5 search results, got %d", len(results))
	}

	results = db.SearchAudit("nonexistent", 10)
	if len(results) != 0 {
		t.Errorf("expected 0 search results, got %d", len(results))
	}
}

func TestIncidentsInsertAndQuery(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	err := db.InsertIncident(IncidentEntry{
		Timestamp: time.Now(),
		Type:      "container_down",
		Host:      "server1",
		Detail:    "app container stopped",
		Status:    "critical",
	})
	if err != nil {
		t.Fatalf("InsertIncident failed: %v", err)
	}

	entries := db.RecentIncidents(10)
	if len(entries) != 1 {
		t.Errorf("expected 1 incident, got %d", len(entries))
	}

	byType := db.IncidentsByType("container_down", 10)
	if len(byType) != 1 {
		t.Errorf("expected 1 incident by type, got %d", len(byType))
	}
}

func TestMetricHistory(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	for i := 0; i < 3; i++ {
		err := db.InsertMetricPoint(MetricPoint{
			Timestamp: time.Now(),
			Server:    "server1",
			CPU:       float64(50 + i),
			RAM:       float64(60 + i),
			Disk:      70,
		})
		if err != nil {
			t.Fatalf("InsertMetricPoint failed: %v", err)
		}
	}

	history := db.MetricHistory("server1", 1)
	if len(history) != 3 {
		t.Errorf("expected 3 points, got %d", len(history))
	}
}

func TestCleanupOldMetrics(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	// Insert old metric.
	_ = db.InsertMetricPoint(MetricPoint{
		Timestamp: time.Now().Add(-48 * time.Hour),
		Server:    "old",
		CPU:       10,
	})
	// Insert recent metric.
	_ = db.InsertMetricPoint(MetricPoint{
		Timestamp: time.Now(),
		Server:    "new",
		CPU:       20,
	})

	if err := db.CleanupOldMetrics(1); err != nil {
		t.Fatalf("CleanupOldMetrics failed: %v", err)
	}

	history := db.MetricHistory("old", 24)
	if len(history) != 0 {
		t.Errorf("expected 0 old points, got %d", len(history))
	}
	history = db.MetricHistory("new", 24)
	if len(history) != 1 {
		t.Errorf("expected 1 recent point, got %d", len(history))
	}
}

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	return db
}
