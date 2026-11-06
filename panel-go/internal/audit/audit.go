// Package audit — логирование операций администратора (restart, delete, vault write и т.д.).
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry — запись аудита.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	User      string    `json:"user"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail,omitempty"`
	Success   bool      `json:"success"`
	SourceIP  string    `json:"source_ip,omitempty"`
}

// Service — файловый аудит-логгер (JSON Lines, ротация по размеру).
type Service struct {
	mu      sync.Mutex
	logPath string
	maxSize int64
}

// New создаёт сервис аудита. logPath — путь к файлу; maxSize — макс. размер в байтах (0 = без ротации).
func New(logPath string, maxSize int64) *Service {
	if logPath == "" {
		logPath = "logs/audit.jsonl"
	}
	dir := filepath.Dir(logPath)
	_ = os.MkdirAll(dir, 0o755)
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10 MB
	}
	return &Service{logPath: logPath, maxSize: maxSize}
}

// Log записывает событие в аудит-лог.
func (s *Service) Log(action, user, target, detail string, success bool, sourceIP string) {
	entry := Entry{
		Timestamp: time.Now(),
		Action:    action,
		User:      user,
		Target:    target,
		Detail:    detail,
		Success:   success,
		SourceIP:  sourceIP,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateIfNeeded()
	f, err := os.OpenFile(s.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(entry)
	f.Write(b)
	f.WriteString("\n")
}

// Recent возвращает последние n записей.
func (s *Service) Recent(n int) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.logPath)
	if err != nil {
		return nil
	}
	var entries []Entry
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if json.Unmarshal(line, &e) == nil {
			entries = append(entries, e)
		}
	}
	if len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	return entries
}

func (s *Service) rotateIfNeeded() {
	if s.maxSize <= 0 {
		return
	}
	info, err := os.Stat(s.logPath)
	if err != nil || info.Size() < s.maxSize {
		return
	}
	bak := s.logPath + ".bak"
	_ = os.Rename(s.logPath, bak)
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// FormatEntry — строковое представление для UI.
func FormatEntry(e Entry) string {
	status := "OK"
	if !e.Success {
		status = "FAIL"
	}
	return fmt.Sprintf("[%s] %s %s → %s (%s)", e.Timestamp.Format("2006-01-02 15:04:05"), e.User, e.Action, e.Target, status)
}
