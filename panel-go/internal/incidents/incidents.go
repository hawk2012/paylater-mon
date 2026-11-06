// Package incidents — хранение истории инцидентов (JSON-файл, ротация).
package incidents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"paylater-mon/internal/models"
)

// Store — файловое хранилище инцидентов.
type Store struct {
	mu      sync.Mutex
	path    string
	maxSize int64
}

// New создаёт хранилище. path — путь к JSON-файлу.
func New(path string, maxSize int64) *Store {
	if path == "" {
		path = "logs/incidents.json"
	}
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0o755)
	if maxSize <= 0 {
		maxSize = 5 * 1024 * 1024 // 5 MB
	}
	return &Store{path: path, maxSize: maxSize}
}

// Record добавляет инцидент в историю.
func (s *Store) Record(inc models.Incident) {
	if inc.Timestamp.IsZero() {
		inc.Timestamp = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.load()
	all = append(all, inc)
	// Ограничиваем до 5000 записей.
	if len(all) > 5000 {
		all = all[len(all)-5000:]
	}
	s.save(all)
}

// All возвращает все инциденты (новые сверху).
func (s *Store) All() []models.Incident {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.load()
	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.After(all[j].Timestamp)
	})
	return all
}

// Recent возвращает последние n инцидентов.
func (s *Store) Recent(n int) []models.Incident {
	all := s.All()
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// ByType возвращает инциденты определённого типа.
func (s *Store) ByType(incType string) []models.Incident {
	var result []models.Incident
	for _, inc := range s.All() {
		if inc.Type == incType {
			result = append(result, inc)
		}
	}
	return result
}

func (s *Store) load() []models.Incident {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil
	}
	var all []models.Incident
	if json.Unmarshal(data, &all) != nil {
		return nil
	}
	return all
}

func (s *Store) save(all []models.Incident) {
	s.rotateIfNeeded()
	data, _ := json.MarshalIndent(all, "", "  ")
	_ = os.WriteFile(s.path, data, 0o644)
}

func (s *Store) rotateIfNeeded() {
	if s.maxSize <= 0 {
		return
	}
	info, err := os.Stat(s.path)
	if err != nil || info.Size() < s.maxSize {
		return
	}
	bak := s.path + ".bak"
	_ = os.Rename(s.path, bak)
}
