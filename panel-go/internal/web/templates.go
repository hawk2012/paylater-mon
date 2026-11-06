package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

// loadTemplates загружает шаблоны: базовый layout клонируется для каждой
// страницы, чтобы каждое определение {{define "content"}} было изолировано
// в собственном наборе шаблонов (иначе при ParseGlob все content-блоки
// коллидируют и «побеждает» последний разобранный файл).
func (a *App) loadTemplates() (map[string]*template.Template, error) {
	dir := "internal/web/templates"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// Fallback relative to executable.
		dir = filepath.Join("templates")
	}
	funcs := template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"json": func(v interface{}) (template.JS, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return template.JS(b), nil
		},
		"tlsBadge": func(m map[string]bool, version string) template.HTML {
			ok, exists := m[version]
			if !exists {
				return template.HTML(`<span class="badge badge-info">n/a</span>`)
			}
			if ok {
				return template.HTML(`<span class="badge badge-success">✓</span>`)
			}
			return template.HTML(`<span class="badge badge-danger">✗</span>`)
		},
		// tlsCipher возвращает cipher suite для версии из ключа "TLS 1.2 → suite".
		"tlsCipher": func(m map[string]bool, version string) string {
			for k, ok := range m {
				if !ok {
					continue
				}
				if strings.HasPrefix(k, version+" →") {
					return strings.TrimSpace(strings.TrimPrefix(k, version+" →"))
				}
			}
			return ""
		},
		// protoBadge — бейдж протокола порта (closed/tcp/http/tls/https).
		"protoBadge": func(p string) template.HTML {
			switch p {
			case "https":
				return template.HTML(`<span class="badge badge-success">https</span>`)
			case "tls":
				return template.HTML(`<span class="badge badge-info">tls</span>`)
			case "http":
				return template.HTML(`<span class="badge badge-warning">http</span>`)
			case "tcp":
				return template.HTML(`<span class="badge badge-info">tcp</span>`)
			case "closed":
				return template.HTML(`<span class="badge">closed</span>`)
			default:
				if p == "" {
					return template.HTML(`<span class="badge">n/a</span>`)
				}
				return template.HTML(template.HTMLEscapeString(p))
			}
		},
		"join": func(ss []string, sep string) string {
			return strings.Join(ss, sep)
		},
		"joinInts": func(is []int, sep string) string {
			parts := make([]string, len(is))
			for i, v := range is {
				parts[i] = fmt.Sprint(v)
			}
			return strings.Join(parts, sep)
		},
	}
	// Базовый layout (без content-блока) — клонируется под каждую страницу.
	base, err := template.New("layout").Funcs(funcs).ParseGlob(filepath.Join(dir, "layout.html"))
	if err != nil {
		return nil, err
	}
	pages, err := filepath.Glob(filepath.Join(dir, "*.html"))
	if err != nil {
		return nil, err
	}
	sets := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		name := strings.TrimSuffix(filepath.Base(page), ".html")
		if name == "layout" {
			continue
		}
		clone, err := base.Clone()
		if err != nil {
			return nil, err
		}
		t, err := clone.ParseFiles(page)
		if err != nil {
			return nil, err
		}
		sets[name] = t
	}
	if len(sets) == 0 {
		return nil, fmt.Errorf("no page templates found in %s", dir)
	}
	return sets, nil
}
