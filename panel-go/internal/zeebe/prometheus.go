package zeebe

import (
	"strconv"
	"strings"

	"paylater-mon/internal/models"
)

// parsePrometheus разбирает текст Prometheus-метрик в ZeebeMetrics.
func parsePrometheus(content []byte, m *models.ZeebeMetrics) {
	counterAgg := map[string]float64{}
	gaugeAgg := map[string]struct{ sum, count float64 }{}
	var processors []models.ZeebeProcessorMetric
	partitions := map[int]*models.ZeebePartitionMetric{}

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		fullName := parts[0]
		value, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil {
			continue
		}
		baseName, labels := parseMetricNameAndLabels(fullName)
		if shouldSkipMetric(fullName, baseName) {
			continue
		}
		isCounter := strings.Contains(fullName, "_total") || strings.Contains(fullName, "_count") ||
			strings.Contains(baseName, "_total") || strings.Contains(baseName, "_count")
		if isCounter {
			counterAgg[baseName] += value
			if len(labels) > 0 {
				if m.CountersByLabel[baseName] == nil {
					m.CountersByLabel[baseName] = map[string]float64{}
				}
				m.CountersByLabel[baseName][joinLabels(labels)] = value
			}
		} else {
			g := gaugeAgg[baseName]
			g.sum += value
			g.count++
			gaugeAgg[baseName] = g
			if len(labels) > 0 {
				if m.GaugesByLabel[baseName] == nil {
					m.GaugesByLabel[baseName] = map[string]float64{}
				}
				m.GaugesByLabel[baseName][joinLabels(labels)] = value
			}
		}
		extractProcessor(baseName, labels, value, &processors)
		extractPartition(baseName, labels, value, partitions)
	}

	for k, v := range counterAgg {
		m.Counters[k] = v
	}
	for k, g := range gaugeAgg {
		if g.count > 0 {
			m.Gauges[k] = g.sum / g.count
		}
	}
	m.Processors = processors
	for _, p := range partitions {
		m.Partitions = append(m.Partitions, *p)
	}
}

func parseMetricNameAndLabels(full string) (string, map[string]string) {
	open := strings.IndexByte(full, '{')
	if open < 0 {
		return full, map[string]string{}
	}
	base := full[:open]
	closeIdx := strings.IndexByte(full, '}')
	if closeIdx < 0 {
		return base, map[string]string{}
	}
	labels := map[string]string{}
	for _, pair := range strings.Split(full[open+1:closeIdx], ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			labels[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), `"`)
		}
	}
	return base, labels
}

func joinLabels(l map[string]string) string {
	var parts []string
	for k, v := range l {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func shouldSkipMetric(full, base string) bool {
	if strings.HasSuffix(base, "_created") {
		return true
	}
	if strings.HasSuffix(base, "_bucket") && !strings.Contains(full, `le="+Inf"`) {
		return true
	}
	switch base {
	case "process_start_time_seconds":
		return true
	}
	if strings.Contains(base, "scrape_duration") || strings.Contains(base, "scrape_samples") {
		return true
	}
	return false
}

func extractProcessor(base string, labels map[string]string, value float64, out *[]models.ZeebeProcessorMetric) {
	if strings.Contains(base, "processor_processing_duration") && strings.HasSuffix(base, "_count") {
		p := models.ZeebeProcessorMetric{FullName: base, Count: int64(value)}
		if v, ok := labels["partition"]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				p.Partition = n
			}
		}
		p.Type = labels["type"]
		if p.Type == "" {
			p.Type = labels["processor"]
		}
		*out = append(*out, p)
	}
}

func extractPartition(base string, labels map[string]string, value float64, parts map[int]*models.ZeebePartitionMetric) {
	ps, ok := labels["partition"]
	if !ok {
		return
	}
	id, err := strconv.Atoi(ps)
	if err != nil {
		return
	}
	if parts[id] == nil {
		parts[id] = &models.ZeebePartitionMetric{PartitionID: id}
	}
	p := parts[id]
	switch {
	case strings.Contains(base, "stream_processor_records"):
		p.RecordsProcessed += int64(value)
	case strings.Contains(base, "stream_processor_latency"):
		p.LatencyCount += int64(value)
	case strings.Contains(base, "batch_processing"):
		p.BatchCount += int64(value)
	case strings.Contains(base, "role"):
		p.Role = labels["role"]
	}
}
