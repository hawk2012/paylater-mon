package zeebe

import (
	"testing"

	"paylater-mon/internal/models"
)

func TestParsePrometheus(t *testing.T) {
	content := []byte(`# HELP zeebe_process_instance_count_total Total number of process instances
# TYPE zeebe_process_instance_count_total counter
zeebe_process_instance_count_total{partition="1"} 150
zeebe_process_instance_count_total{partition="2"} 100
zeebe_execution_duration_seconds 12.5
zeebe_running_process_instances{state="active"} 42
`)
	m := &models.ZeebeMetrics{
		Counters:        map[string]float64{},
		Gauges:          map[string]float64{},
		CountersByLabel: map[string]map[string]float64{},
		GaugesByLabel:   map[string]map[string]float64{},
	}
	parsePrometheus(content, m)

	if m.Counters["zeebe_process_instance_count_total"] != 250 {
		t.Errorf("expected counter sum 250, got %v", m.Counters["zeebe_process_instance_count_total"])
	}
	if m.CountersByLabel["zeebe_process_instance_count_total"]["partition=1"] != 150 {
		t.Errorf("expected labeled counter 150, got %v", m.CountersByLabel["zeebe_process_instance_count_total"])
	}
	if m.Gauges["zeebe_execution_duration_seconds"] != 12.5 {
		t.Errorf("expected gauge 12.5, got %v", m.Gauges["zeebe_execution_duration_seconds"])
	}
}

func TestParsePrometheusEmpty(t *testing.T) {
	m := &models.ZeebeMetrics{Counters: map[string]float64{}, Gauges: map[string]float64{}}
	parsePrometheus(nil, m)
	if len(m.Counters) != 0 {
		t.Errorf("expected no counters, got %v", m.Counters)
	}
}

func TestParsePrometheusCommentsAndJunk(t *testing.T) {
	content := []byte("# just comment\n\ninvalid line\nzeebe_healthy 1\n")
	m := &models.ZeebeMetrics{Counters: map[string]float64{}, Gauges: map[string]float64{}}
	parsePrometheus(content, m)
	if len(m.Gauges) == 0 {
		t.Error("expected at least zeebe_healthy gauge")
	}
}
