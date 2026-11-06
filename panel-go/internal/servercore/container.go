package servercore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"paylater-mon/internal/models"
)

// ContainerActionResult — результат операции с контейнером.
type ContainerActionResult struct {
	Success bool
	Message string
}

// StartContainer запускает Docker-контейнер через SSH.
func (s *Service) StartContainer(ctx context.Context, serverName, containerName string) (models.VmOperationResult, error) {
	return s.containerAction(ctx, serverName, containerName, "start")
}

// StopContainer останавливает Docker-контейнер через SSH.
func (s *Service) StopContainer(ctx context.Context, serverName, containerName string) (models.VmOperationResult, error) {
	return s.containerAction(ctx, serverName, containerName, "stop")
}

// RestartContainer перезапускает Docker-контейнер через SSH.
func (s *Service) RestartContainer(ctx context.Context, serverName, containerName string) (models.VmOperationResult, error) {
	return s.containerAction(ctx, serverName, containerName, "restart")
}

// GetContainerNetworks получает Docker-сети и связи контейнеров (пункт 12 IMPROVEMENTS.md).
func (s *Service) GetContainerNetworks(ctx context.Context, serverName string) ([]models.ContainerNetwork, error) {
	client, err := s.getSshClient(ctx, serverName)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	out, err := client.Run("docker network ls --format '{{json .}}'")
	if err != nil {
		return nil, err
	}
	var networks []models.ContainerNetwork
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]string
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		networks = append(networks, models.ContainerNetwork{
			ID:     m["ID"],
			Name:   m["Name"],
			Driver: m["Driver"],
			Scope:  m["Scope"],
		})
	}
	// Для каждой сети получаем подключённые контейнеры.
	for i := range networks {
		inspectOut, err := client.Run(fmt.Sprintf("docker network inspect %s --format '{{range .Containers}}{{.Name}} {{end}}'", networks[i].Name))
		if err != nil {
			continue
		}
		networks[i].Containers = strings.Fields(strings.TrimSpace(inspectOut))
	}
	return networks, nil
}
func (s *Service) GetContainerLogs(ctx context.Context, serverName, containerName string, lines int) (string, error) {
	if lines <= 0 {
		lines = 500
	}
	client, err := s.getSshClient(ctx, serverName)
	if err != nil {
		return "", err
	}
	defer client.Close()
	out, err := client.Run(fmt.Sprintf("docker logs --tail %d %s 2>&1", lines, containerName))
	return out, err
}

func (s *Service) containerAction(ctx context.Context, serverName, containerName, action string) (models.VmOperationResult, error) {
	client, err := s.getSshClient(ctx, serverName)
	if err != nil {
		return models.VmOperationResult{Success: false, Message: "Не удалось подключиться к серверу " + serverName}, nil
	}
	defer client.Close()
	out, err := client.Run(fmt.Sprintf("docker %s %s", action, containerName))
	success := err == nil || strings.Contains(strings.ToLower(out), "error") == false
	labels := map[string]string{"start": "запущен", "stop": "остановлен", "restart": "перезапущен"}
	label := labels[action]
	if action == "" {
		label = action
	}
	if success {
		return models.VmOperationResult{Success: true, Message: "Контейнер " + containerName + " " + label + "."}, nil
	}
	return models.VmOperationResult{Success: false, Message: "Ошибка: " + out}, nil
}
