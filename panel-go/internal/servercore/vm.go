package servercore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"paylater-mon/internal/models"
)

// apiBase возвращает базовый URL Servercore API.
func (s *Service) apiBase() string {
	base := s.cfg.ServerCore.ApiBase
	if base == "" {
		base = "https://cloud.api.servercore.com"
	}
	return strings.TrimRight(base, "/")
}

// GetTemplates получает список образов ОС для создания ВМ.
func (s *Service) GetTemplates(ctx context.Context) ([]models.VmTemplate, error) {
	if !s.IsMonitoringEnabled(ctx) {
		return []models.VmTemplate{}, nil
	}
	// Пункт 61: приоритет — Glance API (каталог Keystone type=image).
	if gl := s.glanceEndpoint(); gl != "" {
		for _, path := range []string{"/v2/images", "/images"} {
			resp, err := s.sendIAM(ctx, http.MethodGet, gl+path+"?status=active&limit=100", nil)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				continue
			}
			if tpls := parseGlanceImages(body); len(tpls) > 0 {
				return tpls, nil
			}
		}
	}
	base := s.apiBase()
	for _, path := range []string{"/v1/images", "/v1/templates", "/v1/os", "/api/v1/images"} {
		resp, err := s.sendIAM(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if tpls := parseTemplates(body); len(tpls) > 0 {
			return tpls, nil
		}
	}
	return []models.VmTemplate{}, nil
}

// GetGlanceImages получает образы ОС напрямую из Glance API (v2).
// Пункт 61: полноценный список образов с именем, статусом и размером.
func (s *Service) GetGlanceImages(ctx context.Context) ([]models.VmTemplate, error) {
	gl := s.glanceEndpoint()
	if gl == "" || !s.IsMonitoringEnabled(ctx) {
		return []models.VmTemplate{}, nil
	}
	for _, path := range []string{"/v2/images", "/images"} {
		resp, err := s.sendIAM(ctx, http.MethodGet, gl+path+"?status=active&limit=200", nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if tpls := parseGlanceImages(body); len(tpls) > 0 {
			return tpls, nil
		}
	}
	return []models.VmTemplate{}, nil
}

// parseGlanceImages разбирает ответ Glance v2: {"images":[{...}]}.
func parseGlanceImages(body []byte) []models.VmTemplate {
	var doc struct {
		Images []map[string]interface{} `json:"images"`
	}
	if json.Unmarshal(body, &doc) != nil || len(doc.Images) == 0 {
		return nil
	}
	var list []models.VmTemplate
	for _, m := range doc.Images {
		name := firstStr(m, "name")
		if name == "" {
			continue
		}
		osName := normalizeOSName(name, firstStr(m, "id"))
		list = append(list, models.VmTemplate{
			ID:              firstStr(m, "id"),
			Name:            name,
			OperatingSystem: osName,
			Version:         firstStr(m, "version"),
			Description:     firstStr(m, "description", "comment"),
			Size:            int64(toInt(m, "size", "disk_size")),
			Status:          firstStr(m, "status", "visibility"),
		})
	}
	return list
}

// GetNetworks получает список сетей из Neutron (для формы создания ВМ).
func (s *Service) GetNetworks(ctx context.Context) ([]models.VmNetwork, error) {
	ep := s.neutronEndpoint()
	if ep == "" || !s.IsMonitoringEnabled(ctx) {
		return []models.VmNetwork{}, nil
	}
	for _, path := range []string{"/v2.0/networks", "/networks"} {
		resp, err := s.sendIAM(ctx, http.MethodGet, ep+path, nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var doc struct {
			Networks []map[string]interface{} `json:"networks"`
		}
		if json.Unmarshal(body, &doc) != nil || len(doc.Networks) == 0 {
			continue
		}
		var list []models.VmNetwork
		for _, m := range doc.Networks {
			list = append(list, models.VmNetwork{
				ID:     firstStr(m, "id"),
				Name:   firstStr(m, "name"),
				Status: firstStr(m, "status"),
			})
		}
		return list, nil
	}
	return []models.VmNetwork{}, nil
}

// GetSecurityGroups получает список групп безопасности из Neutron.
func (s *Service) GetSecurityGroups(ctx context.Context) ([]models.VmSecurityGroup, error) {
	ep := s.neutronEndpoint()
	if ep == "" || !s.IsMonitoringEnabled(ctx) {
		return []models.VmSecurityGroup{}, nil
	}
	for _, path := range []string{"/v2.0/security-groups", "/security-groups"} {
		resp, err := s.sendIAM(ctx, http.MethodGet, ep+path, nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var doc struct {
			SecurityGroups []map[string]interface{} `json:"security_groups"`
		}
		if json.Unmarshal(body, &doc) != nil || len(doc.SecurityGroups) == 0 {
			continue
		}
		var list []models.VmSecurityGroup
		for _, m := range doc.SecurityGroups {
			list = append(list, models.VmSecurityGroup{
				ID:          firstStr(m, "id"),
				Name:        firstStr(m, "name"),
				Description: firstStr(m, "description"),
			})
		}
		return list, nil
	}
	return []models.VmSecurityGroup{}, nil
}

// GetKeyPairs получает список SSH-ключей из Nova.
func (s *Service) GetKeyPairs(ctx context.Context) ([]models.VmKeyPair, error) {
	if !s.IsMonitoringEnabled(ctx) {
		return []models.VmKeyPair{}, nil
	}
	ep := s.computeEndpoint()
	if ep == "" {
		return []models.VmKeyPair{}, nil
	}
	for _, path := range []string{"/os-keypairs", "/keypairs"} {
		resp, err := s.sendIAM(ctx, http.MethodGet, ep+path, nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var doc struct {
			Keypairs []map[string]interface{} `json:"keypairs"`
		}
		if json.Unmarshal(body, &doc) != nil || len(doc.Keypairs) == 0 {
			continue
		}
		var list []models.VmKeyPair
		for _, kp := range doc.Keypairs {
			var kpInner map[string]interface{}
			// Формат: [{"keypair": {...}}, ...]
			if inner, ok := kp["keypair"].(map[string]interface{}); ok {
				kpInner = inner
			} else {
				kpInner = kp
			}
			list = append(list, models.VmKeyPair{
				Name:        firstStr(kpInner, "name"),
				Fingerprint: firstStr(kpInner, "fingerprint"),
			})
		}
		return list, nil
	}
	return []models.VmKeyPair{}, nil
}

// GetPresets получает список конфигураций (тарифов) ВМ.
func (s *Service) GetPresets(ctx context.Context) ([]models.VmPreset, error) {
	if !s.IsMonitoringEnabled(ctx) {
		return []models.VmPreset{}, nil
	}
	base := s.apiBase()
	for _, path := range []string{"/v1/presets", "/v1/flavors", "/v1/configurations", "/api/v1/presets"} {
		resp, err := s.sendIAM(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if ps := parsePresets(body); len(ps) > 0 {
			return ps, nil
		}
	}
	return []models.VmPreset{}, nil
}

// CreateVM создаёт новую ВМ (полная форма: сеть, security group, ключ).
func (s *Service) CreateVM(ctx context.Context, req models.VmCreateRequest) (models.VmOperationResult, error) {
	if !s.IsMonitoringEnabled(ctx) {
		return models.VmOperationResult{Success: false, Message: "IAM-токен не получен"}, nil
	}
	base := s.apiBase()
	payload := map[string]interface{}{
		"name":          req.Name,
		"image":         req.TemplateID,
		"configuration": map[string]int{"cpu": req.Cpu, "ram": req.RamMb, "disk": req.DiskGb},
		"os":            req.OsID,
		"location":      req.Location,
		"comment":       req.Comment,
	}
	// Сеть и security group — если указаны.
	if req.NetworkID != "" {
		payload["network"] = req.NetworkID
	}
	if req.SecurityGroupID != "" {
		payload["security_group"] = req.SecurityGroupID
	}
	if req.KeyPairName != "" {
		payload["key_name"] = req.KeyPairName
	}
	body, _ := json.Marshal(payload)

	// Пробуем и OpenStack-совместимый формат (server: {..}).
	for _, path := range []string{"/v1/servers", "/v1/hosts", "/api/v1/servers"} {
		resp, err := s.sendIAM(ctx, http.MethodPost, base+path, body)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
			continue
		}
		return models.VmOperationResult{Success: true, Message: "ВМ «" + req.Name + "» создана", VmID: parseCreatedID(respBody)}, nil
	}

	// Fallback: OpenStack Nova формат {"server": {"name": ..., "imageRef": ..., "flavorRef": ...}}.
	if ep := s.computeEndpoint(); ep != "" {
		novaPayload := map[string]interface{}{
			"server": map[string]interface{}{
				"name":      req.Name,
				"imageRef":  req.TemplateID,
				"flavorRef": "",
				"flavor":    map[string]int{"vcpus": req.Cpu, "ram": req.RamMb, "disk": req.DiskGb},
				"networks":  []map[string]string{{"uuid": req.NetworkID}},
				"key_name":  req.KeyPairName,
				"metadata":  map[string]string{"os": req.OsID},
				"user_data": "#!/bin/bash\n",
			},
		}
		body, _ := json.Marshal(novaPayload)
		for _, path := range []string{"/servers", "/v2.1/servers"} {
			resp, err := s.sendIAM(ctx, http.MethodPost, ep+path, body)
			if err != nil {
				continue
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
				continue
			}
			return models.VmOperationResult{Success: true, Message: "ВМ «" + req.Name + "» создана (Nova)", VmID: parseCreatedID(respBody)}, nil
		}
	}

	return models.VmOperationResult{Success: false, Message: "Не удалось создать ВМ (проверьте API ServerCore и параметры формы)"}, nil
}

// DeleteVM, StartVM, StopVM, RestartVM — операции над ВМ.
func (s *Service) DeleteVM(ctx context.Context, vmID string) (models.VmOperationResult, error) {
	return s.vmAction(ctx, vmID, "delete")
}
func (s *Service) StartVM(ctx context.Context, vmID string) (models.VmOperationResult, error) {
	return s.vmAction(ctx, vmID, "start")
}
func (s *Service) StopVM(ctx context.Context, vmID string) (models.VmOperationResult, error) {
	return s.vmAction(ctx, vmID, "stop")
}
func (s *Service) RestartVM(ctx context.Context, vmID string) (models.VmOperationResult, error) {
	return s.vmAction(ctx, vmID, "restart")
}

func (s *Service) vmAction(ctx context.Context, vmID, action string) (models.VmOperationResult, error) {
	if !s.IsMonitoringEnabled(ctx) || vmID == "" {
		return models.VmOperationResult{Success: false, Message: "IAM-токен не получен или ID не указан"}, nil
	}
	base := s.apiBase()
	var method string
	var paths []string
	switch action {
	case "delete":
		method = http.MethodDelete
		paths = []string{"/v1/servers/" + vmID, "/v1/hosts/" + vmID, "/api/v1/servers/" + vmID}
	case "start":
		method = http.MethodPost
		paths = []string{"/v1/servers/" + vmID + "/start", "/v1/hosts/" + vmID + "/start"}
	case "stop":
		method = http.MethodPost
		paths = []string{"/v1/servers/" + vmID + "/stop", "/v1/hosts/" + vmID + "/stop"}
	case "restart":
		method = http.MethodPost
		paths = []string{"/v1/servers/" + vmID + "/restart", "/v1/hosts/" + vmID + "/restart"}
	default:
		return models.VmOperationResult{Success: false, Message: "unknown action"}, nil
	}
	labels := map[string]string{"delete": "удалена", "start": "запущена", "stop": "остановлена", "restart": "перезагружена"}
	for _, p := range paths {
		resp, err := s.sendIAM(ctx, method, base+p, nil)
		if err != nil {
			continue
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
			return models.VmOperationResult{Success: true, Message: "ВМ " + vmID + " " + labels[action]}, nil
		}
	}
	return models.VmOperationResult{Success: false, Message: "Не удалось выполнить «" + action + "» для ВМ " + vmID}, nil
}

// GetConsoleURL возвращает URL консоли ВМ.
func (s *Service) GetConsoleURL(ctx context.Context, vmID string) (string, error) {
	if !s.IsMonitoringEnabled(ctx) || vmID == "" {
		return "", nil
	}
	base := s.apiBase()
	for _, p := range []string{"/v1/servers/" + vmID + "/console", "/v1/hosts/" + vmID + "/console"} {
		resp, err := s.sendIAM(ctx, http.MethodGet, base+p, nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var m map[string]interface{}
		if json.Unmarshal(body, &m) != nil {
			continue
		}
		for _, f := range []string{"url", "console_url", "vnc_url", "ws_url", "terminal_url"} {
			if v, ok := m[f].(string); ok && v != "" {
				return v, nil
			}
		}
	}
	return "", nil
}

// GenerateVMName генерирует имя ВМ по шаблону uz-{env}-{app}-{number}.
func (s *Service) GenerateVMName(ctx context.Context, env, app string) (string, error) {
	prefix := "uz-" + env + "-" + app + "-"
	existing := map[string]bool{}
	if s.IsMonitoringEnabled(ctx) {
		servers, _ := s.GetServers(ctx)
		for _, sv := range servers {
			existing[strings.ToLower(sv.Name)] = true
			existing[strings.ToLower(sv.Title)] = true
		}
	}
	for n := 1; n <= 999; n++ {
		candidate := fmt.Sprintf("%s%d", prefix, n)
		if !existing[strings.ToLower(candidate)] {
			return candidate, nil
		}
	}
	return prefix + "999", nil
}

// CloneServer создаёт staging-клон PROD-сервера из резервной копии диска
// (пункт 45 IMPROVEMENTS.md):
//   - создаёт snapshot диска исходного сервера через Nova createImage;
//   - ожидает готовности образа (status=active);
//   - создаёт новую ВМ из этого snapshot-образа с тем же flavor и сетью;
//   - копирует nginx-конфиг и docker-compose.yml через SSH (best-effort).
//
// Если Nova createImage недоступен, пробует fallback через Cinder volume
// snapshot + block_device_mapping.
func (s *Service) CloneServer(ctx context.Context, sourceName, cloneName string) (models.VmOperationResult, error) {
	if !s.IsMonitoringEnabled(ctx) {
		return models.VmOperationResult{Success: false, Message: "IAM-токен не получен"}, nil
	}
	if cloneName == "" {
		cloneName = sourceName + "-stg-clone"
	}

	// 1. Находим исходный PROD-сервер.
	servers, _ := s.GetAllServers(ctx)
	var source *models.ServerHost
	for i := range servers {
		if strings.EqualFold(servers[i].Name, sourceName) {
			source = &servers[i]
			break
		}
	}
	if source == nil {
		return models.VmOperationResult{Success: false, Message: "Исходный сервер не найден: " + sourceName}, nil
	}

	ep := s.computeEndpoint()
	if ep == "" {
		return models.VmOperationResult{Success: false, Message: "Compute endpoint недоступен"}, nil
	}

	// 2. Получаем детали сервера из Nova (flavor, network, volumes).
	flavorID, networkUUID, volumeIDs := "", "", []string{}
	{
		resp, err := s.sendIAM(ctx, http.MethodGet, ep+"/servers/"+source.ID, nil)
		if err != nil {
			return models.VmOperationResult{Success: false, Message: "Не удалось получить детали сервера: " + err.Error()}, nil
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var doc struct {
			Server map[string]interface{} `json:"server"`
		}
		if json.Unmarshal(body, &doc) == nil && doc.Server != nil {
			if fl, ok := doc.Server["flavor"].(map[string]interface{}); ok {
				flavorID = firstStr(fl, "id")
			}
			if addr, ok := doc.Server["addresses"].(map[string]interface{}); ok {
				for _, netVal := range addr {
					if arr, ok := netVal.([]interface{}); ok && len(arr) > 0 {
						// Ищем port_id (используется как network uuid для новой ВМ).
						for _, a := range arr {
							if m, ok := a.(map[string]interface{}); ok {
								if pid := firstStr(m, "port_id"); pid != "" {
									networkUUID = pid
								}
							}
						}
						break
					}
				}
			}
		}
	}

	// Volume attachments (Cinder) — для fallback через volume snapshot.
	{
		resp, err := s.sendIAM(ctx, http.MethodGet, ep+"/servers/"+source.ID+"/os-volume_attachments", nil)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var doc struct {
				VolumeAttachments []map[string]interface{} `json:"volumeAttachments"`
			}
			if json.Unmarshal(body, &doc) == nil {
				for _, va := range doc.VolumeAttachments {
					if vid := firstStr(va, "volumeId"); vid != "" {
						volumeIDs = append(volumeIDs, vid)
					}
				}
			}
		}
	}

	snapshotName := cloneName + "-snapshot"
	snapshotLabel := sourceName + " → " + cloneName

	// 3. Создаём snapshot диска сервера.
	//    Путь A: Nova createImage (snapshot образа из диска сервера).
	imageID, snapErr := s.createServerSnapshot(ctx, source.ID, snapshotName)
	if snapErr != nil || imageID == "" {
		// Путь B (fallback): Cinder volume snapshot + block_device_mapping.
		if len(volumeIDs) > 0 {
			vmID, cerr := s.createCloneFromVolumeSnapshot(ctx, cloneName, source.ID, flavorID, networkUUID, volumeIDs, snapshotName)
			if cerr == nil {
				s.copyServerConfig(ctx, sourceName, cloneName)
				return models.VmOperationResult{Success: true, Message: "Staging-клон создан из snapshot тома (Cinder): " + snapshotLabel, VmID: vmID}, nil
			}
		}
		msg := "Не удалось создать snapshot диска сервера"
		if snapErr != nil {
			msg += ": " + snapErr.Error()
		}
		return models.VmOperationResult{Success: false, Message: msg}, nil
	}

	// 4. Ожидаем готовности snapshot-образа (status=active).
	if err := s.waitImageActive(ctx, imageID, 5*time.Minute); err != nil {
		return models.VmOperationResult{Success: false, Message: "Snapshot создан, но не стал active: " + err.Error()}, nil
	}

	// 5. Создаём ВМ из snapshot-образа.
	vmID, err := s.createServerFromSnapshot(ctx, cloneName, imageID, flavorID, networkUUID, source)
	if err != nil {
		return models.VmOperationResult{Success: false, Message: "Snapshot готов, но не удалось создать ВМ: " + err.Error()}, nil
	}

	// 6. Копируем конфиги через SSH (best-effort).
	s.copyServerConfig(ctx, sourceName, cloneName)

	return models.VmOperationResult{Success: true, Message: "Staging-клон создан из snapshot диска PROD: " + snapshotLabel, VmID: vmID}, nil
}

// createServerSnapshot создаёт snapshot образа из диска сервера через
// Nova createImage action: POST /servers/{id}/action {"createImage": {...}}.
// Возвращает ID созданного образа (из заголовка Location или поиска по имени).
func (s *Service) createServerSnapshot(ctx context.Context, serverID, snapshotName string) (string, error) {
	ep := s.computeEndpoint()
	if ep == "" {
		return "", fmt.Errorf("compute endpoint недоступен")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"createImage": map[string]interface{}{
			"name":     snapshotName,
			"metadata": map[string]string{"source_server": serverID, "purpose": "staging-clone"},
		},
	})
	for _, path := range []string{"/servers/" + serverID + "/action", "/v2.1/servers/" + serverID + "/action"} {
		resp, err := s.sendIAM(ctx, http.MethodPost, ep+path, payload)
		if err != nil {
			continue
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			continue
		}
		// Образ ID — из заголовка Location: .../images/{id}.
		if loc := resp.Header.Get("Location"); loc != "" {
			if idx := strings.Index(loc, "/images/"); idx >= 0 {
				return strings.TrimRight(loc[idx+8:], "/"), nil
			}
		}
		// Fallback: ищем образ по имени в Glance.
		if gl := s.glanceEndpoint(); gl != "" {
			resp2, err := s.sendIAM(ctx, http.MethodGet, gl+"/v2/images?name="+urlQueryEscape(snapshotName), nil)
			if err == nil {
				body, _ := io.ReadAll(resp2.Body)
				resp2.Body.Close()
				if imgs := parseGlanceImages(body); len(imgs) > 0 {
					return imgs[0].ID, nil
				}
			}
		}
		// Fallback: ищем в Nova images.
		resp2, err := s.sendIAM(ctx, http.MethodGet, ep+"/images?name="+urlQueryEscape(snapshotName), nil)
		if err == nil {
			body, _ := io.ReadAll(resp2.Body)
			resp2.Body.Close()
			var doc struct {
				Images []map[string]interface{} `json:"images"`
			}
			if json.Unmarshal(body, &doc) == nil && len(doc.Images) > 0 {
				return firstStr(doc.Images[0], "id"), nil
			}
		}
		return "", fmt.Errorf("snapshot отправлен, но ID образа не получен")
	}
	return "", fmt.Errorf("createImage action не выполнен")
}

// waitImageActive ожидает, пока образ в Glance станет active.
func (s *Service) waitImageActive(ctx context.Context, imageID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	gl := s.glanceEndpoint()
	checkURL := ""
	if gl != "" {
		checkURL = gl + "/v2/images/" + imageID
	} else if ep := s.computeEndpoint(); ep != "" {
		checkURL = ep + "/images/" + imageID
	}
	if checkURL == "" {
		return fmt.Errorf("нет endpoint для проверки образа")
	}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := s.sendIAM(ctx, http.MethodGet, checkURL, nil)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var doc map[string]interface{}
			if json.Unmarshal(body, &doc) == nil {
				status := strings.ToLower(firstStr(doc, "status"))
				switch status {
				case "active":
					return nil
				case "error", "killed":
					return fmt.Errorf("образ в статусе %s", status)
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
	return fmt.Errorf("таймаут ожидания образа (5 мин)")
}

// createServerFromSnapshot создаёт ВМ из snapshot-образа.
func (s *Service) createServerFromSnapshot(ctx context.Context, name, imageID, flavorID, networkUUID string, source *models.ServerHost) (string, error) {
	ep := s.computeEndpoint()
	if ep == "" {
		return "", fmt.Errorf("compute endpoint недоступен")
	}
	server := map[string]interface{}{
		"name":     name,
		"imageRef": imageID,
		"metadata": map[string]string{"purpose": "staging-clone", "source": source.Name},
	}
	if flavorID != "" {
		server["flavorRef"] = flavorID
	} else {
		server["flavor"] = map[string]int{
			"vcpus": source.CpuCores,
			"ram":   int(source.MemoryTotalGB * 1024),
			"disk":  int(source.DiskTotalGB),
		}
	}
	if networkUUID != "" {
		server["networks"] = []map[string]string{{"uuid": networkUUID}}
	}
	payload, _ := json.Marshal(map[string]interface{}{"server": server})
	for _, path := range []string{"/servers", "/v2.1/servers"} {
		resp, err := s.sendIAM(ctx, http.MethodPost, ep+path, payload)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
			continue
		}
		return parseCreatedID(body), nil
	}
	return "", fmt.Errorf("не удалось создать ВМ из snapshot")
}

// createCloneFromVolumeSnapshot — fallback: создаёт клон через Cinder
// volume snapshot + block_device_mapping_v2 (если сервер использует volumes).
func (s *Service) createCloneFromVolumeSnapshot(ctx context.Context, cloneName, sourceID, flavorID, networkUUID string, volumeIDs []string, snapshotName string) (string, error) {
	ep := s.computeEndpoint()
	if ep == "" || len(volumeIDs) == 0 {
		return "", fmt.Errorf("нет volume attachments")
	}
	// Создаём snapshot первого тома (системный диск).
	snapPayload, _ := json.Marshal(map[string]interface{}{
		"snapshot": map[string]interface{}{
			"volume_id": volumeIDs[0],
			"name":      snapshotName,
			"force":     true,
		},
	})
	snapshotID := ""
	// Пробуем Cinder v3 (через compute proxy) и os-snapshots.
	for _, path := range []string{"/os-snapshots", "/v2.1/os-snapshots"} {
		resp, err := s.sendIAM(ctx, http.MethodPost, ep+path, snapPayload)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			continue
		}
		var doc struct {
			Snapshot map[string]interface{} `json:"snapshot"`
		}
		if json.Unmarshal(body, &doc) == nil && doc.Snapshot != nil {
			snapshotID = firstStr(doc.Snapshot, "id")
		}
		break
	}
	if snapshotID == "" {
		return "", fmt.Errorf("не удалось создать volume snapshot")
	}

	// Создаём ВМ с block_device_mapping_v2 из snapshot.
	server := map[string]interface{}{
		"name":     cloneName,
		"imageRef": "",
		"metadata": map[string]string{"purpose": "staging-clone"},
		"block_device_mapping_v2": []map[string]interface{}{
			{
				"source_type":           "snapshot",
				"destination_type":      "volume",
				"snapshot_id":           snapshotID,
				"delete_on_termination": true,
				"boot_index":            0,
			},
		},
	}
	if flavorID != "" {
		server["flavorRef"] = flavorID
	}
	if networkUUID != "" {
		server["networks"] = []map[string]string{{"uuid": networkUUID}}
	}
	payload, _ := json.Marshal(map[string]interface{}{"server": server})
	for _, path := range []string{"/servers", "/v2.1/servers"} {
		resp, err := s.sendIAM(ctx, http.MethodPost, ep+path, payload)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
			continue
		}
		return parseCreatedID(body), nil
	}
	return "", fmt.Errorf("не удалось создать ВМ из volume snapshot")
}

// urlQueryEscape — минимальный URL-encode для query-параметров.
func urlQueryEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "%20"), "/", "%2F")
}

// copyServerConfig копирует nginx-конфиг и docker-compose.yml с исходного
// сервера на клон (best-effort: ошибки не блокируют создание клона).
func (s *Service) copyServerConfig(ctx context.Context, sourceName, cloneName string) {
	// Читаем конфиги с исходного сервера.
	nginxCfg, _ := s.RunSSHCommand(ctx, sourceName, "nginx -T 2>/dev/null || cat /etc/nginx/nginx.conf 2>/dev/null")
	composeCfg, _ := s.RunSSHCommand(ctx, sourceName, "cat /etc/docker/compose/docker-compose.yml 2>/dev/null || cat docker-compose.yml 2>/dev/null || find / -name 'docker-compose.yml' -maxdepth 4 2>/dev/null | head -1 | xargs cat 2>/dev/null")

	if nginxCfg == "" && composeCfg == "" {
		return
	}

	// Пытаемся записать на клон (может ещё не быть готов — это best-effort).
	if nginxCfg != "" {
		_, _ = s.RunSSHCommand(ctx, cloneName, "mkdir -p /etc/nginx && cat > /tmp/nginx-clone.conf << 'NGINX_EOF'\n"+nginxCfg+"\nNGINX_EOF")
	}
	if composeCfg != "" {
		_, _ = s.RunSSHCommand(ctx, cloneName, "mkdir -p /etc/docker/compose && cat > /etc/docker/compose/docker-compose.yml << 'COMPOSE_EOF'\n"+composeCfg+"\nCOMPOSE_EOF")
	}
}

func parseTemplates(body []byte) []models.VmTemplate {
	items := extractArray(body, []string{"images", "templates", "os", "items", "data", "result"})
	var list []models.VmTemplate
	for _, m := range items {
		list = append(list, models.VmTemplate{
			ID:              firstStr(m, "id", "image_id", "template_id"),
			Name:            firstStr(m, "name", "title", "description"),
			OperatingSystem: firstStr(m, "os", "operating_system", "family"),
			Version:         firstStr(m, "version"),
			Description:     firstStr(m, "description", "comment"),
		})
	}
	return list
}

func parsePresets(body []byte) []models.VmPreset {
	items := extractArray(body, []string{"presets", "flavors", "configurations", "items", "data", "result"})
	var list []models.VmPreset
	for _, m := range items {
		list = append(list, models.VmPreset{
			ID:          firstStr(m, "id", "preset_id", "flavor_id"),
			Name:        firstStr(m, "name", "title"),
			Cpu:         toInt(m, "cpu", "cpus", "vcpu"),
			RamMb:       toInt(m, "ram", "ram_mb", "memory"),
			DiskGb:      toInt(m, "disk", "disk_gb", "storage"),
			Description: firstStr(m, "description", "comment"),
		})
	}
	return list
}

func parseCreatedID(body []byte) string {
	var root map[string]interface{}
	if json.Unmarshal(body, &root) != nil {
		return ""
	}
	el := root
	for _, name := range []string{"server", "host", "data", "info", "result"} {
		if sub, ok := el[name].(map[string]interface{}); ok {
			el = sub
			break
		}
	}
	return firstStr(el, "id", "server_id", "host_id")
}

func extractArray(body []byte, keys []string) []map[string]interface{} {
	var root interface{}
	if json.Unmarshal(body, &root) != nil {
		return nil
	}
	switch v := root.(type) {
	case []interface{}:
		return toMapSlice(v)
	case map[string]interface{}:
		for _, k := range keys {
			if arr, ok := v[k].([]interface{}); ok {
				return toMapSlice(arr)
			}
		}
	}
	return nil
}

func toMapSlice(arr []interface{}) []map[string]interface{} {
	var list []map[string]interface{}
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			list = append(list, m)
		}
	}
	return list
}

func firstStr(m map[string]interface{}, keys ...string) string {
	return str(m, keys...)
}

var _ = bytes.NewReader
