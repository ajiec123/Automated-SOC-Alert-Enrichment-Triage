package engine

import (
	"siem-backend/internal/cti"
	"time"
)

type IOCItem struct {
	Type  cti.IOCType `json:"ioc_type"`
	Value string      `json:"ioc_value"`
}

type AlertPayload struct {
	ID          string                 `json:"alert_id"`
	Source      string                 `json:"source"`
	EventType   string                 `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	SrcIP       string                 `json:"src_ip,omitempty"`
	DstIP       string                 `json:"dst_ip,omitempty"`
	FileHash    string                 `json:"file_hash,omitempty"`
	Domain      string                 `json:"domain,omitempty"`
	AssetID     string                 `json:"asset_id,omitempty"`
	RawMetadata map[string]interface{} `json:"metadata,omitempty"`

	// Compatibility fields for Wazuh / alternative webhook payloads
	RuleID      string                 `json:"rule_id,omitempty"`
	Description string                 `json:"description,omitempty"`
	Indicators  map[string]string      `json:"indicators,omitempty"`
}

type EnrichedAlert struct {
	AlertUUID       string                 `json:"alert_uuid"`
	Source          string                 `json:"source"`
	EventType       string                 `json:"event_type"`
	SeverityRaw     string                 `json:"severity_raw"`
	CalculatedScore float64                `json:"calculated_score"`
	SeverityTier    string                 `json:"severity_tier"` // CRITICAL, HIGH, MEDIUM, LOW
	Status          string                 `json:"status"`        // NEW, ENRICHED, TRIAGED, CONTAINED, DISMISSED
	IOCs            []IOCItem              `json:"iocs"`
	Enrichments     []cti.CTIResult        `json:"enrichments"`
	AssetMultiplier float64                `json:"asset_multiplier"`
	AutoActionTaken string                 `json:"auto_action_taken,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

type ProcessingTask struct {
	Payload   AlertPayload
	Enriched  *EnrichedAlert
	DoneChan  chan struct{}
}
