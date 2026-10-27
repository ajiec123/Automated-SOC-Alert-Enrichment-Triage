package engine

import (
	"math"
	"siem-backend/internal/cti"
	"strings"
)

type ScorerConfig struct {
	Weights struct {
		VirusTotal float64
		AbuseIPDB  float64
		Shodan     float64
	}
	Thresholds struct {
		Critical float64
		High     float64
		Medium   float64
	}
	DefaultAssetMultiplier float64
	AssetCriticality       map[string]float64
}

type ThreatScorer struct {
	config ScorerConfig
}

func NewThreatScorer(cfg ScorerConfig) *ThreatScorer {
	if cfg.Weights.VirusTotal == 0 && cfg.Weights.AbuseIPDB == 0 && cfg.Weights.Shodan == 0 {
		cfg.Weights.VirusTotal = 0.40
		cfg.Weights.AbuseIPDB = 0.35
		cfg.Weights.Shodan = 0.25
	}
	if cfg.Thresholds.Critical == 0 {
		cfg.Thresholds.Critical = 80.0
		cfg.Thresholds.High = 60.0
		cfg.Thresholds.Medium = 30.0
	}
	if cfg.DefaultAssetMultiplier <= 0 {
		cfg.DefaultAssetMultiplier = 1.0
	}
	return &ThreatScorer{config: cfg}
}

func (s *ThreatScorer) GetAssetMultiplier(assetID string) float64 {
	if assetID == "" {
		return s.config.DefaultAssetMultiplier
	}
	clean := strings.ToLower(strings.TrimSpace(assetID))
	for k, v := range s.config.AssetCriticality {
		if strings.Contains(clean, strings.ToLower(k)) {
			return v
		}
	}
	return s.config.DefaultAssetMultiplier
}

// CalculateRisk evaluates CTI results and asset criticality to produce the composite score and tier
func (s *ThreatScorer) CalculateRisk(results []cti.CTIResult, assetID string) (float64, string, string) {
	if len(results) == 0 {
		return 0.0, "LOW", "No intelligence signals returned"
	}

	// Max score per provider across all IOCs
	providerMax := map[string]float64{
		"VirusTotal": 0.0,
		"AbuseIPDB":  0.0,
		"Shodan":     0.0,
	}

	for _, res := range results {
		pName := res.Provider
		if res.Score > providerMax[pName] {
			providerMax[pName] = res.Score
		}
	}

	weightedSum := (providerMax["VirusTotal"] * s.config.Weights.VirusTotal) +
		(providerMax["AbuseIPDB"] * s.config.Weights.AbuseIPDB) +
		(providerMax["Shodan"] * s.config.Weights.Shodan)

	assetMult := s.GetAssetMultiplier(assetID)
	rawComposite := weightedSum * assetMult
	finalScore := math.Min(100.0, math.Max(0.0, rawComposite))
	finalScore = math.Round(finalScore*100) / 100

	var tier string
	var autoAction string

	switch {
	case finalScore >= s.config.Thresholds.Critical:
		tier = "CRITICAL"
		autoAction = "AUTO_BLOCKED: Firewall edge drop rule dispatched; urgent containment initiated"
	case finalScore >= s.config.Thresholds.High:
		tier = "HIGH"
		autoAction = "TELEGRAM_DISPATCHED: Interactive triage escalation sent to SOC team"
	case finalScore >= s.config.Thresholds.Medium:
		tier = "MEDIUM"
		autoAction = "QUEUED_FOR_TRIAGE: Alert queued for SOC analyst review"
	default:
		tier = "LOW"
		autoAction = "LOGGED: Ingested to local client store without active mitigation"
	}

	return finalScore, tier, autoAction
}
