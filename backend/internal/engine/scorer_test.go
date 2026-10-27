package engine

import (
	"siem-backend/internal/cti"
	"testing"
)

func TestCalculateRisk(t *testing.T) {
	cfg := ScorerConfig{
		DefaultAssetMultiplier: 1.0,
		AssetCriticality: map[string]float64{
			"dc-01": 1.5,
		},
	}
	cfg.Weights.VirusTotal = 0.40
	cfg.Weights.AbuseIPDB = 0.35
	cfg.Weights.Shodan = 0.25

	scorer := NewThreatScorer(cfg)

	results := []cti.CTIResult{
		{Provider: "VirusTotal", Score: 80.0},
		{Provider: "AbuseIPDB", Score: 90.0},
		{Provider: "Shodan", Score: 60.0},
	}

	// Weighted calculation:
	// 80 * 0.40 = 32.0
	// 90 * 0.35 = 31.5
	// 60 * 0.25 = 15.0
	// Sum = 78.5
	// Normal asset mult: 1.0 => Score 78.5 => HIGH

	score, tier, _ := scorer.CalculateRisk(results, "corp-pc")
	if score != 78.5 {
		t.Fatalf("expected score 78.5, got %f", score)
	}
	if tier != "HIGH" {
		t.Fatalf("expected tier HIGH, got %s", tier)
	}

	// Critical asset: mult 1.5 => 78.5 * 1.5 = 117.75 => capped at 100.0 => CRITICAL
	critScore, critTier, _ := scorer.CalculateRisk(results, "dc-01.domain.corp")
	if critScore != 100.0 {
		t.Fatalf("expected capped score 100.0, got %f", critScore)
	}
	if critTier != "CRITICAL" {
		t.Fatalf("expected tier CRITICAL, got %s", critTier)
	}
}
