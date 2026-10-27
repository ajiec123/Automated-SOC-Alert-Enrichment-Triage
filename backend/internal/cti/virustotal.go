package cti

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

type VirusTotalProvider struct {
	APIKey     string
	HTTPClient *http.Client
}

func NewVirusTotalProvider(apiKey string, timeout time.Duration) *VirusTotalProvider {
	return &VirusTotalProvider{
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: timeout},
	}
}

func (p *VirusTotalProvider) Name() string {
	return "VirusTotal"
}

func (p *VirusTotalProvider) Query(ctx context.Context, ioc string, iocType IOCType) (CTIResult, error) {
	cleanIOC := strings.TrimSpace(ioc)
	if cleanIOC == "" {
		return CTIResult{Provider: p.Name(), Error: "empty ioc"}, nil
	}

	if p.APIKey != "" && !strings.HasPrefix(p.APIKey, "${") {
		return p.queryRealAPI(ctx, cleanIOC, iocType)
	}

	// Deterministic Mock for dev/demo when API key is not configured
	return p.deterministicMock(cleanIOC, iocType), nil
}

func (p *VirusTotalProvider) queryRealAPI(ctx context.Context, ioc string, iocType IOCType) (CTIResult, error) {
	var endpoint string
	switch iocType {
	case IOCTypeIP:
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ioc)
	case IOCTypeHash:
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", ioc)
	case IOCTypeDomain:
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", ioc)
	default:
		return CTIResult{Provider: p.Name(), Error: "unsupported ioc type for VirusTotal"}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return CTIResult{Provider: p.Name(), Error: err.Error()}, err
	}
	req.Header.Set("x-apikey", p.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return CTIResult{Provider: p.Name(), Error: err.Error()}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CTIResult{
			Provider: p.Name(),
			Error:    fmt.Sprintf("VirusTotal HTTP %d", resp.StatusCode),
		}, nil
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return CTIResult{Provider: p.Name(), Error: err.Error()}, err
	}

	var maliciousCount int
	var totalEngines int = 70

	if dataAttr, ok := data["data"].(map[string]interface{}); ok {
		if attrs, ok := dataAttr["attributes"].(map[string]interface{}); ok {
			if stats, ok := attrs["last_analysis_stats"].(map[string]interface{}); ok {
				if mal, ok := stats["malicious"].(float64); ok {
					maliciousCount = int(mal)
				}
				var sum float64
				for _, v := range stats {
					if vf, ok := v.(float64); ok {
						sum += vf
					}
				}
				if sum > 0 {
					totalEngines = int(sum)
				}
			}
		}
	}

	normalizedScore := math.Min(100, (float64(maliciousCount)/float64(totalEngines))*100.0)

	return CTIResult{
		Provider:       p.Name(),
		Score:          math.Round(normalizedScore*100) / 100,
		RawResponse:    data,
		MaliciousCount: maliciousCount,
	}, nil
}

func (p *VirusTotalProvider) deterministicMock(ioc string, iocType IOCType) CTIResult {
	// Generate deterministic response from hash of IOC string
	hasher := sha256.Sum256([]byte("VT:" + ioc))
	hexVal := hex.EncodeToString(hasher[:])
	seed := int(hasher[0])

	var maliciousCount int
	var totalEngines int = 72

	// Specific well-known IOC test patterns
	if strings.Contains(ioc, "118.25.6.39") || strings.Contains(ioc, "cobalt") || strings.Contains(ioc, "45.33.32.156") {
		maliciousCount = 58
	} else if strings.Contains(ioc, "198.51.100.42") || strings.Contains(ioc, "8.8.4.4") {
		maliciousCount = 14
	} else if strings.Contains(ioc, "192.168.") || strings.Contains(ioc, "10.0.") {
		maliciousCount = 0
	} else {
		maliciousCount = seed % 35
		if seed%5 == 0 {
			maliciousCount = 45 + (seed % 25)
		}
	}

	score := math.Min(100.0, (float64(maliciousCount)/float64(totalEngines))*100.0)

	return CTIResult{
		Provider:       p.Name(),
		Score:          math.Round(score*10) / 10,
		MaliciousCount: maliciousCount,
		RawResponse: map[string]interface{}{
			"scan_id":    hexVal[:16],
			"source":     "VirusTotal v3 Intelligence Feed (Simulated/Cached)",
			"positives":  maliciousCount,
			"total":      totalEngines,
			"scan_date":  time.Now().UTC().Format(time.RFC3339),
			"permalink":  fmt.Sprintf("https://www.virustotal.com/gui/search/%s", ioc),
			"reputation": 72 - (maliciousCount * 2),
		},
	}
}
