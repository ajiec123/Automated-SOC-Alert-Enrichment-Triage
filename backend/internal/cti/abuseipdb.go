package cti

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

type AbuseIPDBProvider struct {
	APIKey     string
	HTTPClient *http.Client
}

func NewAbuseIPDBProvider(apiKey string, timeout time.Duration) *AbuseIPDBProvider {
	return &AbuseIPDBProvider{
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: timeout},
	}
}

func (p *AbuseIPDBProvider) Name() string {
	return "AbuseIPDB"
}

func (p *AbuseIPDBProvider) Query(ctx context.Context, ioc string, iocType IOCType) (CTIResult, error) {
	cleanIOC := strings.TrimSpace(ioc)
	if cleanIOC == "" {
		return CTIResult{Provider: p.Name(), Error: "empty ioc"}, nil
	}

	if iocType != IOCTypeIP {
		return CTIResult{
			Provider: p.Name(),
			Score:    0,
			RawResponse: map[string]interface{}{
				"status": "Skipped - AbuseIPDB only analyzes IP addresses",
			},
		}, nil
	}

	if p.APIKey != "" && !strings.HasPrefix(p.APIKey, "${") {
		return p.queryRealAPI(ctx, cleanIOC)
	}

	return p.deterministicMock(cleanIOC), nil
}

func (p *AbuseIPDBProvider) queryRealAPI(ctx context.Context, ip string) (CTIResult, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return CTIResult{Provider: p.Name(), Error: err.Error()}, err
	}
	req.Header.Set("Key", p.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return CTIResult{Provider: p.Name(), Error: err.Error()}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CTIResult{
			Provider: p.Name(),
			Error:    fmt.Sprintf("AbuseIPDB HTTP %d", resp.StatusCode),
		}, nil
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return CTIResult{Provider: p.Name(), Error: err.Error()}, err
	}

	var confidenceScore float64
	if dataObj, ok := data["data"].(map[string]interface{}); ok {
		if score, ok := dataObj["abuseConfidenceScore"].(float64); ok {
			confidenceScore = score
		}
	}

	return CTIResult{
		Provider:        p.Name(),
		Score:           math.Round(confidenceScore*10) / 10,
		ConfidenceScore: int(confidenceScore),
		RawResponse:     data,
	}, nil
}

func (p *AbuseIPDBProvider) deterministicMock(ip string) CTIResult {
	hasher := sha256.Sum256([]byte("ABUSE:" + ip))
	seed := int(hasher[0])

	var confidenceScore int
	var countryCode string = "US"
	var isp string = "Cloudflare / Hosting Services"

	if strings.Contains(ip, "118.25.6.39") {
		confidenceScore = 96
		countryCode = "CN"
		isp = "Tencent Cloud Computing"
	} else if strings.Contains(ip, "198.51.100.42") {
		confidenceScore = 92
		countryCode = "RU"
		isp = "Selectel Net"
	} else if strings.Contains(ip, "192.168.") || strings.Contains(ip, "10.0.") {
		confidenceScore = 0
		countryCode = "LAN"
		isp = "Private RFC1918 Network"
	} else {
		confidenceScore = (seed % 65)
		if seed%4 == 0 {
			confidenceScore = 80 + (seed % 20)
		}
	}

	return CTIResult{
		Provider:        p.Name(),
		Score:           float64(confidenceScore),
		ConfidenceScore: confidenceScore,
		RawResponse: map[string]interface{}{
			"ipAddress":            ip,
			"isPublic":             !strings.HasPrefix(ip, "10.") && !strings.HasPrefix(ip, "192.168."),
			"ipVersion":            4,
			"isWhitelisted":        confidenceScore == 0,
			"abuseConfidenceScore": confidenceScore,
			"countryCode":          countryCode,
			"isp":                  isp,
			"totalReports":         confidenceScore * 7,
			"numDistinctUsers":     int(float64(confidenceScore) * 1.5),
			"lastReportedAt":       time.Now().UTC().Format(time.RFC3339),
		},
	}
}
