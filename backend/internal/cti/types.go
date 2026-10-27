package cti

import (
	"context"
)

type IOCType string

const (
	IOCTypeIP     IOCType = "IP"
	IOCTypeHash   IOCType = "HASH"
	IOCTypeDomain IOCType = "DOMAIN"
)

type CTIResult struct {
	Provider        string                 `json:"provider"`
	Score           float64                `json:"score"` // Normalized 0-100
	RawResponse     map[string]interface{} `json:"raw_response"`
	MaliciousCount  int                    `json:"malicious_count,omitempty"`
	ConfidenceScore int                    `json:"confidence_score,omitempty"`
	OpenPorts       []int                  `json:"open_ports,omitempty"`
	Vulnerabilities []string               `json:"vulnerabilities,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

type CTIProvider interface {
	Name() string
	Query(ctx context.Context, ioc string, iocType IOCType) (CTIResult, error)
}
