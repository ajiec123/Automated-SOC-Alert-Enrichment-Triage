package engine

import (
	"context"
	"siem-backend/internal/cti"
	"strings"
	"sync"
	"time"
)

type Orchestrator struct {
	providers []cti.CTIProvider
	timeout   time.Duration
}

func NewOrchestrator(providers []cti.CTIProvider, timeout time.Duration) *Orchestrator {
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	return &Orchestrator{
		providers: providers,
		timeout:   timeout,
	}
}

// ExtractIOCs gathers all indicators of compromise present in the alert payload
func ExtractIOCs(p *AlertPayload) []IOCItem {
	var items []IOCItem
	seen := make(map[string]bool)

	addIOC := func(t cti.IOCType, val string) {
		val = strings.TrimSpace(val)
		if val == "" || seen[val] {
			return
		}
		seen[val] = true
		items = append(items, IOCItem{Type: t, Value: val})
	}

	if p.SrcIP != "" {
		addIOC(cti.IOCTypeIP, p.SrcIP)
	}
	if p.DstIP != "" {
		addIOC(cti.IOCTypeIP, p.DstIP)
	}
	if p.FileHash != "" {
		addIOC(cti.IOCTypeHash, p.FileHash)
	}
	if p.Domain != "" {
		addIOC(cti.IOCTypeDomain, p.Domain)
	}

	if p.Indicators != nil {
		if ip, ok := p.Indicators["ip"]; ok && ip != "" {
			addIOC(cti.IOCTypeIP, ip)
		}
		if hash, ok := p.Indicators["hash"]; ok && hash != "" {
			addIOC(cti.IOCTypeHash, hash)
		}
		if domain, ok := p.Indicators["domain"]; ok && domain != "" {
			addIOC(cti.IOCTypeDomain, domain)
		}
	}

	return items
}

// EnrichIOCs queries all configured CTI providers concurrently across all IOCs
func (o *Orchestrator) EnrichIOCs(parentCtx context.Context, iocs []IOCItem) []cti.CTIResult {
	if len(iocs) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(parentCtx, o.timeout)
	defer cancel()

	resultsChan := make(chan cti.CTIResult, len(iocs)*len(o.providers))
	var wg sync.WaitGroup

	for _, item := range iocs {
		for _, provider := range o.providers {
			wg.Add(1)
			go func(p cti.CTIProvider, targetIOC IOCItem) {
				defer wg.Done()
				res, err := p.Query(ctx, targetIOC.Value, targetIOC.Type)
				if err != nil {
					resultsChan <- cti.CTIResult{
						Provider: p.Name(),
						Error:    err.Error(),
					}
					return
				}
				resultsChan <- res
			}(provider, item)
		}
	}

	wg.Wait()
	close(resultsChan)

	var aggregated []cti.CTIResult
	for res := range resultsChan {
		aggregated = append(aggregated, res)
	}

	return aggregated
}
