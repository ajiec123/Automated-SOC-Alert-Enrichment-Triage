package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type TelegramDispatcher struct {
	botToken        string
	chatID          string
	alertThreshold  float64
	enabled         bool
	httpClient      *http.Client
	recentDispatches []TelegramCardLog
	mu              sync.RWMutex
}

type TelegramCardLog struct {
	AlertUUID string    `json:"alert_uuid"`
	Score     float64   `json:"score"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
	SentToAPI bool      `json:"sent_to_api"`
}

type TelegramCallbackRequest struct {
	CallbackQueryID string `json:"callback_query_id"`
	AlertUUID       string `json:"alert_uuid"`
	Action          string `json:"action"` // block_ip, isolate_host, ignore_alert, dismiss
	Actor           string `json:"actor"`
	Notes           string `json:"notes,omitempty"`
}

func NewTelegramDispatcher(botToken, chatID string, threshold float64) *TelegramDispatcher {
	enabled := botToken != "" && !strings.HasPrefix(botToken, "${") &&
		chatID != "" && !strings.HasPrefix(chatID, "${")

	return &TelegramDispatcher{
		botToken:        botToken,
		chatID:          chatID,
		alertThreshold:  threshold,
		enabled:         enabled,
		httpClient:      &http.Client{Timeout: 5 * time.Second},
		recentDispatches: make([]TelegramCardLog, 0),
	}
}

func (t *TelegramDispatcher) DispatchAlert(alertUUID, source, eventType string, score float64, indicators []string, enrichmentSummary string) error {
	if score < t.alertThreshold {
		return nil
	}

	tier := "HIGH"
	icon := "⚠️"
	if score >= 80 {
		tier = "CRITICAL"
		icon = "🚨"
	}

	primaryIOC := "N/A"
	if len(indicators) > 0 {
		primaryIOC = indicators[0]
	}

	cardText := fmt.Sprintf(
		"%s *[%s ALERT] - Elevated Threat Score Detected*\n\n"+
			"*Alert UUID:* `%s`\n"+
			"*Score:* `%.1f / 100`\n"+
			"*Source:* `%s`\n"+
			"*Event:* %s\n"+
			"*Primary Indicator:* `%s`\n"+
			"*Enrichment:* %s\n",
		icon, tier, alertUUID, score, source, eventType, primaryIOC, enrichmentSummary,
	)

	// Keep in internal audit memory
	t.mu.Lock()
	t.recentDispatches = append([]TelegramCardLog{{
		AlertUUID: alertUUID,
		Score:     score,
		Text:      cardText,
		Timestamp: time.Now().UTC(),
		SentToAPI: t.enabled,
	}}, t.recentDispatches...)
	if len(t.recentDispatches) > 50 {
		t.recentDispatches = t.recentDispatches[:50]
	}
	t.mu.Unlock()

	log.Printf("[Telegram Dispatcher] Alert %s (Score: %.1f) prepared for Telegram notification", alertUUID, score)

	if !t.enabled {
		return nil
	}

	// Telegram Inline Keyboard format
	payload := map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       cardText,
		"parse_mode": "Markdown",
		"reply_markup": map[string]interface{}{
			"inline_keyboard": [][]map[string]string{
				{
					{"text": "🚫 Block IP", "callback_data": fmt.Sprintf("action:block_ip:%s", alertUUID)},
					{"text": "🛡️ Isolate Host", "callback_data": fmt.Sprintf("action:isolate_host:%s", alertUUID)},
					{"text": "❌ Ignore Alert", "callback_data": fmt.Sprintf("action:ignore_alert:%s", alertUUID)},
				},
			},
		},
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)
	resp, err := t.httpClient.Post(apiURL, "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		log.Printf("[Telegram Error] Failed to send message: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("[Telegram Error] API returned status %d", resp.StatusCode)
	}

	return nil
}

func (t *TelegramDispatcher) GetDispatches() []TelegramCardLog {
	t.mu.RLock()
	defer t.mu.RUnlock()
	copied := make([]TelegramCardLog, len(t.recentDispatches))
	copy(copied, t.recentDispatches)
	return copied
}
