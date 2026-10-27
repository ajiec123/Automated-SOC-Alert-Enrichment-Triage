package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	httpHandler "siem-backend/internal/api/http"
	wsHandler "siem-backend/internal/api/websocket"
	"siem-backend/internal/cti"
	"siem-backend/internal/engine"
	"siem-backend/internal/notifier"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port           int      `yaml:"port"`
		Env            string   `yaml:"env"`
		LogLevel       string   `yaml:"log_level"`
		AllowedOrigins []string `yaml:"allowed_origins"`
	} `yaml:"server"`

	Scoring engine.ScorerConfig `yaml:"scoring"`

	CTI struct {
		VirusTotal struct {
			Enabled   bool   `yaml:"enabled"`
			APIKey    string `yaml:"api_key"`
			TimeoutMS int    `yaml:"timeout_ms"`
		} `yaml:"virustotal"`
		AbuseIPDB struct {
			Enabled   bool   `yaml:"enabled"`
			APIKey    string `yaml:"api_key"`
			TimeoutMS int    `yaml:"timeout_ms"`
		} `yaml:"abuseipdb"`
		Shodan struct {
			Enabled   bool   `yaml:"enabled"`
			APIKey    string `yaml:"api_key"`
			TimeoutMS int    `yaml:"timeout_ms"`
		} `yaml:"shodan"`
	} `yaml:"cti"`

	Telegram struct {
		Enabled        bool    `yaml:"enabled"`
		BotToken       string  `yaml:"bot_token"`
		ChatID         string  `yaml:"chat_id"`
		AlertThreshold float64 `yaml:"alert_threshold"`
	} `yaml:"telegram"`
}

func loadConfig() (*Config, error) {
	cfg := &Config{}

	// Defaults
	cfg.Server.Port = 8080
	cfg.Server.Env = "development"
	cfg.Telegram.AlertThreshold = 60.0
	cfg.CTI.VirusTotal.TimeoutMS = 2500
	cfg.CTI.AbuseIPDB.TimeoutMS = 2500
	cfg.CTI.Shodan.TimeoutMS = 2500

	configPaths := []string{
		"config/config.yaml",
		"backend/config/config.yaml",
		filepath.Join(".", "config", "config.yaml"),
	}

	for _, p := range configPaths {
		if data, err := os.ReadFile(p); err == nil {
			if err := yaml.Unmarshal(data, cfg); err == nil {
				log.Printf("[Config] Loaded configuration from %s", p)
				break
			}
		}
	}

	// Environment variable overrides
	if p := os.Getenv("PORT"); p != "" {
		if pInt, err := strconv.Atoi(p); err == nil {
			cfg.Server.Port = pInt
		}
	}
	if vtKey := os.Getenv("VIRUSTOTAL_API_KEY"); vtKey != "" {
		cfg.CTI.VirusTotal.APIKey = vtKey
	}
	if abuseKey := os.Getenv("ABUSEIPDB_API_KEY"); abuseKey != "" {
		cfg.CTI.AbuseIPDB.APIKey = abuseKey
	}
	if shodanKey := os.Getenv("SHODAN_API_KEY"); shodanKey != "" {
		cfg.CTI.Shodan.APIKey = shodanKey
	}
	if tgToken := os.Getenv("TELEGRAM_BOT_TOKEN"); tgToken != "" {
		cfg.Telegram.BotToken = tgToken
	}
	if tgChat := os.Getenv("TELEGRAM_CHAT_ID"); tgChat != "" {
		cfg.Telegram.ChatID = tgChat
	}

	return cfg, nil
}

func main() {
	log.Println("================================================================")
	log.Println(" Automated SOC Alert Enrichment & Triage Platform (Go Core Engine)")
	log.Println("================================================================")

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to initialize configuration: %v", err)
	}

	// Initialize CTI Providers
	vtTimeout := time.Duration(cfg.CTI.VirusTotal.TimeoutMS) * time.Millisecond
	abuseTimeout := time.Duration(cfg.CTI.AbuseIPDB.TimeoutMS) * time.Millisecond
	shodanTimeout := time.Duration(cfg.CTI.Shodan.TimeoutMS) * time.Millisecond

	providers := []cti.CTIProvider{
		cti.NewVirusTotalProvider(cfg.CTI.VirusTotal.APIKey, vtTimeout),
		cti.NewAbuseIPDBProvider(cfg.CTI.AbuseIPDB.APIKey, abuseTimeout),
		cti.NewShodanProvider(cfg.CTI.Shodan.APIKey, shodanTimeout),
	}

	// Initialize Orchestrator & Scorer
	orchestrator := engine.NewOrchestrator(providers, 2500*time.Millisecond)
	scorer := engine.NewThreatScorer(cfg.Scoring)

	// Initialize Telegram Dispatcher
	telegram := notifier.NewTelegramDispatcher(
		cfg.Telegram.BotToken,
		cfg.Telegram.ChatID,
		cfg.Telegram.AlertThreshold,
	)

	// Initialize WebSocket Hub
	hub := wsHandler.NewHub()
	go hub.Run()

	// Initialize API Handler with 10 async ingestion workers
	handler := httpHandler.NewAPIHandler(
		orchestrator,
		scorer,
		telegram,
		hub,
		1000,
		10,
	)

	// Set Gin mode
	if strings.ToLower(cfg.Server.Env) == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())

	// Custom Logger
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[HTTP] %s | %3d | %13v | %15s | %-7s %s\n",
			param.TimeStamp.Format("2006/01/02 15:04:05"),
			param.StatusCode,
			param.Latency,
			param.ClientIP,
			param.Method,
			param.Path,
		)
	}))

	// CORS Setup
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Health check endpoints
	router.GET("/health", handler.HealthCheck)
	router.GET("/api/v1/health", handler.HealthCheck)

	// Ingestion & Triage API Endpoints
	v1 := router.Group("/api/v1")
	{
		v1.POST("/alerts/ingest", handler.IngestAlert)
		v1.GET("/alerts", handler.GetAlerts)
		v1.POST("/alerts/simulate", handler.SimulateAlert)
		v1.POST("/triage", handler.TriageAction)
		v1.POST("/telegram/callback", handler.TelegramCallback)
		v1.GET("/telegram/dispatches", handler.GetTelegramDispatches)
	}

	// Real-time WebSocket Endpoint
	router.GET("/ws/alerts", func(c *gin.Context) {
		wsHandler.ServeWs(hub, c.Writer, c.Request)
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("[Server] Ingestion & SOAR Middleware running on port :%d", cfg.Server.Port)
		log.Printf("[Server] WebSocket stream live at ws://localhost:%d/ws/alerts", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server listen failed: %v", err)
		}
	}()

	// Graceful shutdown handling
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[Server] Gracefully shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("[Server] Forced shutdown: %v", err)
	}

	log.Println("[Server] SOAR engine cleanly exited")
}
