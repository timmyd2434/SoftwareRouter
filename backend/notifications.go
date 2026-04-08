package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

// --- Notification Configuration ---

const notificationConfigPath = "/etc/softrouter/notifications.json"

// NotificationConfig is the top-level config for all notification channels
type NotificationConfig struct {
	Enabled     bool            `json:"enabled"`
	MinSeverity string          `json:"min_severity"` // "critical", "warning", "info"
	CooldownMin int             `json:"cooldown_minutes"`
	Email       EmailConfig     `json:"email"`
	Webhooks    []WebhookConfig `json:"webhooks"`
}

// EmailConfig represents SMTP email notification settings
type EmailConfig struct {
	Enabled    bool   `json:"enabled"`
	SMTPServer string `json:"smtp_server"`
	SMTPPort   int    `json:"smtp_port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	From       string `json:"from"`
	To         string `json:"to"`
	UseTLS     bool   `json:"use_tls"`
}

// WebhookConfig represents a single webhook destination
type WebhookConfig struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"` // "discord", "slack", "generic"
}

// NotificationEvent is what gets dispatched to all channels
type NotificationEvent struct {
	Type      string    `json:"type"`      // "wan_state_change", "brute_force_detected", etc.
	Severity  string    `json:"severity"`  // "critical", "warning", "info"
	Title     string    `json:"title"`     // Short summary
	Details   string    `json:"details"`   // Longer description
	Timestamp time.Time `json:"timestamp"` // When it happened
}

// --- Globals ---

var (
	notifConfig     NotificationConfig
	notifConfigLock sync.RWMutex
	cooldownTracker sync.Map // map[eventType]time.Time — tracks last send per event type
)

// --- Init / Load / Save ---

func initNotifications() {
	loadNotificationConfig()
	log.Println("Notification system initialized")
}

func loadNotificationConfig() {
	notifConfigLock.Lock()
	defer notifConfigLock.Unlock()

	data, err := os.ReadFile(notificationConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Set defaults
			notifConfig = NotificationConfig{
				Enabled:     false,
				MinSeverity: "warning",
				CooldownMin: 5,
			}
			return
		}
		log.Printf("WARNING: Failed to load notification config: %v", err)
		return
	}

	if err := json.Unmarshal(data, &notifConfig); err != nil {
		log.Printf("WARNING: Failed to parse notification config: %v", err)
		notifConfig = NotificationConfig{
			Enabled:     false,
			MinSeverity: "warning",
			CooldownMin: 5,
		}
	}
}

func saveNotificationConfig() error {
	notifConfigLock.RLock()
	data, err := json.MarshalIndent(notifConfig, "", "  ")
	notifConfigLock.RUnlock()

	if err != nil {
		return err
	}

	if err := os.MkdirAll("/etc/softrouter", 0750); err != nil {
		return err
	}

	return os.WriteFile(notificationConfigPath, data, 0600)
}

// --- Severity Helpers ---

func severityLevel(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func severityEmoji(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "🔴"
	case "warning":
		return "🟡"
	case "info":
		return "🔵"
	default:
		return "⚪"
	}
}

func severityColor(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0xFF0000 // Red
	case "warning":
		return 0xFFAA00 // Orange
	case "info":
		return 0x00AAFF // Blue
	default:
		return 0x888888 // Grey
	}
}

// --- Core Dispatcher ---

// SendNotification dispatches an event to all enabled channels.
// This is the main entry point — call this from anywhere in the codebase.
func SendNotification(event NotificationEvent) {
	notifConfigLock.RLock()
	cfg := notifConfig
	notifConfigLock.RUnlock()

	if !cfg.Enabled {
		return
	}

	// Check severity threshold
	if severityLevel(event.Severity) < severityLevel(cfg.MinSeverity) {
		return
	}

	// Check cooldown
	cooldownKey := event.Type
	if lastSent, ok := cooldownTracker.Load(cooldownKey); ok {
		if time.Since(lastSent.(time.Time)) < time.Duration(cfg.CooldownMin)*time.Minute {
			log.Printf("[NOTIFY] Cooldown active for event type '%s', skipping", event.Type)
			return
		}
	}

	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Update cooldown tracker
	cooldownTracker.Store(cooldownKey, time.Now())

	// Dispatch to all channels asynchronously
	if cfg.Email.Enabled {
		go func() {
			if err := sendEmailNotification(event, cfg.Email); err != nil {
				log.Printf("[NOTIFY] Email send failed: %v", err)
			}
		}()
	}

	for _, wh := range cfg.Webhooks {
		if wh.Enabled {
			go func(webhook WebhookConfig) {
				if err := sendWebhookNotification(event, webhook); err != nil {
					log.Printf("[NOTIFY] Webhook '%s' send failed: %v", webhook.Name, err)
				}
			}(wh)
		}
	}
}

// --- Email Sending ---

func sendEmailNotification(event NotificationEvent, cfg EmailConfig) error {
	if cfg.SMTPServer == "" || cfg.To == "" {
		return fmt.Errorf("email not configured (missing SMTP server or recipient)")
	}

	subject := fmt.Sprintf("[SoftRouter %s] %s", strings.ToUpper(event.Severity), event.Title)
	body := fmt.Sprintf("Severity: %s\nEvent: %s\nTime: %s\n\n%s\n\n---\nSent by SoftRouter Notification System",
		strings.ToUpper(event.Severity),
		event.Title,
		event.Timestamp.Format("2006-01-02 15:04:05 MST"),
		event.Details,
	)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n%s",
		cfg.From, cfg.To, subject, body)

	addr := fmt.Sprintf("%s:%d", cfg.SMTPServer, cfg.SMTPPort)

	// Use STARTTLS for port 587, direct TLS for 465, plain for 25
	if cfg.SMTPPort == 465 {
		return sendEmailTLS(addr, cfg, []byte(msg))
	}

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPServer)
	}

	err := smtp.SendMail(addr, auth, cfg.From, []string{cfg.To}, []byte(msg))
	if err != nil {
		return fmt.Errorf("SMTP send failed: %w", err)
	}

	log.Printf("[NOTIFY] Email sent to %s: %s", cfg.To, event.Title)
	return nil
}

// sendEmailTLS handles direct TLS connections (port 465)
func sendEmailTLS(addr string, cfg EmailConfig, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: cfg.SMTPServer,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.SMTPServer)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer client.Quit() //nolint:errcheck

	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPServer)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %w", err)
		}
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(cfg.To); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA failed: %w", err)
	}
	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("SMTP write failed: %w", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("SMTP close failed: %w", err)
	}

	log.Printf("[NOTIFY] Email sent via TLS to %s", cfg.To)
	return nil
}

// --- Webhook Sending ---

func sendWebhookNotification(event NotificationEvent, wh WebhookConfig) error {
	var payload []byte
	var err error

	switch wh.Type {
	case "discord":
		payload, err = buildDiscordPayload(event)
	case "slack":
		payload, err = buildSlackPayload(event)
	default:
		payload, err = buildGenericPayload(event)
	}

	if err != nil {
		return fmt.Errorf("failed to build payload: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Post(wh.URL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	log.Printf("[NOTIFY] Webhook '%s' sent: %s", wh.Name, event.Title)
	return nil
}

func buildDiscordPayload(event NotificationEvent) ([]byte, error) {
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("%s %s", severityEmoji(event.Severity), event.Title),
				"description": event.Details,
				"color":       severityColor(event.Severity),
				"fields": []map[string]interface{}{
					{
						"name":   "Severity",
						"value":  strings.ToUpper(event.Severity),
						"inline": true,
					},
					{
						"name":   "Event Type",
						"value":  event.Type,
						"inline": true,
					},
				},
				"timestamp": event.Timestamp.Format(time.RFC3339),
				"footer": map[string]string{
					"text": "SoftRouter Notification System",
				},
			},
		},
	}
	return json.Marshal(payload)
}

func buildSlackPayload(event NotificationEvent) ([]byte, error) {
	payload := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("%s %s", severityEmoji(event.Severity), event.Title),
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": event.Details,
				},
			},
			{
				"type": "context",
				"elements": []map[string]string{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Severity:* %s | *Type:* %s | *Time:* %s",
							strings.ToUpper(event.Severity), event.Type,
							event.Timestamp.Format("15:04:05 MST")),
					},
				},
			},
		},
	}
	return json.Marshal(payload)
}

func buildGenericPayload(event NotificationEvent) ([]byte, error) {
	return json.Marshal(event)
}

// --- API Handlers ---

func getNotificationConfig(w http.ResponseWriter, r *http.Request) {
	notifConfigLock.RLock()
	cfg := notifConfig
	notifConfigLock.RUnlock()

	// Mask email password for security
	if cfg.Email.Password != "" {
		cfg.Email.Password = "••••••••"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func updateNotificationConfig(w http.ResponseWriter, r *http.Request) {
	var newCfg NotificationConfig
	if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Preserve existing password if masked value was sent back
	notifConfigLock.RLock()
	oldPassword := notifConfig.Email.Password
	notifConfigLock.RUnlock()

	if newCfg.Email.Password == "••••••••" {
		newCfg.Email.Password = oldPassword
	}

	// Set defaults
	if newCfg.CooldownMin <= 0 {
		newCfg.CooldownMin = 5
	}
	if newCfg.MinSeverity == "" {
		newCfg.MinSeverity = "warning"
	}

	// Assign IDs to new webhooks
	for i := range newCfg.Webhooks {
		if newCfg.Webhooks[i].ID == "" {
			newCfg.Webhooks[i].ID = fmt.Sprintf("wh_%d", time.Now().UnixNano())
		}
	}

	notifConfigLock.Lock()
	notifConfig = newCfg
	notifConfigLock.Unlock()

	if err := saveNotificationConfig(); err != nil {
		log.Printf("ERROR: Failed to save notification config: %v", err)
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	logAuditEvent(getUsernameFromToken(r), "notifications.config.update", "system",
		"{\"status\":\"success\"}", getClientIP(r), true)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func sendTestNotification(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Channel string `json:"channel"` // "email", "webhook"
		ID      string `json:"id"`      // Webhook ID (if channel is "webhook")
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	testEvent := NotificationEvent{
		Type:      "test",
		Severity:  "info",
		Title:     "Test Notification from SoftRouter",
		Details:   "This is a test notification. If you received this, your notification channel is configured correctly!",
		Timestamp: time.Now(),
	}

	notifConfigLock.RLock()
	cfg := notifConfig
	notifConfigLock.RUnlock()

	var sendErr error

	switch req.Channel {
	case "email":
		if !cfg.Email.Enabled {
			http.Error(w, "Email notifications are not enabled", http.StatusBadRequest)
			return
		}
		sendErr = sendEmailNotification(testEvent, cfg.Email)

	case "webhook":
		found := false
		for _, wh := range cfg.Webhooks {
			if wh.ID == req.ID {
				found = true
				sendErr = sendWebhookNotification(testEvent, wh)
				break
			}
		}
		if !found {
			http.Error(w, "Webhook not found", http.StatusNotFound)
			return
		}

	default:
		http.Error(w, "Invalid channel. Use 'email' or 'webhook'", http.StatusBadRequest)
		return
	}

	if sendErr != nil {
		log.Printf("[NOTIFY] Test send failed: %v", sendErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"error":  sendErr.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "sent"})
}
