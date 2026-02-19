// Tinta Smart Device Agent - runs on client HA mini-PC (HAOS Add-on or Docker).
// Protocol: pairing code -> bootstrap (CSR -> cert + device JWT) -> heartbeat, telemetry, tunnel-status.
package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tinta-smart/agent/internal/api"
	"github.com/tinta-smart/agent/internal/bootstrap"
	"github.com/tinta-smart/agent/internal/config"
)

const (
	version   = "0.1.0"
	agentName = "tinta-smart-agent"
)

func main() {
	cfg := config.Load()

	doBootstrap := flag.Bool("bootstrap", false, "run bootstrap with pairing code from TINTA_PAIRING_CODE env")
	flag.Parse()

	if *doBootstrap {
		code := os.Getenv("TINTA_PAIRING_CODE")
		if code == "" {
			log.Fatal("TINTA_PAIRING_CODE is required for -bootstrap")
		}
		result, err := bootstrap.Run(cfg, code)
		if err != nil {
			log.Fatalf("bootstrap: %v", err)
		}
		log.Printf("Bootstrap OK: deviceId=%s clientId=%s hostname=%s", result.DeviceID, result.ClientID, result.Hostname)
		return
	}

	// Check that we have a token (already registered)
	client, err := api.NewFromEnv(cfg.APIBaseURL, cfg.TokenPath())
	if err != nil {
		log.Fatalf("No token found. Run with -bootstrap and TINTA_PAIRING_CODE=12345678 first: %v", err)
	}

	// Read hostname for tunnel-status
	hostname, _ := os.ReadFile(cfg.HostnamePath())
	hostnameStr := string(bytes.TrimSpace(hostname))

	ctx := signalContext()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	log.Printf("%s %s started; reporting every 60s", agentName, version)

	for {
		report(client, hostnameStr, cfg)
		select {
		case <-ctx:
			log.Println("shutdown")
			return
		case <-ticker.C:
		}
	}
}

func report(c *api.Client, hostname string, cfg *config.Config) {
	if err := c.Heartbeat(); err != nil {
		log.Printf("heartbeat: %v", err)
	}
	status := "unknown"
	status = "online"
	if err := c.TunnelStatus(&api.TunnelStatusPayload{
		Hostname: &hostname,
		Status:   status,
	}); err != nil {
		log.Printf("tunnel-status: %v", err)
	}
	if err := c.Telemetry(&api.TelemetryPayload{
		TunnelConnected: true,
	}); err != nil {
		log.Printf("telemetry: %v", err)
	}
}

func signalContext() <-chan struct{} {
	done := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		close(done)
	}()
	return done
}
