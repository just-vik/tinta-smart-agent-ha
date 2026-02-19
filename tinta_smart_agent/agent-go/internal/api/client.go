package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type Client struct {
	BaseURL string
	Token   string
}

func NewFromEnv(baseURL, tokenPath string) (*Client, error) {
	if baseURL == "" {
		baseURL = os.Getenv("TINTA_API_BASE_URL")
	}
	if baseURL == "" {
		baseURL = "http://localhost:3000"
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, err
	}
	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		Token:   strings.TrimSpace(string(token)),
	}, nil
}

func (c *Client) do(method, path string, body interface{}, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API %s %d: %s", path, resp.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Heartbeat() error {
	return c.do(http.MethodPost, "/devices/heartbeat", nil, nil)
}

func (c *Client) Telemetry(payload *TelemetryPayload) error {
	return c.do(http.MethodPost, "/telemetry/push", payload, nil)
}

func (c *Client) TunnelStatus(payload *TunnelStatusPayload) error {
	return c.do(http.MethodPost, "/devices/tunnel-status", payload, nil)
}

type TelemetryPayload struct {
	AgentVersion        string  `json:"agentVersion,omitempty"`
	HomeAssistantVersion string `json:"homeAssistantVersion,omitempty"`
	TunnelConnected     bool    `json:"tunnelConnected"`
	UptimeSec           *int    `json:"uptimeSec,omitempty"`
	CPULoad1m           *float64 `json:"cpuLoad1m,omitempty"`
	MemUsedPercent      *float64 `json:"memUsedPercent,omitempty"`
	DiskUsedPercent     *float64 `json:"diskUsedPercent,omitempty"`
}

type TunnelStatusPayload struct {
	TunnelID *string `json:"tunnelId,omitempty"`
	Hostname *string `json:"hostname,omitempty"`
	Status   string  `json:"status"` // "online" | "offline" | "unknown"
}
