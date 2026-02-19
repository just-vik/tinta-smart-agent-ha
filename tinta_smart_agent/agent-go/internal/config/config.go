package config

import (
	"os"
	"path/filepath"
)

type Config struct {
	APIBaseURL string
	DataDir    string
	HAHost     string // e.g. "homeassistant" or "127.0.0.1"
	HAPort     string // e.g. "8123"
}

func Load() *Config {
	dataDir := os.Getenv("TINTA_DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}
	apiBase := os.Getenv("TINTA_API_BASE_URL")
	if apiBase == "" {
		apiBase = "http://localhost:3000"
	}
	haHost := os.Getenv("HA_HOST")
	if haHost == "" {
		haHost = "homeassistant"
	}
	haPort := os.Getenv("HA_PORT")
	if haPort == "" {
		haPort = "8123"
	}
	return &Config{
		APIBaseURL: apiBase,
		DataDir:    dataDir,
		HAHost:     haHost,
		HAPort:     haPort,
	}
}

func (c *Config) DeviceUIDPath() string   { return filepath.Join(c.DataDir, "device_uid") }
func (c *Config) KeyPath() string        { return filepath.Join(c.DataDir, "device.key") }
func (c *Config) CertPath() string       { return filepath.Join(c.DataDir, "device.pem") }
func (c *Config) CACertPath() string     { return filepath.Join(c.DataDir, "ca.pem") }
func (c *Config) TokenPath() string      { return filepath.Join(c.DataDir, "access_token") }
func (c *Config) ClientIDPath() string   { return filepath.Join(c.DataDir, "client_id") }
func (c *Config) DeviceIDPath() string   { return filepath.Join(c.DataDir, "device_id") }
func (c *Config) HostnamePath() string   { return filepath.Join(c.DataDir, "hostname") }
func (c *Config) TunnelCredsPath() string { return filepath.Join(c.DataDir, "tunnel_credentials.json") }
