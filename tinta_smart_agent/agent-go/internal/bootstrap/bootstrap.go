package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/tinta-smart/agent/internal/config"
)

type BootstrapResult struct {
	DeviceID    string
	ClientID    string
	AccessToken string
	Hostname    string // ha-<clientId>.tinta-smart.de
}

// Run performs bootstrap: ensures device UID, generates key+CSR, calls API, saves certs and token.
func Run(cfg *config.Config, pairingCode string) (*BootstrapResult, error) {
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir data: %w", err)
	}

	deviceUid, err := readOrCreateDeviceUID(cfg.DeviceUIDPath())
	if err != nil {
		return nil, err
	}

	key, csrPem, err := loadOrCreateKeyAndCSR(cfg, deviceUid)
	if err != nil {
		return nil, err
	}

	body := fmt.Sprintf(`{"code":"%s","deviceUid":"%s","csrPem":%s}`,
		pairingCode, deviceUid, escapeJSON(csrPem))
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(cfg.APIBaseURL, "/")+"/device-registry/bootstrap", bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bootstrap request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bootstrap API %d: %s", resp.StatusCode, string(b))
	}

	var out struct {
		DeviceID    string `json:"deviceId"`
		ClientID    string `json:"clientId"`
		DeviceCertPem string `json:"deviceCertPem"`
		CACertPem   string `json:"caCertPem"`
		ExpiresAt   string `json:"expiresAt"`
		AccessToken string `json:"accessToken"`
	}
	if err := jsonDecode(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	keyPEM, err := pemEncodeKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfg.KeyPath(), keyPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfg.CertPath(), []byte(out.DeviceCertPem), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfg.CACertPath(), []byte(out.CACertPem), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfg.TokenPath(), []byte(out.AccessToken), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfg.DeviceIDPath(), []byte(out.DeviceID), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfg.ClientIDPath(), []byte(out.ClientID), 0600); err != nil {
		return nil, err
	}

	hostname := "ha-" + out.ClientID + ".tinta-smart.de"
	if err := os.WriteFile(cfg.HostnamePath(), []byte(hostname), 0600); err != nil {
		return nil, err
	}

	return &BootstrapResult{
		DeviceID:    out.DeviceID,
		ClientID:    out.ClientID,
		AccessToken: out.AccessToken,
		Hostname:    hostname,
	}, nil
}

func readOrCreateDeviceUID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	// Generate a stable UID (e.g. 32 hex chars)
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	uid := fmt.Sprintf("%x", buf)
	if err := os.WriteFile(path, []byte(uid), 0600); err != nil {
		return "", err
	}
	return uid, nil
}

func loadOrCreateKeyAndCSR(cfg *config.Config, deviceUid string) (*ecdsa.PrivateKey, string, error) {
	keyPath := cfg.KeyPath()
	key, err := loadKey(keyPath)
	if err == nil {
		csrPem, err := createCSR(key, deviceUid)
		if err != nil {
			return nil, "", err
		}
		return key, csrPem, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	csrPem, err := createCSR(key, deviceUid)
	if err != nil {
		return nil, "", err
	}
	return key, csrPem, nil
}

func jsonDecode(r io.Reader, v interface{}) error { return json.NewDecoder(r).Decode(v) }

func escapeJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func pemEncodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func createCSR(key *ecdsa.PrivateKey, deviceUid string) (string, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device:" + deviceUid},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}
</think>
Исправляю импорт pkix и добавляю простой JSON-декодер.
<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>
StrReplace