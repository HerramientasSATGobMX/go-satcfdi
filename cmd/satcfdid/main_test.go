package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunRequiresTLSByDefault(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "TLS es obligatorio por defecto") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestLoadTLSConfigEnforcesMTLSWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	caCertPEM, ca, caKey := generateCertificateAuthority(t)
	serverCertPEM, serverKeyPEM := generateLeafCertificate(t, ca, caKey, false)
	clientCertPEM, clientKeyPEM := generateLeafCertificate(t, ca, caKey, true)

	caPath := writePEMFile(t, dir, "ca.pem", caCertPEM)
	serverCertPath := writePEMFile(t, dir, "server-cert.pem", serverCertPEM)
	serverKeyPath := writePEMFile(t, dir, "server-key.pem", serverKeyPEM)
	clientCertPath := writePEMFile(t, dir, "client-cert.pem", clientCertPEM)
	clientKeyPath := writePEMFile(t, dir, "client-key.pem", clientKeyPEM)

	serverTLS, err := loadTLSConfig(serverCertPath, serverKeyPath, caPath, true)
	if err != nil {
		t.Fatalf("loadTLSConfig() error = %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewUnstartedServer(mux)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("AppendCertsFromPEM() = false")
	}

	noClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
	if _, err := noClient.Get(server.URL + "/healthz"); err == nil {
		t.Fatal("expected handshake failure without client certificate")
	}

	clientCertificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair() error = %v", err)
	}

	withClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      roots,
				Certificates: []tls.Certificate{clientCertificate},
			},
		},
	}

	resp, err := withClient.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("client with certificate error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func writePEMFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func generateCertificateAuthority(t *testing.T) ([]byte, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "satservice-test-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate, privateKey
}

func generateLeafCertificate(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, client bool) ([]byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("rand.Int() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "satservice-test-leaf",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.DNSNames = nil
		template.IPAddresses = nil
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca, &privateKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
}
