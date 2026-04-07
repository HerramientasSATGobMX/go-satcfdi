package sat_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
)

const fixturePassword = "password"

var fixedTime = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

func loadTestFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{"..", "testdata"}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func loadFixtureFiel(t *testing.T, keyFile string) *sat.Fiel {
	t.Helper()
	certDER := loadTestFile(t, "certs", "rsa_cert.der")
	keyDER := loadTestFile(t, "certs", keyFile)
	fiel, err := sat.NewFiel(certDER, keyDER, []byte(fixturePassword))
	if err != nil {
		t.Fatalf("NewFiel: %v", err)
	}
	return fiel
}

func newTestClient(server *httptest.Server) *sat.Client {
	return sat.NewClient(sat.Config{
		HTTPClient: server.Client(),
		Clock:      func() time.Time { return fixedTime },
		Endpoints: sat.Endpoints{
			AuthURL:       server.URL,
			SolicitaURL:   server.URL,
			VerificaURL:   server.URL,
			DescargaURL:   server.URL,
			ValidacionURL: server.URL,
		},
	})
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "testdata", "golden", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}

	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Fatalf("golden mismatch for %s\nwant:\n%s\n\ngot:\n%s", name, want, got)
	}
}

func newSOAPServer(t *testing.T, responseFile string, validate func(*http.Request, []byte)) *httptest.Server {
	t.Helper()
	responseBody := loadTestFile(t, "responses", responseFile)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if validate != nil {
			validate(r, body)
		}
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		_, _ = w.Write(responseBody)
	}))
}
