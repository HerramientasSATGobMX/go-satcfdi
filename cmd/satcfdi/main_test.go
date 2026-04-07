package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/zalando/go-keyring"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(help) code = %d", code)
	}
	if !strings.Contains(stdout.String(), "Comandos:") {
		t.Fatalf("unexpected help output: %s", stdout.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"nope"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run(nope) code = %d", code)
	}
	if !strings.Contains(stderr.String(), "comando desconocido") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestRunAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		_, _ = w.Write(loadTestFile(t, "responses", "auth_success.xml"))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"auth",
		"-cert", testPath("certs", "rsa_cert.der"),
		"-key", testPath("certs", "rsa_key_encrypted_pkcs8.der"),
		"-password", "password",
		"-auth-url", server.URL,
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(auth) code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"token": "test-token"`) {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunValidar(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		_, _ = w.Write(loadTestFile(t, "responses", "validacion_success.xml"))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"validar",
		"-validacion-url", server.URL,
		"-rfc-emisor", "AAA010101AAA",
		"-rfc-receptor", "BBB010101BBB",
		"-total", "1000.41",
		"-uuid", "11111111-2222-3333-4444-555555555555",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(validar) code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"Estado": "Vigente"`) {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunFlujo(t *testing.T) {
	server := newFlowServer(t)
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"flujo",
		"-cert", testPath("certs", "rsa_cert.der"),
		"-key", testPath("certs", "rsa_key_encrypted_pkcs8.der"),
		"-password", "password",
		"-auth-url", server.URL,
		"-solicita-url", server.URL,
		"-verifica-url", server.URL,
		"-descarga-url", server.URL,
		"-rfc-solicitante", "AAA010101AAA",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(flujo) code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"IDSolicitud": "REQ-FLOW-123"`) {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"ID": "PKG_01"`) {
		t.Fatalf("expected downloaded package in stdout: %s", stdout.String())
	}
}

func TestRunSolicitarRequiresValidDate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"solicitar",
		"-cert", testPath("certs", "rsa_cert.der"),
		"-key", testPath("certs", "rsa_key_encrypted_pkcs8.der"),
		"-password", "password",
		"-token", "token",
		"-rfc-solicitante", "AAA010101AAA",
		"-fecha-inicial", "bad-date",
		"-fecha-final", "2025-01-31",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run(solicitar invalid date) code = %d", code)
	}
	if !strings.Contains(stderr.String(), "fecha-inicial inválida") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestRunSolicitarDefaultsRecibidosToVigente(t *testing.T) {
	cliNow = func() time.Time {
		return time.Date(2026, 4, 5, 14, 30, 0, 0, time.UTC)
	}
	defer func() { cliNow = time.Now }()

	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		requestBody = string(body)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		_, _ = w.Write(loadTestFile(t, "responses", "solicita_recibidos_success.xml"))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"solicitar",
		"-cert", testPath("certs", "rsa_cert.der"),
		"-key", testPath("certs", "rsa_key_encrypted_pkcs8.der"),
		"-password", "password",
		"-solicita-url", server.URL,
		"-token", "manual-token",
		"-rfc-solicitante", "AAA010101AAA",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(solicitar) code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(requestBody, `FechaInicial="2026-04-01T00:00:00"`) {
		t.Fatalf("expected month-start default in request body, got %s", requestBody)
	}
	if !strings.Contains(requestBody, `FechaFinal="2026-04-05T00:00:00"`) {
		t.Fatalf("expected today default in request body, got %s", requestBody)
	}
	if !strings.Contains(requestBody, `EstadoComprobante="Vigente"`) {
		t.Fatalf("expected Vigente default for recibidos CFDI, got %s", requestBody)
	}
}

func TestRunShellExit(t *testing.T) {
	input := strings.Join([]string{
		testPath("certs", "rsa_cert.der"),
		testPath("certs", "rsa_key_encrypted_pkcs8.der"),
		"password",
		"AAA010101AAA",
		"exit",
		"",
	}, "\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"shell"}, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(shell exit) code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Shell interactiva de go-satcfdi") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Sesión terminada.") {
		t.Fatalf("shell did not exit cleanly: %s", stdout.String())
	}
}

func TestRunShellAuthThenContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		_, _ = io.WriteString(w, string(loadTestFile(t, "responses", "auth_success.xml")))
	}))
	defer server.Close()

	input := strings.Join([]string{
		testPath("certs", "rsa_cert.der"),
		testPath("certs", "rsa_key_encrypted_pkcs8.der"),
		"password",
		"AAA010101AAA",
		"auth",
		"context",
		"exit",
		"",
	}, "\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"shell", "-auth-url", server.URL}, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(shell auth) code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"token": "test-token"`) {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"has_token": true`) {
		t.Fatalf("expected session token in context: %s", stdout.String())
	}
}

func TestRunShellSolicitarDefaultsDateWindow(t *testing.T) {
	cliNow = func() time.Time {
		return time.Date(2026, 4, 5, 14, 30, 0, 0, time.UTC)
	}
	defer func() { cliNow = time.Now }()

	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		requestBody = string(body)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		_, _ = w.Write(loadTestFile(t, "responses", "solicita_recibidos_success.xml"))
	}))
	defer server.Close()

	input := strings.Join([]string{
		testPath("certs", "rsa_cert.der"),
		testPath("certs", "rsa_key_encrypted_pkcs8.der"),
		"password",
		"AAA010101AAA",
		"solicitar",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"exit",
		"",
	}, "\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"shell",
		"-solicita-url", server.URL,
		"-token", "manual-token",
	}, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(shell solicitar) code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(requestBody, `FechaInicial="2026-04-01T00:00:00"`) {
		t.Fatalf("expected FechaInicial month-start default in request body, got %s", requestBody)
	}
	if !strings.Contains(requestBody, `FechaFinal="2026-04-05T00:00:00"`) {
		t.Fatalf("expected FechaFinal default in request body, got %s", requestBody)
	}
	if !strings.Contains(requestBody, `EstadoComprobante="Vigente"`) {
		t.Fatalf("expected Vigente default in request body, got %s", requestBody)
	}
}

func TestRunShellFlujo(t *testing.T) {
	server := newFlowServer(t)
	defer server.Close()

	input := strings.Join([]string{
		testPath("certs", "rsa_cert.der"),
		testPath("certs", "rsa_key_encrypted_pkcs8.der"),
		"password",
		"AAA010101AAA",
		"flujo",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"exit",
		"",
	}, "\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"shell",
		"-auth-url", server.URL,
		"-solicita-url", server.URL,
		"-verifica-url", server.URL,
		"-descarga-url", server.URL,
	}, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(shell flujo) code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"IDSolicitud": "REQ-FLOW-123"`) {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"ID": "PKG_01"`) {
		t.Fatalf("expected downloaded package in stdout: %s", stdout.String())
	}
}

func TestRunShellTokenStoreOptIn(t *testing.T) {
	var deletedServices []string

	stubKeyring(t, func(service, user string) (string, error) {
		if service != keychainService {
			t.Fatalf("unexpected service on get: %s", service)
		}
		return "stored-token", nil
	}, func(service, user, value string) error {
		if service != keychainService {
			t.Fatalf("unexpected service on set: %s", service)
		}
		if value != "manual-token" {
			t.Fatalf("unexpected token value: %s", value)
		}
		return nil
	}, func(service, user string) error {
		if service != keychainService && service != legacyKeychainService {
			t.Fatalf("unexpected service on delete: %s", service)
		}
		deletedServices = append(deletedServices, service)
		return nil
	})

	input := strings.Join([]string{
		testPath("certs", "rsa_cert.der"),
		testPath("certs", "rsa_key_encrypted_pkcs8.der"),
		"password",
		"AAA010101AAA",
		"token save",
		"token load",
		"token clear",
		"exit",
		"",
	}, "\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"shell",
		"-token", "manual-token",
		"-token-store", "keychain",
	}, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(shell token-store) code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Token guardado para AAA010101AAA.") {
		t.Fatalf("expected save notice, got stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Token cargado para AAA010101AAA.") {
		t.Fatalf("expected load notice, got stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Token eliminado para AAA010101AAA.") {
		t.Fatalf("expected clear notice, got stdout=%s", stdout.String())
	}
	if !slices.Contains(deletedServices, keychainService) || !slices.Contains(deletedServices, legacyKeychainService) {
		t.Fatalf("expected token clear to cover current and legacy keychain services, got %v", deletedServices)
	}
}

func stubKeyring(
	t *testing.T,
	get func(service, user string) (string, error),
	set func(service, user, value string) error,
	del func(service, user string) error,
) {
	t.Helper()
	origGet, origSet, origDelete := keyringGet, keyringSet, keyringDelete
	t.Cleanup(func() {
		keyringGet = origGet
		keyringSet = origSet
		keyringDelete = origDelete
		cliNow = time.Now
	})
	keyringGet = get
	keyringSet = set
	keyringDelete = del
}

func loadTestFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func testPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

func TestTokenStoreScopeIncludesEndpoints(t *testing.T) {
	a, err := newTokenStore("keychain", sat.DefaultEndpoints())
	if err != nil {
		t.Fatalf("newTokenStore() error = %v", err)
	}
	b, err := newTokenStore("keychain", sat.Endpoints{
		AuthURL:       "https://example.test/auth",
		SolicitaURL:   sat.DefaultEndpoints().SolicitaURL,
		VerificaURL:   sat.DefaultEndpoints().VerificaURL,
		DescargaURL:   sat.DefaultEndpoints().DescargaURL,
		ValidacionURL: sat.DefaultEndpoints().ValidacionURL,
	})
	if err != nil {
		t.Fatalf("newTokenStore() error = %v", err)
	}
	if a.scope == b.scope {
		t.Fatalf("expected token store scope to change with endpoints")
	}
}

func TestTokenStoreLoadFallsBackToLegacyService(t *testing.T) {
	stubKeyring(t, func(service, user string) (string, error) {
		switch service {
		case keychainService:
			return "", keyring.ErrNotFound
		case legacyKeychainService:
			return "legacy-token", nil
		default:
			t.Fatalf("unexpected service on get: %s", service)
			return "", nil
		}
	}, func(service, user, value string) error {
		t.Fatalf("unexpected set on service %s", service)
		return nil
	}, func(service, user string) error {
		t.Fatalf("unexpected delete on service %s", service)
		return nil
	})

	store, err := newTokenStore("keychain", sat.DefaultEndpoints())
	if err != nil {
		t.Fatalf("newTokenStore() error = %v", err)
	}

	token, err := store.Load("AAA010101AAA")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if token != "legacy-token" {
		t.Fatalf("Load() token = %q, want legacy-token", token)
	}
}

func newFlowServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		switch action := r.Header.Get("SOAPAction"); {
		case strings.Contains(action, "Autentica"):
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><AutenticaResponse xmlns="http://DescargaMasivaTerceros.gob.mx"><AutenticaResult>flow-token</AutenticaResult></AutenticaResponse></s:Body></s:Envelope>`)
		case strings.Contains(action, "SolicitaDescarga"):
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><SolicitaDescargaRecibidosResponse xmlns="http://DescargaMasivaTerceros.sat.gob.mx"><SolicitaDescargaRecibidosResult IdSolicitud="REQ-FLOW-123" CodEstatus="5000" Mensaje="Solicitud Aceptada"></SolicitaDescargaRecibidosResult></SolicitaDescargaRecibidosResponse></s:Body></s:Envelope>`)
		case strings.Contains(action, "VerificaSolicitudDescarga"):
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><VerificaSolicitudDescargaResponse xmlns="http://DescargaMasivaTerceros.sat.gob.mx"><VerificaSolicitudDescargaResult CodEstatus="5000" EstadoSolicitud="3" CodigoEstadoSolicitud="5000" NumeroCFDIs="1" Mensaje="Solicitud Aceptada"><IdsPaquetes>PKG_01</IdsPaquetes></VerificaSolicitudDescargaResult></VerificaSolicitudDescargaResponse></s:Body></s:Envelope>`)
		case strings.Contains(action, "Descargar"):
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:h="http://DescargaMasivaTerceros.sat.gob.mx"><s:Header><h:respuesta CodEstatus="5000" Mensaje="Solicitud Aceptada"></h:respuesta></s:Header><s:Body><RespuestaDescargaMasivaTercerosSalida xmlns="http://DescargaMasivaTerceros.sat.gob.mx"><Paquete>WklQREFUQQ==</Paquete></RespuestaDescargaMasivaTercerosSalida></s:Body></s:Envelope>`)
		default:
			t.Fatalf("unexpected SOAPAction %q", action)
		}
	}))
}
