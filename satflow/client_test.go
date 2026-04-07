package satflow_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

const fixturePassword = "password"

var fixedTime = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

func TestRunEndToEndDecodesPackages(t *testing.T) {
	fiel := loadFixtureFiel(t)

	var mu sync.Mutex
	authCalls := 0
	verifyCalls := 0
	downloaded := []string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		switch action := r.Header.Get("SOAPAction"); {
		case strings.Contains(action, "Autentica"):
			mu.Lock()
			authCalls++
			mu.Unlock()
			writeXML(w, http.StatusOK, authResponse("token-1"))
		case strings.Contains(action, "SolicitaDescarga"):
			if got := r.Header.Get("Authorization"); got != `WRAP access_token="token-1"` {
				t.Fatalf("Authorization = %q", got)
			}
			writeXML(w, http.StatusOK, consultaResponse("REQ-1"))
		case strings.Contains(action, "VerificaSolicitudDescarga"):
			if got := r.Header.Get("Authorization"); got != `WRAP access_token="token-1"` {
				t.Fatalf("Authorization = %q", got)
			}
			mu.Lock()
			verifyCalls++
			call := verifyCalls
			mu.Unlock()
			if call == 1 {
				writeXML(w, http.StatusOK, verifyResponse(sat.EstadoSolicitudEnProceso, "En proceso"))
				return
			}
			writeXML(w, http.StatusOK, verifyResponse(sat.EstadoSolicitudTerminada, "Solicitud Aceptada", "PKG_01", "PKG_02"))
		case strings.Contains(action, "Descargar"):
			packageID := packageIDFromBody(string(body))
			mu.Lock()
			downloaded = append(downloaded, packageID)
			mu.Unlock()
			writeXML(w, http.StatusOK, descargaResponse(packageID, "zip:"+packageID))
		default:
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{
		Poll: satflow.PollPolicy{
			Interval:    time.Millisecond,
			MaxAttempts: 3,
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})

	result, err := flow.Run(context.Background(), satflow.DownloadRequest{
		FechaInicial:      time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
		FechaFinal:        time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		TipoDescarga:      sat.TipoDescargaRecibidos,
		TipoSolicitud:     sat.TipoSolicitudCFDI,
		EstadoComprobante: sat.EstadoComprobanteVigente,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Solicitud == nil || result.Solicitud.IDSolicitud != "REQ-1" {
		t.Fatalf("unexpected solicitud: %+v", result.Solicitud)
	}
	if result.Verificacion == nil || len(result.Verificacion.Paquetes) != 2 {
		t.Fatalf("unexpected verificacion: %+v", result.Verificacion)
	}
	if len(result.Packages) != 2 {
		t.Fatalf("len(Packages) = %d", len(result.Packages))
	}
	if got := string(result.Packages[0].Bytes); got != "zip:PKG_01" {
		t.Fatalf("first package bytes = %q", got)
	}
	if result.Packages[0].Base64 == "" {
		t.Fatal("expected package base64 to be preserved")
	}

	mu.Lock()
	defer mu.Unlock()
	if authCalls != 1 {
		t.Fatalf("authCalls = %d, want 1", authCalls)
	}
	if verifyCalls != 2 {
		t.Fatalf("verifyCalls = %d, want 2", verifyCalls)
	}
	if strings.Join(downloaded, ",") != "PKG_01,PKG_02" {
		t.Fatalf("downloaded = %v", downloaded)
	}
}

func TestAuthenticateRefreshesBeforeExpiry(t *testing.T) {
	fiel := loadFixtureFiel(t)

	var mu sync.Mutex
	authCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("SOAPAction"), "Autentica") {
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
		mu.Lock()
		authCalls++
		token := fmt.Sprintf("token-%d", authCalls)
		mu.Unlock()
		writeXML(w, http.StatusOK, authResponse(token))
	}))
	defer server.Close()

	now := fixedTime
	flow := newFlowClient(t, fiel, server, func() time.Time { return now }, satflow.Config{
		TokenTTL:      2 * time.Minute,
		RefreshBefore: 30 * time.Second,
	})

	token1, err := flow.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate() first error = %v", err)
	}
	if token1.Value != "token-1" {
		t.Fatalf("Authenticate() first = %q", token1.Value)
	}

	now = fixedTime.Add(80 * time.Second)
	token2, err := flow.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate() second error = %v", err)
	}
	if token2.Value != "token-1" {
		t.Fatalf("Authenticate() second = %q, want token-1", token2.Value)
	}

	now = fixedTime.Add(95 * time.Second)
	token3, err := flow.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate() third error = %v", err)
	}
	if token3.Value != "token-2" {
		t.Fatalf("Authenticate() third = %q, want token-2", token3.Value)
	}

	mu.Lock()
	defer mu.Unlock()
	if authCalls != 2 {
		t.Fatalf("authCalls = %d, want 2", authCalls)
	}
}

func TestAuthenticateUsesCacheAndSkipsHTTP(t *testing.T) {
	fiel := loadFixtureFiel(t)

	cache := &stubTokenCache{
		loadToken: satflow.AccessToken{
			Value:      "cached-token",
			ObtainedAt: fixedTime,
			ExpiresAt:  fixedTime.Add(time.Minute),
		},
		loadOK: true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected network call with cached token: %s", r.Header.Get("SOAPAction"))
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{
		TokenCache: cache,
	})

	token, err := flow.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if token.Value != "cached-token" {
		t.Fatalf("Authenticate() = %q", token.Value)
	}
	if cache.loadCalls != 1 {
		t.Fatalf("cache.loadCalls = %d", cache.loadCalls)
	}
	if cache.storeCalls != 0 {
		t.Fatalf("cache.storeCalls = %d", cache.storeCalls)
	}
}

func TestAuthenticateConcurrentOnlyAuthenticatesOnce(t *testing.T) {
	fiel := loadFixtureFiel(t)

	var mu sync.Mutex
	authCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("SOAPAction"), "Autentica") {
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		authCalls++
		mu.Unlock()
		writeXML(w, http.StatusOK, authResponse("shared-token"))
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{})

	var wg sync.WaitGroup
	errCh := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := flow.Authenticate(context.Background())
			if err != nil {
				errCh <- err
				return
			}
			if token.Value != "shared-token" {
				errCh <- fmt.Errorf("token.Value = %q", token.Value)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("Authenticate() concurrent error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if authCalls != 1 {
		t.Fatalf("authCalls = %d, want 1", authCalls)
	}
}

func TestAuthenticateReturnsCacheLoadError(t *testing.T) {
	fiel := loadFixtureFiel(t)
	wantErr := errors.New("cache load failed")

	flow := newFlowClient(t, fiel, newNoopServer(t), func() time.Time { return fixedTime }, satflow.Config{
		TokenCache: &stubTokenCache{loadErr: wantErr},
	})

	_, err := flow.Authenticate(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected cache load error, got %v", err)
	}
}

func TestAuthenticateReturnsCacheStoreError(t *testing.T) {
	fiel := loadFixtureFiel(t)
	wantErr := errors.New("cache store failed")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeXML(w, http.StatusOK, authResponse("token-1"))
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{
		TokenCache: &stubTokenCache{storeErr: wantErr},
	})

	_, err := flow.Authenticate(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected cache store error, got %v", err)
	}
}

func TestSubmitRetriesTransientSOAPFault(t *testing.T) {
	fiel := loadFixtureFiel(t)
	soapFault := string(loadTestFile(t, "responses", "soap_fault.xml"))

	var mu sync.Mutex
	consultaCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch action := r.Header.Get("SOAPAction"); {
		case strings.Contains(action, "Autentica"):
			writeXML(w, http.StatusOK, authResponse("token-1"))
		case strings.Contains(action, "SolicitaDescarga"):
			mu.Lock()
			consultaCalls++
			call := consultaCalls
			mu.Unlock()
			if call == 1 {
				writeXML(w, http.StatusInternalServerError, soapFault)
				return
			}
			writeXML(w, http.StatusOK, consultaResponse("REQ-2"))
		default:
			t.Fatalf("unexpected SOAPAction %q", action)
		}
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{
		Retry: satflow.RetryPolicy{
			MaxAttempts:    2,
			InitialBackoff: time.Millisecond,
			MaxBackoff:     time.Millisecond,
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})

	resp, err := flow.Submit(context.Background(), satflow.DownloadRequest{
		FechaInicial:      time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
		FechaFinal:        time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		TipoDescarga:      sat.TipoDescargaRecibidos,
		TipoSolicitud:     sat.TipoSolicitudCFDI,
		EstadoComprobante: sat.EstadoComprobanteVigente,
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if resp == nil || resp.IDSolicitud != "REQ-2" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	mu.Lock()
	defer mu.Unlock()
	if consultaCalls != 2 {
		t.Fatalf("consultaCalls = %d, want 2", consultaCalls)
	}
}

func TestVerifyRefreshes401SOAPFault(t *testing.T) {
	fiel := loadFixtureFiel(t)

	var mu sync.Mutex
	authCalls := 0
	verifyCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch action := r.Header.Get("SOAPAction"); {
		case strings.Contains(action, "Autentica"):
			mu.Lock()
			authCalls++
			token := fmt.Sprintf("token-%d", authCalls)
			mu.Unlock()
			writeXML(w, http.StatusOK, authResponse(token))
		case strings.Contains(action, "VerificaSolicitudDescarga"):
			mu.Lock()
			verifyCalls++
			mu.Unlock()
			if got := r.Header.Get("Authorization"); got == `WRAP access_token="token-1"` {
				writeXML(w, http.StatusUnauthorized, soapFaultResponse("Token expired"))
				return
			}
			if got := r.Header.Get("Authorization"); got != `WRAP access_token="token-2"` {
				t.Fatalf("Authorization = %q", got)
			}
			writeXML(w, http.StatusOK, verifyResponse(sat.EstadoSolicitudTerminada, "Solicitud Aceptada", "PKG_99"))
		default:
			t.Fatalf("unexpected SOAPAction %q", action)
		}
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{})

	resp, err := flow.Verify(context.Background(), "REQ-4")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if resp == nil || resp.EstadoSolicitud != sat.EstadoSolicitudTerminada {
		t.Fatalf("unexpected response: %+v", resp)
	}

	mu.Lock()
	defer mu.Unlock()
	if authCalls != 2 {
		t.Fatalf("authCalls = %d, want 2", authCalls)
	}
	if verifyCalls != 2 {
		t.Fatalf("verifyCalls = %d, want 2", verifyCalls)
	}
}

func TestWaitReturnsPollExceededError(t *testing.T) {
	fiel := loadFixtureFiel(t)

	verifyCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.Header.Get("SOAPAction"), "Autentica"):
			writeXML(w, http.StatusOK, authResponse("token-1"))
		case strings.Contains(r.Header.Get("SOAPAction"), "VerificaSolicitudDescarga"):
			verifyCalls++
			writeXML(w, http.StatusOK, verifyResponse(sat.EstadoSolicitudEnProceso, "En proceso"))
		default:
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{
		Poll: satflow.PollPolicy{
			Interval:    time.Millisecond,
			MaxAttempts: 2,
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})

	resp, err := flow.WaitForCompletion(context.Background(), "REQ-3")
	if err == nil {
		t.Fatal("WaitForCompletion() error = nil, want error")
	}
	if !errors.Is(err, satflow.ErrPollExceeded) {
		t.Fatalf("expected ErrPollExceeded, got %v", err)
	}

	var pollErr *satflow.PollExceededError
	if !errors.As(err, &pollErr) {
		t.Fatalf("expected PollExceededError, got %T", err)
	}
	if pollErr.Attempts != 2 {
		t.Fatalf("pollErr.Attempts = %d", pollErr.Attempts)
	}
	if resp == nil || resp.EstadoSolicitud != sat.EstadoSolicitudEnProceso {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if verifyCalls != 2 {
		t.Fatalf("verifyCalls = %d, want 2", verifyCalls)
	}
}

func TestWaitReturnsTerminalStatusError(t *testing.T) {
	fiel := loadFixtureFiel(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.Header.Get("SOAPAction"), "Autentica"):
			writeXML(w, http.StatusOK, authResponse("token-1"))
		case strings.Contains(r.Header.Get("SOAPAction"), "VerificaSolicitudDescarga"):
			writeXML(w, http.StatusOK, verifyResponse(sat.EstadoSolicitudRechazada, "Solicitud rechazada"))
		default:
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{})

	resp, err := flow.Wait(context.Background(), "REQ-5")
	if err == nil {
		t.Fatal("Wait() error = nil, want error")
	}
	if !errors.Is(err, satflow.ErrTerminalStatus) {
		t.Fatalf("expected ErrTerminalStatus, got %v", err)
	}
	if resp == nil || resp.EstadoSolicitud != sat.EstadoSolicitudRechazada {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestWaitPropagatesContextCancellation(t *testing.T) {
	fiel := loadFixtureFiel(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.Header.Get("SOAPAction"), "Autentica"):
			writeXML(w, http.StatusOK, authResponse("token-1"))
		case strings.Contains(r.Header.Get("SOAPAction"), "VerificaSolicitudDescarga"):
			writeXML(w, http.StatusOK, verifyResponse(sat.EstadoSolicitudEnProceso, "En proceso"))
		default:
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{
		Sleep: func(context.Context, time.Duration) error { return context.Canceled },
	})

	_, err := flow.Wait(context.Background(), "REQ-6")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestFetchPackageReturnsInvalidPayloadError(t *testing.T) {
	fiel := loadFixtureFiel(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.Header.Get("SOAPAction"), "Autentica"):
			writeXML(w, http.StatusOK, authResponse("token-1"))
		case strings.Contains(r.Header.Get("SOAPAction"), "Descargar"):
			writeXML(w, http.StatusOK, invalidDescargaResponse("%%%"))
		default:
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
	}))
	defer server.Close()

	flow := newFlowClient(t, fiel, server, func() time.Time { return fixedTime }, satflow.Config{})

	_, err := flow.FetchPackage(context.Background(), "PKG_BAD")
	if err == nil {
		t.Fatal("FetchPackage() error = nil, want error")
	}
	if !errors.Is(err, satflow.ErrInvalidPackagePayload) {
		t.Fatalf("expected ErrInvalidPackagePayload, got %v", err)
	}

	var payloadErr *satflow.InvalidPackagePayloadError
	if !errors.As(err, &payloadErr) {
		t.Fatalf("expected InvalidPackagePayloadError, got %T", err)
	}
	if payloadErr.PackageID != "PKG_BAD" {
		t.Fatalf("payloadErr.PackageID = %q", payloadErr.PackageID)
	}
}

func newFlowClient(
	t *testing.T,
	fiel *sat.Fiel,
	server *httptest.Server,
	clock func() time.Time,
	overrides satflow.Config,
) *satflow.Client {
	t.Helper()

	core := sat.NewClient(sat.Config{
		HTTPClient: server.Client(),
		Clock:      clock,
		Endpoints: sat.Endpoints{
			AuthURL:       server.URL,
			SolicitaURL:   server.URL,
			VerificaURL:   server.URL,
			DescargaURL:   server.URL,
			ValidacionURL: server.URL,
		},
	})

	cfg := overrides
	cfg.Client = core
	cfg.Fiel = fiel
	cfg.RFCSolicitante = "AAA010101AAA"
	if cfg.Clock == nil {
		cfg.Clock = clock
	}

	flow, err := satflow.New(cfg)
	if err != nil {
		t.Fatalf("satflow.New() error = %v", err)
	}
	return flow
}

func newNoopServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request: %s", r.Header.Get("SOAPAction"))
	}))
}

type stubTokenCache struct {
	loadToken  satflow.AccessToken
	loadOK     bool
	loadErr    error
	storeErr   error
	clearErr   error
	loadCalls  int
	storeCalls int
	clearCalls int
}

func (s *stubTokenCache) Load(context.Context) (satflow.AccessToken, bool, error) {
	s.loadCalls++
	if s.loadErr != nil {
		return satflow.AccessToken{}, false, s.loadErr
	}
	return s.loadToken, s.loadOK, nil
}

func (s *stubTokenCache) Store(_ context.Context, token satflow.AccessToken) error {
	s.storeCalls++
	if s.storeErr != nil {
		return s.storeErr
	}
	s.loadToken = token
	s.loadOK = true
	return nil
}

func (s *stubTokenCache) Clear(context.Context) error {
	s.clearCalls++
	if s.clearErr != nil {
		return s.clearErr
	}
	s.loadToken = satflow.AccessToken{}
	s.loadOK = false
	return nil
}

func loadTestFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{"..", "testdata"}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func loadFixtureFiel(t *testing.T) *sat.Fiel {
	t.Helper()
	certDER := loadTestFile(t, "certs", "rsa_cert.der")
	keyDER := loadTestFile(t, "certs", "rsa_key_encrypted_pkcs8.der")
	fiel, err := sat.NewFiel(certDER, keyDER, []byte(fixturePassword))
	if err != nil {
		t.Fatalf("sat.NewFiel() error = %v", err)
	}
	return fiel
}

func writeXML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func authResponse(token string) string {
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><AutenticaResponse xmlns="http://DescargaMasivaTerceros.gob.mx"><AutenticaResult>%s</AutenticaResult></AutenticaResponse></s:Body></s:Envelope>`, token)
}

func consultaResponse(requestID string) string {
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><SolicitaDescargaRecibidosResponse xmlns="http://DescargaMasivaTerceros.sat.gob.mx"><SolicitaDescargaRecibidosResult IdSolicitud="%s" CodEstatus="5000" Mensaje="Solicitud Aceptada"></SolicitaDescargaRecibidosResult></SolicitaDescargaRecibidosResponse></s:Body></s:Envelope>`, requestID)
}

func verifyResponse(state int, message string, packageIDs ...string) string {
	var packages strings.Builder
	for _, packageID := range packageIDs {
		packages.WriteString("<IdsPaquetes>")
		packages.WriteString(packageID)
		packages.WriteString("</IdsPaquetes>")
	}
	return fmt.Sprintf(
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><VerificaSolicitudDescargaResponse xmlns="http://DescargaMasivaTerceros.sat.gob.mx"><VerificaSolicitudDescargaResult CodEstatus="5000" EstadoSolicitud="%d" CodigoEstadoSolicitud="5000" NumeroCFDIs="%d" Mensaje="%s">%s</VerificaSolicitudDescargaResult></VerificaSolicitudDescargaResponse></s:Body></s:Envelope>`,
		state,
		len(packageIDs),
		message,
		packages.String(),
	)
}

func descargaResponse(packageID, payload string) string {
	return fmt.Sprintf(
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:h="http://DescargaMasivaTerceros.sat.gob.mx"><s:Header><h:respuesta CodEstatus="5000" Mensaje="Solicitud Aceptada"></h:respuesta></s:Header><s:Body><RespuestaDescargaMasivaTercerosSalida xmlns="http://DescargaMasivaTerceros.sat.gob.mx"><Paquete>%s</Paquete></RespuestaDescargaMasivaTercerosSalida></s:Body></s:Envelope>`,
		encodeBase64(payload),
	)
}

func invalidDescargaResponse(payload string) string {
	return fmt.Sprintf(
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:h="http://DescargaMasivaTerceros.sat.gob.mx"><s:Header><h:respuesta CodEstatus="5000" Mensaje="Solicitud Aceptada"></h:respuesta></s:Header><s:Body><RespuestaDescargaMasivaTercerosSalida xmlns="http://DescargaMasivaTerceros.sat.gob.mx"><Paquete>%s</Paquete></RespuestaDescargaMasivaTercerosSalida></s:Body></s:Envelope>`,
		payload,
	)
}

func soapFaultResponse(message string) string {
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>%s</faultstring></s:Fault></s:Body></s:Envelope>`, message)
}

func packageIDFromBody(body string) string {
	start := strings.Index(body, `IdPaquete="`)
	if start == -1 {
		return ""
	}
	start += len(`IdPaquete="`)
	end := strings.Index(body[start:], `"`)
	if end == -1 {
		return ""
	}
	return body[start : start+end]
}

func encodeBase64(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}
