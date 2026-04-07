package satservice_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	satcfdiv1 "github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1"
	"github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1/satcfdiv1connect"
	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satservice"
)

func TestAuthenticateRequiresExactlyOneCredentialSource(t *testing.T) {
	soapServer := newSOAPBackend(t, func(http.ResponseWriter, *http.Request, []byte) {
		t.Fatal("unexpected network call")
	})
	defer soapServer.Close()

	client, _ := newServiceClientsWithConfig(t, soapServer, false, satservice.Config{})

	_, err := client.Authenticate(context.Background(), connect.NewRequest(&satcfdiv1.AuthenticateRequest{}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	if detail := requireServiceDetail(t, asConnectError(t, err)); detail.GetCategory() != satcfdiv1.ErrorCategory_ERROR_CATEGORY_VALIDATION {
		t.Fatalf("category = %v", detail.GetCategory())
	}

	_, err = client.Authenticate(context.Background(), connect.NewRequest(&satcfdiv1.AuthenticateRequest{
		Credentials:   fixtureCredentials(t),
		CredentialRef: &satcfdiv1.CredentialRef{Provider: "file", Id: "creds.json"},
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	if detail := requireServiceDetail(t, asConnectError(t, err)); detail.GetCategory() != satcfdiv1.ErrorCategory_ERROR_CATEGORY_VALIDATION {
		t.Fatalf("category = %v", detail.GetCategory())
	}
}

func TestAuthenticateSupportsFileCredentialRef(t *testing.T) {
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if !strings.Contains(r.Header.Get("SOAPAction"), "Autentica") {
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
		writeFixture(t, w, http.StatusOK, "auth_success.xml")
	})
	defer soapServer.Close()

	allowDir := t.TempDir()
	writeCredentialDescriptor(t, allowDir, "creds.json")

	client, _ := newServiceClientsWithConfig(t, soapServer, false, satservice.Config{
		CredentialFileAllowlist: []string{allowDir},
	})

	resp, err := client.Authenticate(context.Background(), connect.NewRequest(&satcfdiv1.AuthenticateRequest{
		CredentialRef: &satcfdiv1.CredentialRef{Provider: "file", Id: "creds.json"},
	}))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if resp.Msg.GetAccessToken() != "test-token" {
		t.Fatalf("token = %q", resp.Msg.GetAccessToken())
	}
}

func TestAuthenticateRejectsCredentialRefOutsideAllowlist(t *testing.T) {
	soapServer := newSOAPBackend(t, func(http.ResponseWriter, *http.Request, []byte) {
		t.Fatal("unexpected network call")
	})
	defer soapServer.Close()

	allowedDir := t.TempDir()
	deniedDir := t.TempDir()
	descriptor := writeCredentialDescriptor(t, deniedDir, "creds.json")

	client, _ := newServiceClientsWithConfig(t, soapServer, false, satservice.Config{
		CredentialFileAllowlist: []string{allowedDir},
	})

	_, err := client.Authenticate(context.Background(), connect.NewRequest(&satcfdiv1.AuthenticateRequest{
		CredentialRef: &satcfdiv1.CredentialRef{Provider: "file", Id: descriptor},
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	detail := requireServiceDetail(t, asConnectError(t, err))
	if detail.GetCategory() != satcfdiv1.ErrorCategory_ERROR_CATEGORY_CREDENTIALS {
		t.Fatalf("category = %v", detail.GetCategory())
	}
	if detail.GetOperation() != "authenticate" {
		t.Fatalf("operation = %q", detail.GetOperation())
	}
}

func TestStreamDownloadPackageChunksAndUnaryLimit(t *testing.T) {
	payload := []byte("abcdefghijkl")
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if !strings.Contains(r.Header.Get("SOAPAction"), "Descargar") {
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
		writeRawXML(t, w, http.StatusOK, descargaResponseBytes(payload))
	})
	defer soapServer.Close()

	client, _ := newServiceClientsWithConfig(t, soapServer, false, satservice.Config{
		StreamChunkSize:      4,
		MaxUnaryPackageBytes: 4,
	})

	stream, err := client.StreamDownloadPackage(context.Background(), connect.NewRequest(&satcfdiv1.StreamDownloadPackageRequest{
		Credentials:    fixtureCredentials(t),
		AccessToken:    "token",
		RfcSolicitante: "AAA010101AAA",
		PackageId:      "PKG_BIG",
	}))
	if err != nil {
		t.Fatalf("StreamDownloadPackage() error = %v", err)
	}
	defer stream.Close()

	var chunks []*satcfdiv1.StreamDownloadPackageResponse
	var combined []byte
	for stream.Receive() {
		chunk := stream.Msg()
		chunks = append(chunks, chunk)
		combined = append(combined, chunk.GetData()...)
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream.Err() = %v", err)
	}

	if len(chunks) != 3 {
		t.Fatalf("len(chunks) = %d", len(chunks))
	}
	if chunks[0].GetOffset() != 0 || chunks[1].GetOffset() != 4 || chunks[2].GetOffset() != 8 {
		t.Fatalf("offsets = %d,%d,%d", chunks[0].GetOffset(), chunks[1].GetOffset(), chunks[2].GetOffset())
	}
	if !chunks[2].GetEof() {
		t.Fatal("expected EOF on last chunk")
	}
	if got := string(combined); got != string(payload) {
		t.Fatalf("combined payload = %q", got)
	}

	_, err = client.DownloadPackage(context.Background(), connect.NewRequest(&satcfdiv1.DownloadPackageRequest{
		Credentials:    fixtureCredentials(t),
		AccessToken:    "token",
		RfcSolicitante: "AAA010101AAA",
		PackageId:      "PKG_BIG",
	}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
	detail := requireServiceDetail(t, asConnectError(t, err))
	if detail.GetCategory() != satcfdiv1.ErrorCategory_ERROR_CATEGORY_VALIDATION {
		t.Fatalf("category = %v", detail.GetCategory())
	}
	if detail.GetPackageId() != "PKG_BIG" {
		t.Fatalf("package_id = %q", detail.GetPackageId())
	}
}

func TestRunDownloadFlowHappyPath(t *testing.T) {
	var mu sync.Mutex
	verifyCalls := 0

	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		switch action := r.Header.Get("SOAPAction"); {
		case strings.Contains(action, "Autentica"):
			writeRawXML(t, w, http.StatusOK, authResponse("flow-token"))
		case strings.Contains(action, "SolicitaDescarga"):
			writeRawXML(t, w, http.StatusOK, consultaResponse("REQ-FLOW-1"))
		case strings.Contains(action, "VerificaSolicitudDescarga"):
			mu.Lock()
			verifyCalls++
			call := verifyCalls
			mu.Unlock()
			if call == 1 {
				writeRawXML(t, w, http.StatusOK, verifyResponse(sat.EstadoSolicitudEnProceso, "En proceso"))
				return
			}
			writeRawXML(t, w, http.StatusOK, verifyResponse(sat.EstadoSolicitudTerminada, "Solicitud Aceptada", "PKG_01", "PKG_02"))
		default:
			t.Fatalf("unexpected SOAPAction %q", action)
		}
	})
	defer soapServer.Close()

	_, flowClient := newServiceClientsWithConfig(t, soapServer, false, satservice.Config{})
	resp, err := flowClient.RunDownloadFlow(context.Background(), connect.NewRequest(&satcfdiv1.RunDownloadFlowRequest{
		Credentials:    fixtureCredentials(t),
		RfcSolicitante: "AAA010101AAA",
		FechaInicial:   timestamp(t, time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)),
		FechaFinal:     timestamp(t, time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC)),
		DownloadType:   satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS,
		QueryType:      satcfdiv1.QueryType_QUERY_TYPE_CFDI,
		InvoiceStatus:  satcfdiv1.InvoiceStatus_INVOICE_STATUS_VIGENTE,
		PollPolicy:     &satcfdiv1.PollPolicy{Interval: durationProto(time.Millisecond), MaxAttempts: 3},
	}))
	if err != nil {
		t.Fatalf("RunDownloadFlow() error = %v", err)
	}
	if resp.Msg.GetRequestId() != "REQ-FLOW-1" {
		t.Fatalf("request_id = %q", resp.Msg.GetRequestId())
	}
	if resp.Msg.GetRequestStatus() != satcfdiv1.DownloadRequestStatus_DOWNLOAD_REQUEST_STATUS_FINISHED {
		t.Fatalf("request_status = %v", resp.Msg.GetRequestStatus())
	}
	if len(resp.Msg.GetPackageIds()) != 2 {
		t.Fatalf("package_ids = %v", resp.Msg.GetPackageIds())
	}
}

func TestRunDownloadFlowPropagatesContextTimeout(t *testing.T) {
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		switch action := r.Header.Get("SOAPAction"); {
		case strings.Contains(action, "Autentica"):
			writeRawXML(t, w, http.StatusOK, authResponse("flow-token"))
		case strings.Contains(action, "SolicitaDescarga"):
			writeRawXML(t, w, http.StatusOK, consultaResponse("REQ-FLOW-2"))
		case strings.Contains(action, "VerificaSolicitudDescarga"):
			time.Sleep(50 * time.Millisecond)
			writeRawXML(t, w, http.StatusOK, verifyResponse(sat.EstadoSolicitudEnProceso, "En proceso"))
		default:
			t.Fatalf("unexpected SOAPAction %q", action)
		}
	})
	defer soapServer.Close()

	coreClient := sat.NewClient(sat.Config{
		HTTPClient: &http.Client{Timeout: 10 * time.Millisecond},
		Clock:      func() time.Time { return fixedTime },
		Endpoints: sat.Endpoints{
			AuthURL:       soapServer.URL,
			SolicitaURL:   soapServer.URL,
			VerificaURL:   soapServer.URL,
			DescargaURL:   soapServer.URL,
			ValidacionURL: soapServer.URL,
		},
	})
	_, flowClient := newServiceClientsWithConfig(t, soapServer, false, satservice.Config{Client: coreClient})

	_, err := flowClient.RunDownloadFlow(context.Background(), connect.NewRequest(&satcfdiv1.RunDownloadFlowRequest{
		Credentials:    fixtureCredentials(t),
		RfcSolicitante: "AAA010101AAA",
		FechaInicial:   timestamp(t, time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)),
		FechaFinal:     timestamp(t, time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC)),
		DownloadType:   satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS,
		QueryType:      satcfdiv1.QueryType_QUERY_TYPE_CFDI,
		InvoiceStatus:  satcfdiv1.InvoiceStatus_INVOICE_STATUS_VIGENTE,
		PollPolicy:     &satcfdiv1.PollPolicy{Interval: durationProto(time.Millisecond), MaxAttempts: 3},
	}))
	requireConnectCode(t, err, connect.CodeDeadlineExceeded)
	detail := requireServiceDetail(t, asConnectError(t, err))
	if detail.GetCategory() != satcfdiv1.ErrorCategory_ERROR_CATEGORY_TIMEOUT {
		t.Fatalf("category = %v", detail.GetCategory())
	}
}

func TestRunDownloadFlowPollTimeoutIncludesRequestDetails(t *testing.T) {
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		switch action := r.Header.Get("SOAPAction"); {
		case strings.Contains(action, "Autentica"):
			writeRawXML(t, w, http.StatusOK, authResponse("flow-token"))
		case strings.Contains(action, "SolicitaDescarga"):
			writeRawXML(t, w, http.StatusOK, consultaResponse("REQ-FLOW-3"))
		case strings.Contains(action, "VerificaSolicitudDescarga"):
			writeRawXML(t, w, http.StatusOK, verifyResponse(sat.EstadoSolicitudEnProceso, "En proceso"))
		default:
			t.Fatalf("unexpected SOAPAction %q", action)
		}
	})
	defer soapServer.Close()

	_, flowClient := newServiceClientsWithConfig(t, soapServer, false, satservice.Config{})
	_, err := flowClient.RunDownloadFlow(context.Background(), connect.NewRequest(&satcfdiv1.RunDownloadFlowRequest{
		Credentials:    fixtureCredentials(t),
		RfcSolicitante: "AAA010101AAA",
		FechaInicial:   timestamp(t, time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)),
		FechaFinal:     timestamp(t, time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC)),
		DownloadType:   satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS,
		QueryType:      satcfdiv1.QueryType_QUERY_TYPE_CFDI,
		InvoiceStatus:  satcfdiv1.InvoiceStatus_INVOICE_STATUS_VIGENTE,
		PollPolicy:     &satcfdiv1.PollPolicy{Interval: durationProto(time.Millisecond), MaxAttempts: 2},
	}))
	requireConnectCode(t, err, connect.CodeDeadlineExceeded)
	detail := requireServiceDetail(t, asConnectError(t, err))
	if detail.GetCategory() != satcfdiv1.ErrorCategory_ERROR_CATEGORY_TIMEOUT {
		t.Fatalf("category = %v", detail.GetCategory())
	}
	if detail.GetOperation() != "run_download_flow" {
		t.Fatalf("operation = %q", detail.GetOperation())
	}
	if detail.GetRequestId() != "REQ-FLOW-3" {
		t.Fatalf("request_id = %q", detail.GetRequestId())
	}
	if detail.GetSatStatusCode() != "5000" {
		t.Fatalf("sat_status_code = %q", detail.GetSatStatusCode())
	}
	if detail.GetRequestStatusCode() != "5000" {
		t.Fatalf("request_status_code = %q", detail.GetRequestStatusCode())
	}
}

func TestServiceLogsRedactSensitiveValues(t *testing.T) {
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if !strings.Contains(r.Header.Get("SOAPAction"), "Autentica") {
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
		writeFixture(t, w, http.StatusOK, "auth_success.xml")
	})
	defer soapServer.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	client, _ := newServiceClientsWithConfig(t, soapServer, false, satservice.Config{Logger: logger})

	_, err := client.Authenticate(context.Background(), connect.NewRequest(&satcfdiv1.AuthenticateRequest{
		Credentials: fixtureCredentials(t),
	}))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	output := logs.String()
	if strings.Contains(output, "password") {
		t.Fatal("logs leaked private key password")
	}
	if strings.Contains(output, "test-token") {
		t.Fatal("logs leaked SAT token")
	}
	if !strings.Contains(output, "/satcfdi.v1.SATService/Authenticate") {
		t.Fatalf("expected procedure in logs, got %q", output)
	}
}

func newServiceClientsWithConfig(
	t *testing.T,
	soapServer *httptest.Server,
	useTLSHTTP2 bool,
	cfg satservice.Config,
	opts ...connect.ClientOption,
) (satcfdiv1connect.SATServiceClient, satcfdiv1connect.SATFlowServiceClient) {
	t.Helper()

	if cfg.Client == nil {
		cfg.Client = sat.NewClient(sat.Config{
			HTTPClient: soapServer.Client(),
			Clock:      func() time.Time { return fixedTime },
			Endpoints: sat.Endpoints{
				AuthURL:       soapServer.URL,
				SolicitaURL:   soapServer.URL,
				VerificaURL:   soapServer.URL,
				DescargaURL:   soapServer.URL,
				ValidacionURL: soapServer.URL,
			},
		})
	}

	path, handler, err := satservice.NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(path, handler)

	if useTLSHTTP2 {
		unstarted := httptest.NewUnstartedServer(mux)
		unstarted.EnableHTTP2 = true
		unstarted.StartTLS()
		t.Cleanup(unstarted.Close)
		return satcfdiv1connect.NewSATServiceClient(unstarted.Client(), unstarted.URL, opts...),
			satcfdiv1connect.NewSATFlowServiceClient(unstarted.Client(), unstarted.URL, opts...)
	}

	serviceServer := httptest.NewServer(mux)
	t.Cleanup(serviceServer.Close)
	return satcfdiv1connect.NewSATServiceClient(serviceServer.Client(), serviceServer.URL, opts...),
		satcfdiv1connect.NewSATFlowServiceClient(serviceServer.Client(), serviceServer.URL, opts...)
}

func requireConnectCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected connect.Error, got %v", err)
	}
	if connectErr.Code() != want {
		t.Fatalf("code = %v, want %v", connectErr.Code(), want)
	}
}

func asConnectError(t *testing.T, err error) *connect.Error {
	t.Helper()
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected connect.Error, got %v", err)
	}
	return connectErr
}

func writeCredentialDescriptor(t *testing.T, dir, name string) string {
	t.Helper()
	certPath := filepath.Join(dir, "cert.der")
	keyPath := filepath.Join(dir, "key.der")
	if err := os.WriteFile(certPath, loadFile(t, "certs", "rsa_cert.der"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, loadFile(t, "certs", "rsa_key_encrypted_pkcs8.der"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	descriptorPath := filepath.Join(dir, name)
	payload, err := json.Marshal(map[string]string{
		"certificate_path":     filepath.Base(certPath),
		"private_key_path":     filepath.Base(keyPath),
		"private_key_password": "password",
	})
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	if err := os.WriteFile(descriptorPath, payload, 0o600); err != nil {
		t.Fatalf("write descriptor: %v", err)
	}
	return descriptorPath
}

func durationProto(value time.Duration) *durationpb.Duration {
	return durationpb.New(value)
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

func descargaResponseBytes(payload []byte) string {
	return fmt.Sprintf(
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:h="http://DescargaMasivaTerceros.sat.gob.mx"><s:Header><h:respuesta CodEstatus="5000" Mensaje="Solicitud Aceptada"></h:respuesta></s:Header><s:Body><RespuestaDescargaMasivaTercerosSalida xmlns="http://DescargaMasivaTerceros.sat.gob.mx"><Paquete>%s</Paquete></RespuestaDescargaMasivaTercerosSalida></s:Body></s:Envelope>`,
		base64.StdEncoding.EncodeToString(payload),
	)
}
