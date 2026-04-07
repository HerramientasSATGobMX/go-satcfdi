package satservice_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	satcfdiv1 "github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1"
	"github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1/satcfdiv1connect"
	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satservice"
)

var fixedTime = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

func TestServerConnectRoundTrip(t *testing.T) {
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		switch action := r.Header.Get("SOAPAction"); {
		case strings.Contains(action, "Autentica"):
			writeFixture(t, w, http.StatusOK, "auth_success.xml")
		case strings.Contains(action, "SolicitaDescarga"):
			writeFixture(t, w, http.StatusOK, "solicita_recibidos_success.xml")
		case strings.Contains(action, "VerificaSolicitudDescarga"):
			writeFixture(t, w, http.StatusOK, "verifica_with_packages.xml")
		case strings.Contains(action, "Descargar"):
			writeFixture(t, w, http.StatusOK, "descarga_success.xml")
		case strings.Contains(action, "ConsultaCFDI"):
			writeFixture(t, w, http.StatusOK, "validacion_success.xml")
		default:
			t.Fatalf("unexpected SOAPAction %q", action)
		}
	})
	defer soapServer.Close()

	client := newServiceClient(t, soapServer, false)
	credentials := fixtureCredentials(t)

	authResp, err := client.Authenticate(context.Background(), connect.NewRequest(&satcfdiv1.AuthenticateRequest{
		Credentials: credentials,
	}))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authResp.Msg.GetAccessToken() != "test-token" {
		t.Fatalf("Authenticate() token = %q", authResp.Msg.GetAccessToken())
	}

	consultResp, err := client.ConsultDownload(context.Background(), connect.NewRequest(&satcfdiv1.ConsultDownloadRequest{
		Credentials:    credentials,
		AccessToken:    "token",
		RfcSolicitante: "AAA010101AAA",
		FechaInicial:   timestamp(t, time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)),
		FechaFinal:     timestamp(t, time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC)),
		DownloadType:   satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS,
		QueryType:      satcfdiv1.QueryType_QUERY_TYPE_CFDI,
		InvoiceStatus:  satcfdiv1.InvoiceStatus_INVOICE_STATUS_VIGENTE,
	}))
	if err != nil {
		t.Fatalf("ConsultDownload() error = %v", err)
	}
	if consultResp.Msg.GetRequestId() != "REQ-REC-123" {
		t.Fatalf("ConsultDownload() request_id = %q", consultResp.Msg.GetRequestId())
	}

	verifyResp, err := client.VerifyDownload(context.Background(), connect.NewRequest(&satcfdiv1.VerifyDownloadRequest{
		Credentials:    credentials,
		AccessToken:    "token",
		RfcSolicitante: "AAA010101AAA",
		RequestId:      "REQ-123",
	}))
	if err != nil {
		t.Fatalf("VerifyDownload() error = %v", err)
	}
	if verifyResp.Msg.GetRequestStatus() != satcfdiv1.DownloadRequestStatus_DOWNLOAD_REQUEST_STATUS_FINISHED {
		t.Fatalf("VerifyDownload() request_status = %v", verifyResp.Msg.GetRequestStatus())
	}
	if len(verifyResp.Msg.GetPackageIds()) != 2 {
		t.Fatalf("VerifyDownload() package_ids = %v", verifyResp.Msg.GetPackageIds())
	}

	downloadResp, err := client.DownloadPackage(context.Background(), connect.NewRequest(&satcfdiv1.DownloadPackageRequest{
		Credentials:    credentials,
		AccessToken:    "token",
		RfcSolicitante: "AAA010101AAA",
		PackageId:      "PKG_01",
	}))
	if err != nil {
		t.Fatalf("DownloadPackage() error = %v", err)
	}
	if downloadResp.Msg.GetPackageId() != "PKG_01" {
		t.Fatalf("DownloadPackage() package_id = %q", downloadResp.Msg.GetPackageId())
	}
	if len(downloadResp.Msg.GetPackageBytes()) == 0 {
		t.Fatal("DownloadPackage() expected decoded package bytes")
	}

	validateResp, err := client.ValidateCfdi(context.Background(), connect.NewRequest(&satcfdiv1.ValidateCfdiRequest{
		RfcEmisor:   "AAA010101AAA",
		RfcReceptor: "BBB010101BBB",
		Total:       "1000.41",
		Uuid:        "11111111-2222-3333-4444-555555555555",
	}))
	if err != nil {
		t.Fatalf("ValidateCfdi() error = %v", err)
	}
	if validateResp.Msg.GetEstado() != "Vigente" {
		t.Fatalf("ValidateCfdi() estado = %q", validateResp.Msg.GetEstado())
	}
}

func TestServerSupportsGRPCProtocol(t *testing.T) {
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if !strings.Contains(r.Header.Get("SOAPAction"), "Autentica") {
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
		writeFixture(t, w, http.StatusOK, "auth_success.xml")
	})
	defer soapServer.Close()

	client := newServiceClient(t, soapServer, true, connect.WithGRPC())
	resp, err := client.Authenticate(context.Background(), connect.NewRequest(&satcfdiv1.AuthenticateRequest{
		Credentials: fixtureCredentials(t),
	}))
	if err != nil {
		t.Fatalf("Authenticate() via gRPC error = %v", err)
	}
	if resp.Msg.GetAccessToken() != "test-token" {
		t.Fatalf("Authenticate() via gRPC token = %q", resp.Msg.GetAccessToken())
	}
}

func TestBusinessErrorMapping(t *testing.T) {
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if !strings.Contains(r.Header.Get("SOAPAction"), "SolicitaDescarga") {
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
		writeFixture(t, w, http.StatusOK, "solicita_rechazada.xml")
	})
	defer soapServer.Close()

	client := newServiceClient(t, soapServer, false)
	_, err := client.ConsultDownload(context.Background(), connect.NewRequest(&satcfdiv1.ConsultDownloadRequest{
		Credentials:    fixtureCredentials(t),
		AccessToken:    "token",
		RfcSolicitante: "AAA010101AAA",
		FechaInicial:   timestamp(t, time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)),
		FechaFinal:     timestamp(t, time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC)),
		DownloadType:   satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS,
		QueryType:      satcfdiv1.QueryType_QUERY_TYPE_CFDI,
		InvoiceStatus:  satcfdiv1.InvoiceStatus_INVOICE_STATUS_VIGENTE,
	}))

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected connect.Error, got %v", err)
	}
	if connectErr.Code() != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want %v", connectErr.Code(), connect.CodeFailedPrecondition)
	}

	detail := requireServiceDetail(t, connectErr)
	if detail.GetCategory() != satcfdiv1.ErrorCategory_ERROR_CATEGORY_BUSINESS {
		t.Fatalf("category = %v", detail.GetCategory())
	}
	if detail.GetSatCode() != "300" {
		t.Fatalf("sat_code = %q", detail.GetSatCode())
	}
}

func TestSOAPFaultMapping(t *testing.T) {
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if !strings.Contains(r.Header.Get("SOAPAction"), "SolicitaDescarga") {
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
		writeRawXML(t, w, http.StatusInternalServerError, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <s:Fault>
      <faultcode>s:Server</faultcode>
      <faultstring>Servicio temporal no disponible</faultstring>
    </s:Fault>
  </s:Body>
</s:Envelope>`)
	})
	defer soapServer.Close()

	client := newServiceClient(t, soapServer, false)
	_, err := client.ConsultDownload(context.Background(), connect.NewRequest(&satcfdiv1.ConsultDownloadRequest{
		Credentials:    fixtureCredentials(t),
		AccessToken:    "token",
		RfcSolicitante: "AAA010101AAA",
		FechaInicial:   timestamp(t, time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)),
		FechaFinal:     timestamp(t, time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC)),
		DownloadType:   satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS,
		QueryType:      satcfdiv1.QueryType_QUERY_TYPE_CFDI,
		InvoiceStatus:  satcfdiv1.InvoiceStatus_INVOICE_STATUS_VIGENTE,
	}))

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected connect.Error, got %v", err)
	}
	if connectErr.Code() != connect.CodeUnavailable {
		t.Fatalf("code = %v, want %v", connectErr.Code(), connect.CodeUnavailable)
	}

	detail := requireServiceDetail(t, connectErr)
	if detail.GetCategory() != satcfdiv1.ErrorCategory_ERROR_CATEGORY_SOAP {
		t.Fatalf("category = %v", detail.GetCategory())
	}
	if !detail.GetRetryable() {
		t.Fatal("expected retryable SOAP fault detail")
	}
	if detail.GetSoapHttpStatus() != 500 {
		t.Fatalf("soap_http_status = %d", detail.GetSoapHttpStatus())
	}
}

func TestAuthenticationSOAPFaultMapping(t *testing.T) {
	soapServer := newSOAPBackend(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if !strings.Contains(r.Header.Get("SOAPAction"), "SolicitaDescarga") {
			t.Fatalf("unexpected SOAPAction %q", r.Header.Get("SOAPAction"))
		}
		writeFixture(t, w, http.StatusInternalServerError, "soap_fault.xml")
	})
	defer soapServer.Close()

	client := newServiceClient(t, soapServer, false)
	_, err := client.ConsultDownload(context.Background(), connect.NewRequest(&satcfdiv1.ConsultDownloadRequest{
		Credentials:    fixtureCredentials(t),
		AccessToken:    "token",
		RfcSolicitante: "AAA010101AAA",
		FechaInicial:   timestamp(t, time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)),
		FechaFinal:     timestamp(t, time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC)),
		DownloadType:   satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS,
		QueryType:      satcfdiv1.QueryType_QUERY_TYPE_CFDI,
		InvoiceStatus:  satcfdiv1.InvoiceStatus_INVOICE_STATUS_VIGENTE,
	}))

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected connect.Error, got %v", err)
	}
	if connectErr.Code() != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want %v", connectErr.Code(), connect.CodeUnauthenticated)
	}

	detail := requireServiceDetail(t, connectErr)
	if detail.GetCategory() != satcfdiv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION {
		t.Fatalf("category = %v", detail.GetCategory())
	}
}

func newServiceClient(
	t *testing.T,
	soapServer *httptest.Server,
	useTLSHTTP2 bool,
	opts ...connect.ClientOption,
) satcfdiv1connect.SATServiceClient {
	t.Helper()

	coreClient := sat.NewClient(sat.Config{
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

	path, handler, err := satservice.NewHandler(satservice.Config{Client: coreClient})
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
		return satcfdiv1connect.NewSATServiceClient(unstarted.Client(), unstarted.URL, opts...)
	}

	serviceServer := httptest.NewServer(mux)
	t.Cleanup(serviceServer.Close)
	return satcfdiv1connect.NewSATServiceClient(serviceServer.Client(), serviceServer.URL, opts...)
}

func newSOAPBackend(t *testing.T, fn func(http.ResponseWriter, *http.Request, []byte)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		fn(w, r, body)
	}))
}

func fixtureCredentials(t *testing.T) *satcfdiv1.SATCredentials {
	t.Helper()
	return &satcfdiv1.SATCredentials{
		CertificateDer:     loadFile(t, "certs", "rsa_cert.der"),
		PrivateKeyDer:      loadFile(t, "certs", "rsa_key_encrypted_pkcs8.der"),
		PrivateKeyPassword: "password",
	}
}

func timestamp(t *testing.T, value time.Time) *timestamppb.Timestamp {
	t.Helper()
	return timestamppb.New(value)
}

func requireServiceDetail(t *testing.T, err *connect.Error) *satcfdiv1.ServiceErrorDetail {
	t.Helper()
	for _, detail := range err.Details() {
		msg, decodeErr := detail.Value()
		if decodeErr != nil {
			t.Fatalf("decode detail: %v", decodeErr)
		}
		if typed, ok := msg.(*satcfdiv1.ServiceErrorDetail); ok {
			return typed
		}
	}
	t.Fatal("missing ServiceErrorDetail")
	return nil
}

func writeFixture(t *testing.T, w http.ResponseWriter, status int, name string) {
	t.Helper()
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(loadFile(t, "responses", name))
}

func writeRawXML(t *testing.T, w http.ResponseWriter, status int, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func loadFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{"..", "testdata"}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
