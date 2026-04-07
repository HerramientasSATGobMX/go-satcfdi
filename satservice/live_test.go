package satservice_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"

	satcfdiv1 "github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1"
	"github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1/satcfdiv1connect"
	"github.com/herramientassatgobmx/go-satcfdi/satservice"
)

func TestLiveAuthenticate(t *testing.T) {
	if os.Getenv("SAT_LIVE_ENABLE") != "1" {
		t.Skip("set SAT_LIVE_ENABLE=1 to run live SAT tests")
	}

	credentials := loadLiveCredentials(t)
	client := newLiveServiceClient(t)

	resp, err := client.Authenticate(context.Background(), connect.NewRequest(&satcfdiv1.AuthenticateRequest{
		Credentials: credentials,
	}))
	if err != nil {
		t.Fatalf("Authenticate() live error = %v", err)
	}
	if resp.Msg.GetAccessToken() == "" {
		t.Fatal("expected non-empty live access token")
	}
}

func TestLiveRunDownloadFlow(t *testing.T) {
	if os.Getenv("SAT_LIVE_ENABLE") != "1" || os.Getenv("SAT_LIVE_RUN_FLOW") != "1" {
		t.Skip("set SAT_LIVE_ENABLE=1 and SAT_LIVE_RUN_FLOW=1 to run live flow test")
	}

	rfc := os.Getenv("SAT_LIVE_RFC_SOLICITANTE")
	if rfc == "" {
		t.Skip("SAT_LIVE_RFC_SOLICITANTE is required for live flow test")
	}

	credentials := loadLiveCredentials(t)
	flowClient := newLiveFlowClient(t)
	now := time.Now().UTC()

	resp, err := flowClient.RunDownloadFlow(context.Background(), connect.NewRequest(&satcfdiv1.RunDownloadFlowRequest{
		Credentials:    credentials,
		RfcSolicitante: rfc,
		FechaInicial:   timestamp(t, now.Add(-time.Hour)),
		FechaFinal:     timestamp(t, now),
		DownloadType:   satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS,
		QueryType:      satcfdiv1.QueryType_QUERY_TYPE_METADATA,
		PollPolicy:     durationFlowPolicy(2*time.Second, 2),
	}))
	if err != nil {
		t.Fatalf("RunDownloadFlow() live error = %v", err)
	}
	if resp.Msg.GetRequestId() == "" {
		t.Fatal("expected non-empty live request id")
	}
}

func newLiveServiceClient(t *testing.T) satcfdiv1connect.SATServiceClient {
	t.Helper()
	path, handler, err := satservice.NewHandler(satservice.Config{})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return satcfdiv1connect.NewSATServiceClient(server.Client(), server.URL)
}

func newLiveFlowClient(t *testing.T) satcfdiv1connect.SATFlowServiceClient {
	t.Helper()
	path, handler, err := satservice.NewHandler(satservice.Config{})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return satcfdiv1connect.NewSATFlowServiceClient(server.Client(), server.URL)
}

func loadLiveCredentials(t *testing.T) *satcfdiv1.SATCredentials {
	t.Helper()

	certPath := os.Getenv("SAT_LIVE_CERT_PATH")
	keyPath := os.Getenv("SAT_LIVE_KEY_PATH")
	password := os.Getenv("SAT_LIVE_KEY_PASSWORD")
	if certPath == "" || keyPath == "" || password == "" {
		t.Skip("SAT_LIVE_CERT_PATH, SAT_LIVE_KEY_PATH, and SAT_LIVE_KEY_PASSWORD are required")
	}

	certDER, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyDER, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	return &satcfdiv1.SATCredentials{
		CertificateDer:     certDER,
		PrivateKeyDer:      keyDER,
		PrivateKeyPassword: password,
	}
}

func durationFlowPolicy(interval time.Duration, attempts int32) *satcfdiv1.PollPolicy {
	return &satcfdiv1.PollPolicy{
		Interval:    durationProto(interval),
		MaxAttempts: attempts,
	}
}
