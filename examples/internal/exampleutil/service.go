package exampleutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	satcfdiv1 "github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1"
	"github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1/satcfdiv1connect"
)

type ServiceCredentialSource struct {
	Credentials   *satcfdiv1.SATCredentials
	CredentialRef *satcfdiv1.CredentialRef
	Mode          string
}

type ServiceClients struct {
	URL  string
	Flow satcfdiv1connect.SATFlowServiceClient
}

func MustServiceCredentialSource() ServiceCredentialSource {
	if ref := Optional("SAT_CREDENTIAL_REF"); ref != "" {
		return ServiceCredentialSource{
			CredentialRef: &satcfdiv1.CredentialRef{
				Provider: Env("SAT_CREDENTIAL_PROVIDER", "file"),
				Id:       ref,
			},
			Mode: "credential_ref",
		}
	}

	return ServiceCredentialSource{
		Credentials: MustInlineCredentials(),
		Mode:        "inline",
	}
}

func MustServiceClients() ServiceClients {
	httpClient, err := newServiceHTTPClient()
	Fail(err)

	url := Env("SAT_SERVICE_URL", "https://127.0.0.1:8443")
	return ServiceClients{
		URL:  url,
		Flow: satcfdiv1connect.NewSATFlowServiceClient(httpClient, url),
	}
}

func newServiceHTTPClient() (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{}

	if caFile := Optional("SAT_SERVICE_CA_FILE"); caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("leer SAT_SERVICE_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("SAT_SERVICE_CA_FILE no contiene certificados válidos")
		}
		tlsConfig.RootCAs = pool
	}

	clientCert := Optional("SAT_SERVICE_CLIENT_CERT_FILE")
	clientKey := Optional("SAT_SERVICE_CLIENT_KEY_FILE")
	if clientCert != "" || clientKey != "" {
		if clientCert == "" || clientKey == "" {
			Usagef("SAT_SERVICE_CLIENT_CERT_FILE y SAT_SERVICE_CLIENT_KEY_FILE deben venir juntos")
		}
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("cargar certificado cliente TLS: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	if Optional("SAT_SERVICE_INSECURE_SKIP_VERIFY") == "1" {
		tlsConfig.InsecureSkipVerify = true
	}

	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport}, nil
}
