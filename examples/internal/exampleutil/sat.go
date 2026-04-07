package exampleutil

import (
	"fmt"
	"net/http"
	"os"
	"time"

	satcfdiv1 "github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1"
	"github.com/herramientassatgobmx/go-satcfdi/sat"
)

func MustSATClient() *sat.Client {
	timeout := 15 * time.Second
	if raw := Optional("SAT_TIMEOUT"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil {
			Usagef("SAT_TIMEOUT debe ser un duration válido: %v", err)
		}
		timeout = value
	}

	return sat.NewClient(sat.Config{
		HTTPClient: &http.Client{Timeout: timeout},
		Endpoints: sat.Endpoints{
			AuthURL:       Optional("SAT_AUTH_URL"),
			SolicitaURL:   Optional("SAT_SOLICITA_URL"),
			VerificaURL:   Optional("SAT_VERIFICA_URL"),
			DescargaURL:   Optional("SAT_DESCARGA_URL"),
			ValidacionURL: Optional("SAT_VALIDACION_URL"),
		},
	})
}

func MustInlineCredentials() *satcfdiv1.SATCredentials {
	certPath := Require("SAT_CERT_PATH")
	keyPath := Require("SAT_KEY_PATH")

	certificateDER, err := os.ReadFile(certPath)
	if err != nil {
		Fail(fmt.Errorf("leer SAT_CERT_PATH: %w", err))
	}
	privateKeyDER, err := os.ReadFile(keyPath)
	if err != nil {
		Fail(fmt.Errorf("leer SAT_KEY_PATH: %w", err))
	}

	return &satcfdiv1.SATCredentials{
		CertificateDer:     certificateDER,
		PrivateKeyDer:      privateKeyDER,
		PrivateKeyPassword: Optional("SAT_KEY_PASSWORD"),
	}
}

func MustFiel() *sat.Fiel {
	credentials := MustInlineCredentials()
	fiel, err := sat.NewFiel(
		credentials.GetCertificateDer(),
		credentials.GetPrivateKeyDer(),
		[]byte(credentials.GetPrivateKeyPassword()),
	)
	Fail(err)
	return fiel
}

func MustSATClientAndFiel() (*sat.Client, *sat.Fiel) {
	return MustSATClient(), MustFiel()
}
