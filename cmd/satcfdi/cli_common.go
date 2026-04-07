package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

var cliNow = time.Now

type commonOptions struct {
	timeout       time.Duration
	authURL       string
	solicitaURL   string
	verificaURL   string
	descargaURL   string
	validacionURL string
	tokenStore    string
}

type credentialOptions struct {
	certPath string
	keyPath  string
	password string
}

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		*s = append(*s, trimmed)
	}
	return nil
}

func bindCommonFlags(fs *flag.FlagSet) *commonOptions {
	opts := &commonOptions{}
	fs.DurationVar(&opts.timeout, "timeout", envDuration("SAT_TIMEOUT", 15*time.Second), "timeout HTTP")
	fs.StringVar(&opts.authURL, "auth-url", os.Getenv("SAT_AUTH_URL"), "endpoint de autenticación SAT")
	fs.StringVar(&opts.solicitaURL, "solicita-url", os.Getenv("SAT_SOLICITA_URL"), "endpoint para solicitar descargas")
	fs.StringVar(&opts.verificaURL, "verifica-url", os.Getenv("SAT_VERIFICA_URL"), "endpoint para verificar solicitudes")
	fs.StringVar(&opts.descargaURL, "descarga-url", os.Getenv("SAT_DESCARGA_URL"), "endpoint para descargar paquetes")
	fs.StringVar(&opts.validacionURL, "validacion-url", os.Getenv("SAT_VALIDACION_URL"), "endpoint para validar CFDI")
	fs.StringVar(&opts.tokenStore, "token-store", os.Getenv("SAT_TOKEN_STORE"), "almacenamiento de token opcional (vacío o keychain)")
	return opts
}

func bindCredentialFlags(fs *flag.FlagSet) *credentialOptions {
	opts := &credentialOptions{}
	fs.StringVar(&opts.certPath, "cert", os.Getenv("SAT_CERT_PATH"), "ruta al certificado .cer DER")
	fs.StringVar(&opts.keyPath, "key", os.Getenv("SAT_KEY_PATH"), "ruta a la llave .key DER")
	fs.StringVar(&opts.password, "password", os.Getenv("SAT_KEY_PASSWORD"), "contraseña de la llave")
	return opts
}

func newClient(opts *commonOptions) *sat.Client {
	httpClient := &http.Client{Timeout: opts.timeout}
	return sat.NewClient(sat.Config{
		HTTPClient: httpClient,
		Endpoints:  effectiveEndpoints(opts),
	})
}

func newFlowClient(opts *commonOptions, fiel *sat.Fiel, rfcSolicitante string) (*satflow.Client, error) {
	return satflow.New(satflow.Config{
		Client:         newClient(opts),
		Fiel:           fiel,
		RFCSolicitante: rfcSolicitante,
	})
}

func effectiveEndpoints(opts *commonOptions) sat.Endpoints {
	defaults := sat.DefaultEndpoints()
	if strings.TrimSpace(opts.authURL) != "" {
		defaults.AuthURL = opts.authURL
	}
	if strings.TrimSpace(opts.solicitaURL) != "" {
		defaults.SolicitaURL = opts.solicitaURL
	}
	if strings.TrimSpace(opts.verificaURL) != "" {
		defaults.VerificaURL = opts.verificaURL
	}
	if strings.TrimSpace(opts.descargaURL) != "" {
		defaults.DescargaURL = opts.descargaURL
	}
	if strings.TrimSpace(opts.validacionURL) != "" {
		defaults.ValidacionURL = opts.validacionURL
	}
	return defaults
}

func loadFiel(opts *credentialOptions) (*sat.Fiel, error) {
	if strings.TrimSpace(opts.certPath) == "" {
		return nil, fmt.Errorf("flag requerida: -cert")
	}
	if strings.TrimSpace(opts.keyPath) == "" {
		return nil, fmt.Errorf("flag requerida: -key")
	}

	certDER, err := os.ReadFile(opts.certPath)
	if err != nil {
		return nil, err
	}
	keyDER, err := os.ReadFile(opts.keyPath)
	if err != nil {
		return nil, err
	}

	return sat.NewFiel(certDER, keyDER, []byte(opts.password))
}

func prompt(reader *bufio.Reader, stdout io.Writer, label, defaultValue string, required bool) (string, error) {
	if strings.TrimSpace(defaultValue) != "" {
		fmt.Fprintf(stdout, "%s [%s]: ", label, defaultValue)
	} else {
		fmt.Fprintf(stdout, "%s: ", label)
	}

	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		value = defaultValue
	}
	if required && strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s es requerido", label)
	}
	return value, nil
}

func parseCLITime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("valor vacío")
	}

	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02",
	}

	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("usa YYYY-MM-DD, RFC3339 o 2006-01-02T15:04:05")
}

func writeJSON(stdout io.Writer, v any, stderr io.Writer) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func fail(stderr io.Writer, err error) int {
	var soapErr *sat.SOAPFaultError
	if errors.As(err, &soapErr) {
		fmt.Fprintf(stderr, "error: %s\n", soapErr.Error())
		return 1
	}
	fmt.Fprintf(stderr, "error: %v\n", err)
	return 1
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func currentMonthStart() time.Time {
	now := cliNow()
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "satcfdi es un CLI para probar go-satcfdi de forma manual.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Comandos:")
	fmt.Fprintln(w, "  shell       Abre una shell persistente satcfdi>")
	fmt.Fprintln(w, "  interactive Alias de shell")
	fmt.Fprintln(w, "  wizard      Alias de shell")
	fmt.Fprintln(w, "  auth        Obtiene un token SAT usando e.firma")
	fmt.Fprintln(w, "  solicitar   Crea una solicitud de descarga")
	fmt.Fprintln(w, "  verificar   Consulta el estado de una solicitud")
	fmt.Fprintln(w, "  descargar   Descarga un paquete por ID")
	fmt.Fprintln(w, "  flujo       Ejecuta auth + solicitud + polling + descarga de paquetes")
	fmt.Fprintln(w, "  validar     Valida el estado de un CFDI")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Ejemplos:")
	fmt.Fprintln(w, "  satcfdi shell -cert mi.cer -key mi.key -password secreto -rfc-solicitante XAXX010101000")
	fmt.Fprintln(w, "  satcfdi auth -cert mi.cer -key mi.key -password secreto")
	fmt.Fprintln(w, "  satcfdi solicitar -cert mi.cer -key mi.key -token TOKEN -rfc-solicitante XAXX010101000 -tipo-descarga recibidos")
	fmt.Fprintln(w, "  satcfdi flujo -cert mi.cer -key mi.key -password secreto -rfc-solicitante XAXX010101000 -tipo-descarga recibidos")
}
