package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satservice"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("satcfdid", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		listen                 = fs.String("listen", envString("SAT_SERVICE_LISTEN", ":8443"), "dirección de escucha")
		insecureH2C            = fs.Bool("insecure-h2c", envBool("SAT_SERVICE_INSECURE_H2C", false), "habilita h2c/plaintext para desarrollo local")
		timeout                = fs.Duration("timeout", envDuration("SAT_TIMEOUT", 15*time.Second), "timeout HTTP hacia SAT por solicitud SOAP")
		authURL                = fs.String("auth-url", os.Getenv("SAT_AUTH_URL"), "endpoint de autenticación SAT")
		solicitaURL            = fs.String("solicita-url", os.Getenv("SAT_SOLICITA_URL"), "endpoint para solicitar descargas")
		verificaURL            = fs.String("verifica-url", os.Getenv("SAT_VERIFICA_URL"), "endpoint para verificar solicitudes")
		descargaURL            = fs.String("descarga-url", os.Getenv("SAT_DESCARGA_URL"), "endpoint para descargar paquetes")
		validacionURL          = fs.String("validacion-url", os.Getenv("SAT_VALIDACION_URL"), "endpoint para validar CFDI")
		tlsCert                = fs.String("tls-cert", strings.TrimSpace(os.Getenv("SAT_SERVICE_TLS_CERT")), "ruta al certificado TLS del servidor")
		tlsKey                 = fs.String("tls-key", strings.TrimSpace(os.Getenv("SAT_SERVICE_TLS_KEY")), "ruta a la llave TLS del servidor")
		tlsClientCA            = fs.String("tls-client-ca", strings.TrimSpace(os.Getenv("SAT_SERVICE_TLS_CLIENT_CA")), "ruta al CA bundle para validar certificados cliente")
		requireClientCert      = fs.Bool("tls-require-client-cert", envBool("SAT_SERVICE_TLS_REQUIRE_CLIENT_CERT", false), "requiere y valida certificado cliente (mTLS)")
		credentialDirs         = fs.String("credential-dirs", envString("SAT_SERVICE_CREDENTIAL_DIRS", ""), "lista separada por comas de directorios permitidos para credential_ref con provider=file")
		pollInterval           = fs.Duration("poll-interval", envDuration("SAT_SERVICE_POLL_INTERVAL", 5*time.Second), "intervalo por defecto para polling del flow service")
		pollMaxAttempts        = fs.Int("poll-max-attempts", envInt("SAT_SERVICE_POLL_MAX_ATTEMPTS", 60), "máximo de intentos por defecto para polling del flow service")
		maxUnaryRequestBytes   = fs.Int("max-unary-request-bytes", envInt("SAT_SERVICE_MAX_UNARY_REQUEST_BYTES", 10<<20), "tamaño máximo de solicitud unary")
		maxUnaryResponseBytes  = fs.Int("max-unary-response-bytes", envInt("SAT_SERVICE_MAX_UNARY_RESPONSE_BYTES", 16<<20), "tamaño máximo de respuesta unary")
		maxUnaryPackageBytes   = fs.Int("max-unary-package-bytes", envInt("SAT_SERVICE_MAX_UNARY_PACKAGE_BYTES", 16<<20), "tamaño máximo del package decoded permitido en DownloadPackage")
		streamChunkSize        = fs.Int("stream-chunk-size", envInt("SAT_SERVICE_STREAM_CHUNK_SIZE", 256<<10), "tamaño de bloque para StreamDownloadPackage")
		maxConcurrentDownloads = fs.Int("max-concurrent-downloads", envInt("SAT_SERVICE_MAX_CONCURRENT_DOWNLOADS", 4), "máximo de descargas SAT concurrentes")
		maxConcurrentStreams   = fs.Int("max-concurrent-streams", envInt("SAT_SERVICE_MAX_CONCURRENT_STREAMS", 4), "máximo de streams concurrentes")
	)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Uso: satcfdid [-listen :8443]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	client := sat.NewClient(sat.Config{
		HTTPClient: &http.Client{Timeout: *timeout},
		Endpoints: sat.Endpoints{
			AuthURL:       *authURL,
			SolicitaURL:   *solicitaURL,
			VerificaURL:   *verificaURL,
			DescargaURL:   *descargaURL,
			ValidacionURL: *validacionURL,
		},
	})

	service, err := satservice.NewService(satservice.Config{
		Client:                  client,
		CredentialFileAllowlist: splitCSV(*credentialDirs),
		Logger:                  logger,
		UpstreamTimeout:         *timeout,
		PollInterval:            *pollInterval,
		PollMaxAttempts:         *pollMaxAttempts,
		MaxUnaryRequestBytes:    *maxUnaryRequestBytes,
		MaxUnaryResponseBytes:   *maxUnaryResponseBytes,
		MaxUnaryPackageBytes:    *maxUnaryPackageBytes,
		StreamChunkSize:         *streamChunkSize,
		MaxConcurrentDownloads:  *maxConcurrentDownloads,
		MaxConcurrentStreams:    *maxConcurrentStreams,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", service.MetricsHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := service.Ready(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/", service.Handler())

	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	scheme := "https"
	if *insecureH2C {
		scheme = "http"
		server.Handler = h2c.NewHandler(mux, &http2.Server{})
	} else {
		tlsConfig, err := loadTLSConfig(*tlsCert, *tlsKey, *tlsClientCA, *requireClientCert)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		server.TLSConfig = tlsConfig
		if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	}

	fmt.Fprintf(stdout, "satcfdid escuchando en %s://127.0.0.1%s\n", scheme, normalizeListenAddr(*listen))
	fmt.Fprintf(stdout, "RPCs de bajo nivel y de flujo montados en /\n")
	fmt.Fprintf(stdout, "healthz=%s://127.0.0.1%s/healthz readyz=%s://127.0.0.1%s/readyz metrics=%s://127.0.0.1%s/metrics\n",
		scheme, normalizeListenAddr(*listen),
		scheme, normalizeListenAddr(*listen),
		scheme, normalizeListenAddr(*listen),
	)

	if *insecureH2C {
		fmt.Fprintln(stdout, "modo inseguro h2c habilitado solo para desarrollo local")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return 0
	}

	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func loadTLSConfig(certPath, keyPath, clientCAPath string, requireClientCert bool) (*tls.Config, error) {
	certPath = strings.TrimSpace(certPath)
	keyPath = strings.TrimSpace(keyPath)
	if certPath == "" || keyPath == "" {
		return nil, errors.New("TLS es obligatorio por defecto; usa -tls-cert y -tls-key o activa -insecure-h2c solo para desarrollo local")
	}

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("cargar par TLS: %w", err)
	}

	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}

	clientCAPath = strings.TrimSpace(clientCAPath)
	if clientCAPath == "" {
		if requireClientCert {
			return nil, errors.New("mTLS requiere -tls-client-ca cuando -tls-require-client-cert está habilitado")
		}
		return config, nil
	}

	caPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("leer bundle CA de cliente: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("interpretar bundle CA de cliente: no se encontraron certificados")
	}

	config.ClientCAs = pool
	if requireClientCert {
		config.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		config.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return config, nil
}

func envString(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
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

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil {
		return fallback
	}
	return parsed
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	case "":
		return fallback
	default:
		return fallback
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeListenAddr(value string) string {
	if strings.HasPrefix(value, ":") {
		return value
	}
	return value
}
