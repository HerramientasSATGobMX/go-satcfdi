package sat

import (
	"net/http"
	"time"
)

const (
	authSOAPAction         = "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica"
	solicitaEmitSOAPAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaEmitidos"
	solicitaRecSOAPAction  = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos"
	verificaSOAPAction     = "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga"
	descargaSOAPAction     = "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar"
	validacionSOAPAction   = "http://tempuri.org/IConsultaCFDIService/Consulta"
)

// Endpoints agrupa las URLs de SAT utilizadas por Client.
type Endpoints struct {
	AuthURL       string
	SolicitaURL   string
	VerificaURL   string
	DescargaURL   string
	ValidacionURL string
}

// Config permite personalizar el cliente HTTP, los endpoints y el reloj usados
// por Client.
type Config struct {
	HTTPClient *http.Client
	Endpoints  Endpoints
	Clock      func() time.Time
}

// Client es un cliente SAT sin estado para autenticación, descargas y
// validación de CFDI.
type Client struct {
	httpClient *http.Client
	endpoints  Endpoints
	clock      func() time.Time
}

// DefaultEndpoints devuelve los endpoints públicos predeterminados que usa el
// cliente.
func DefaultEndpoints() Endpoints {
	return Endpoints{
		AuthURL:       "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc",
		SolicitaURL:   "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc",
		VerificaURL:   "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc",
		DescargaURL:   "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc",
		ValidacionURL: "https://consultaqr.facturaelectronica.sat.gob.mx/ConsultaCFDIService.svc",
	}
}

// NewClient construye un Client nuevo con cliente HTTP, endpoints y reloj
// opcionales.
func NewClient(cfg Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	endpoints := cfg.Endpoints
	defaults := DefaultEndpoints()
	if endpoints.AuthURL == "" {
		endpoints.AuthURL = defaults.AuthURL
	}
	if endpoints.SolicitaURL == "" {
		endpoints.SolicitaURL = defaults.SolicitaURL
	}
	if endpoints.VerificaURL == "" {
		endpoints.VerificaURL = defaults.VerificaURL
	}
	if endpoints.DescargaURL == "" {
		endpoints.DescargaURL = defaults.DescargaURL
	}
	if endpoints.ValidacionURL == "" {
		endpoints.ValidacionURL = defaults.ValidacionURL
	}

	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	return &Client{
		httpClient: httpClient,
		endpoints:  endpoints,
		clock:      clock,
	}
}
