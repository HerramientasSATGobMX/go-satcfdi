package satflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
)

const (
	defaultTokenTTL      = 5 * time.Minute
	defaultRefreshBefore = 30 * time.Second
	defaultPollInterval  = 5 * time.Second
	defaultPollAttempts  = 60
	defaultRetryAttempts = 3
	defaultRetryBackoff  = 250 * time.Millisecond
	defaultRetryMaxWait  = 2 * time.Second
)

var (
	// ErrPollExceeded indica que el polling terminó antes de que la solicitud
	// llegara a un estado terminal.
	ErrPollExceeded = errors.New("satflow: el polling excedió el máximo de intentos")
	// ErrTerminalStatus indica que SAT devolvió un estado terminal no exitoso
	// para la solicitud.
	ErrTerminalStatus = errors.New("satflow: estado terminal de solicitud")
	// ErrInvalidPackagePayload indica que el cuerpo descargado del paquete no se
	// pudo decodificar desde base64.
	ErrInvalidPackagePayload = errors.New("satflow: contenido de paquete inválido")
)

// Config permite personalizar un cliente de flujo SAT de alto nivel.
type Config struct {
	Client         *sat.Client
	Fiel           *sat.Fiel
	RFCSolicitante string
	TokenCache     AccessTokenCache
	TokenTTL       time.Duration
	RefreshBefore  time.Duration
	Retry          RetryPolicy
	Poll           PollPolicy
	Clock          func() time.Time
	Sleep          func(context.Context, time.Duration) error
}

// RetryPolicy controla los reintentos ante fallas transitorias de transporte o
// SOAP.
type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

// PollPolicy controla cuánto tiempo Wait sigue consultando el estado de una
// solicitud SAT.
type PollPolicy struct {
	Interval    time.Duration
	MaxAttempts int
}

// DownloadRequest representa la solicitud SAT de descarga masiva de alto
// nivel. El token y el RFC propietario viven en la configuración de Client y
// no en cada llamada.
type DownloadRequest struct {
	FechaInicial       time.Time
	FechaFinal         time.Time
	TipoDescarga       sat.TipoDescarga
	TipoSolicitud      sat.TipoSolicitud
	RFCContrapartes    []string
	TipoComprobante    string
	EstadoComprobante  sat.EstadoComprobante
	RFCACuentaTerceros string
	Complemento        string
	UUID               string
}

func (r DownloadRequest) consultaRequest(rfc, token string) sat.ConsultaRequest {
	return sat.ConsultaRequest{
		Token:              token,
		RFCSolicitante:     rfc,
		FechaInicial:       r.FechaInicial,
		FechaFinal:         r.FechaFinal,
		TipoDescarga:       r.TipoDescarga,
		TipoSolicitud:      r.TipoSolicitud,
		RFCContrapartes:    append([]string(nil), r.RFCContrapartes...),
		TipoComprobante:    r.TipoComprobante,
		EstadoComprobante:  r.EstadoComprobante,
		RFCACuentaTerceros: r.RFCACuentaTerceros,
		Complemento:        r.Complemento,
		UUID:               r.UUID,
	}
}

// DownloadResult contiene la salida completa del flujo de alto nivel.
type DownloadResult struct {
	Solicitud    *sat.ConsultaResponse
	Verificacion *sat.VerificaSolicitudResponse
	Packages     []DownloadedPackage
}

// DownloadedPackage contiene un paquete SAT ya decodificado y la respuesta de
// bajo nivel asociada.
type DownloadedPackage struct {
	ID       string
	Base64   string
	Bytes    []byte
	Response *sat.DescargaPaqueteResponse
}

// AccessToken contiene un token SAT cacheado y su ventana local de validez.
type AccessToken struct {
	Value      string
	ObtainedAt time.Time
	ExpiresAt  time.Time
}

func (t AccessToken) usableAt(now time.Time, refreshBefore time.Duration) bool {
	if strings.TrimSpace(t.Value) == "" {
		return false
	}
	if t.ExpiresAt.IsZero() {
		return true
	}
	return now.Add(refreshBefore).Before(t.ExpiresAt)
}

// AccessTokenCache almacena tokens para un satflow.Client. Las implementaciones
// personalizadas deberían ser seguras para uso concurrente si el cliente se
// comparte entre goroutines.
type AccessTokenCache interface {
	Load(context.Context) (AccessToken, bool, error)
	Store(context.Context, AccessToken) error
	Clear(context.Context) error
}

// MemoryAccessTokenCache mantiene un solo token en memoria.
type MemoryAccessTokenCache struct {
	mu    sync.Mutex
	token AccessToken
	ok    bool
}

// NewMemoryAccessTokenCache construye una caché de token vacía en memoria.
func NewMemoryAccessTokenCache() *MemoryAccessTokenCache {
	return &MemoryAccessTokenCache{}
}

// Load devuelve el token cacheado, si existe.
func (c *MemoryAccessTokenCache) Load(ctx context.Context) (AccessToken, bool, error) {
	if err := ctx.Err(); err != nil {
		return AccessToken{}, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ok {
		return AccessToken{}, false, nil
	}
	return c.token, true, nil
}

// Store guarda el token cacheado.
func (c *MemoryAccessTokenCache) Store(ctx context.Context, token AccessToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	c.ok = true
	return nil
}

// Clear elimina el token cacheado.
func (c *MemoryAccessTokenCache) Clear(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = AccessToken{}
	c.ok = false
	return nil
}

// PollExceededError indica que Wait agotó la cantidad de intentos configurada.
type PollExceededError struct {
	RequestID string
	Attempts  int
	Last      *sat.VerificaSolicitudResponse
}

func (e *PollExceededError) Error() string {
	if e.Last != nil && strings.TrimSpace(e.Last.Mensaje) != "" {
		return fmt.Sprintf("satflow: el polling excedió el máximo de intentos para la solicitud %s: %s", e.RequestID, e.Last.Mensaje)
	}
	return fmt.Sprintf("satflow: el polling excedió el máximo de intentos para la solicitud %s", e.RequestID)
}

func (e *PollExceededError) Unwrap() error {
	return ErrPollExceeded
}

// TerminalStatusError indica que una solicitud SAT terminó en un estado
// terminal no exitoso, como error, rechazo o vencimiento.
type TerminalStatusError struct {
	RequestID string
	Response  *sat.VerificaSolicitudResponse
}

func (e *TerminalStatusError) Error() string {
	if e.Response == nil {
		return fmt.Sprintf("satflow: la solicitud %s terminó con un estado terminal no exitoso", e.RequestID)
	}
	if msg := strings.TrimSpace(e.Response.Mensaje); msg != "" {
		return fmt.Sprintf(
			"satflow: la solicitud %s terminó con EstadoSolicitud=%d (%s)",
			e.RequestID,
			e.Response.EstadoSolicitud,
			msg,
		)
	}
	return fmt.Sprintf("satflow: la solicitud %s terminó con EstadoSolicitud=%d", e.RequestID, e.Response.EstadoSolicitud)
}

func (e *TerminalStatusError) Unwrap() error {
	return ErrTerminalStatus
}

// InvalidPackagePayloadError indica que el cuerpo de un paquete SAT no pudo
// decodificarse desde base64.
type InvalidPackagePayloadError struct {
	PackageID string
	Err       error
}

func (e *InvalidPackagePayloadError) Error() string {
	if e.PackageID == "" {
		return fmt.Sprintf("satflow: contenido de paquete inválido: %v", e.Err)
	}
	return fmt.Sprintf("satflow: contenido de paquete inválido para %s: %v", e.PackageID, e.Err)
}

func (e *InvalidPackagePayloadError) Unwrap() error {
	if e.Err != nil {
		return errors.Join(ErrInvalidPackagePayload, e.Err)
	}
	return ErrInvalidPackagePayload
}

// Alias retrocompatibles mantenidos mientras el proyecto sigue consolidando su
// nomenclatura.
type Request = DownloadRequest
type Result = DownloadResult
type Package = DownloadedPackage
type Token = AccessToken
type TokenCache = AccessTokenCache
type MemoryTokenCache = MemoryAccessTokenCache
