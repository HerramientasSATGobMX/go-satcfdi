package satflow

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
)

// Client orquesta el flujo SAT de autenticación, solicitud, verificación y
// descarga reutilizando al paquete sat como núcleo de ejecución de bajo nivel.
type Client struct {
	client         *sat.Client
	fiel           *sat.Fiel
	rfcSolicitante string
	tokenCache     AccessTokenCache
	tokenTTL       time.Duration
	refreshBefore  time.Duration
	retry          RetryPolicy
	poll           PollPolicy
	clock          func() time.Time
	sleep          func(context.Context, time.Duration) error

	authMu      sync.Mutex
	stateMu     sync.Mutex
	cachedToken *AccessToken
	cacheLoaded bool
}

// New construye un cliente SAT de flujo de alto nivel.
func New(cfg Config) (*Client, error) {
	if cfg.Fiel == nil {
		return nil, sat.ErrNilFiel
	}

	rfcSolicitante := strings.ToUpper(strings.TrimSpace(cfg.RFCSolicitante))
	if rfcSolicitante == "" {
		return nil, fmt.Errorf("satflow: RFCSolicitante es requerido")
	}

	tokenTTL := cfg.TokenTTL
	if tokenTTL <= 0 {
		tokenTTL = defaultTokenTTL
	}

	refreshBefore := cfg.RefreshBefore
	if refreshBefore < 0 {
		return nil, fmt.Errorf("satflow: RefreshBefore debe ser >= 0")
	}
	if refreshBefore == 0 {
		refreshBefore = defaultRefreshBefore
		if refreshBefore >= tokenTTL {
			refreshBefore = tokenTTL / 10
		}
	}
	if refreshBefore >= tokenTTL {
		return nil, fmt.Errorf("satflow: RefreshBefore debe ser menor que TokenTTL")
	}

	retry := cfg.Retry
	if retry.MaxAttempts <= 0 {
		retry.MaxAttempts = defaultRetryAttempts
	}
	if retry.InitialBackoff <= 0 {
		retry.InitialBackoff = defaultRetryBackoff
	}
	if retry.MaxBackoff <= 0 {
		retry.MaxBackoff = defaultRetryMaxWait
	}
	if retry.MaxBackoff < retry.InitialBackoff {
		retry.MaxBackoff = retry.InitialBackoff
	}

	poll := cfg.Poll
	if poll.Interval <= 0 {
		poll.Interval = defaultPollInterval
	}
	if poll.MaxAttempts <= 0 {
		poll.MaxAttempts = defaultPollAttempts
	}

	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	sleep := cfg.Sleep
	if sleep == nil {
		sleep = sleepContext
	}

	client := cfg.Client
	if client == nil {
		client = sat.NewClient(sat.Config{})
	}

	cache := cfg.TokenCache
	if cache == nil {
		cache = NewMemoryAccessTokenCache()
	}

	return &Client{
		client:         client,
		fiel:           cfg.Fiel,
		rfcSolicitante: rfcSolicitante,
		tokenCache:     cache,
		tokenTTL:       tokenTTL,
		refreshBefore:  refreshBefore,
		retry:          retry,
		poll:           poll,
		clock:          clock,
		sleep:          sleep,
	}, nil
}

// NewClient se mantiene como alias de conveniencia sobre New.
func NewClient(cfg Config) (*Client, error) {
	return New(cfg)
}

// Authenticate devuelve un token SAT cacheado o autentica para obtener uno
// nuevo.
func (c *Client) Authenticate(ctx context.Context) (AccessToken, error) {
	if token, ok, err := c.currentToken(ctx); err != nil || ok {
		return token, err
	}

	c.authMu.Lock()
	defer c.authMu.Unlock()

	if token, ok, err := c.currentToken(ctx); err != nil || ok {
		return token, err
	}

	value, err := retryCall(c, ctx, func(ctx context.Context) (string, error) {
		return c.client.ObtenerToken(ctx, c.fiel)
	})
	if err != nil {
		return AccessToken{}, err
	}

	now := c.clock().UTC()
	token := AccessToken{
		Value:      strings.TrimSpace(value),
		ObtainedAt: now,
		ExpiresAt:  now.Add(c.tokenTTL),
	}
	if token.Value == "" {
		return AccessToken{}, fmt.Errorf("satflow: la autenticación devolvió un token vacío")
	}
	if err := c.storeToken(ctx, token); err != nil {
		return AccessToken{}, err
	}
	return token, nil
}

// Token se mantiene como alias de conveniencia sobre Authenticate.
func (c *Client) Token(ctx context.Context) (AccessToken, error) {
	return c.Authenticate(ctx)
}

// InvalidateAccessToken limpia la caché local y externa del token.
func (c *Client) InvalidateAccessToken(ctx context.Context) error {
	c.stateMu.Lock()
	c.cachedToken = nil
	c.cacheLoaded = true
	c.stateMu.Unlock()
	return c.tokenCache.Clear(ctx)
}

// InvalidateToken se mantiene como alias de conveniencia sobre
// InvalidateAccessToken.
func (c *Client) InvalidateToken(ctx context.Context) error {
	return c.InvalidateAccessToken(ctx)
}

// Submit crea una solicitud SAT usando manejo automático de token.
func (c *Client) Submit(ctx context.Context, req DownloadRequest) (*sat.ConsultaResponse, error) {
	return withToken(c, ctx, func(ctx context.Context, token string) (*sat.ConsultaResponse, error) {
		return c.client.Consultar(ctx, c.fiel, req.consultaRequest(c.rfcSolicitante, token))
	}, nil)
}

// SubmitRequest se mantiene como alias explícito de Submit.
func (c *Client) SubmitRequest(ctx context.Context, req DownloadRequest) (*sat.ConsultaResponse, error) {
	return c.Submit(ctx, req)
}

// Verify consulta el estado SAT actual para un ID de solicitud existente.
func (c *Client) Verify(ctx context.Context, requestID string) (*sat.VerificaSolicitudResponse, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, fmt.Errorf("satflow: requestID es requerido")
	}

	return withToken(c, ctx, func(ctx context.Context, token string) (*sat.VerificaSolicitudResponse, error) {
		return c.client.VerificarDescarga(ctx, c.fiel, sat.VerificaSolicitudRequest{
			Token:          token,
			RFCSolicitante: c.rfcSolicitante,
			IDSolicitud:    requestID,
		})
	}, func(resp *sat.VerificaSolicitudResponse, _ error) bool {
		return resp != nil && resp.EstadoSolicitud == sat.EstadoSolicitudTokenInvalido
	})
}

// CheckRequest se mantiene como alias explícito de Verify.
func (c *Client) CheckRequest(ctx context.Context, requestID string) (*sat.VerificaSolicitudResponse, error) {
	return c.Verify(ctx, requestID)
}

// Wait hace polling contra SAT hasta que la solicitud alcance un estado
// terminal.
func (c *Client) Wait(ctx context.Context, requestID string) (*sat.VerificaSolicitudResponse, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, fmt.Errorf("satflow: requestID es requerido")
	}

	for attempt := 1; attempt <= c.poll.MaxAttempts; attempt++ {
		resp, err := c.Verify(ctx, requestID)
		if err != nil {
			return resp, err
		}

		switch resp.EstadoSolicitud {
		case sat.EstadoSolicitudAceptada, sat.EstadoSolicitudEnProceso:
			if attempt == c.poll.MaxAttempts {
				return resp, &PollExceededError{
					RequestID: requestID,
					Attempts:  attempt,
					Last:      resp,
				}
			}
			if err := c.sleep(ctx, c.poll.Interval); err != nil {
				return resp, err
			}
		case sat.EstadoSolicitudTerminada:
			return resp, nil
		case sat.EstadoSolicitudError, sat.EstadoSolicitudRechazada, sat.EstadoSolicitudVencida:
			return resp, &TerminalStatusError{
				RequestID: requestID,
				Response:  resp,
			}
		default:
			return resp, fmt.Errorf(
				"satflow: EstadoSolicitud=%d inesperado para la solicitud %s",
				resp.EstadoSolicitud,
				requestID,
			)
		}
	}

	return nil, &PollExceededError{RequestID: requestID, Attempts: c.poll.MaxAttempts}
}

// WaitForCompletion se mantiene como alias explícito de Wait.
func (c *Client) WaitForCompletion(ctx context.Context, requestID string) (*sat.VerificaSolicitudResponse, error) {
	return c.Wait(ctx, requestID)
}

// FetchPackage descarga y decodifica un solo paquete SAT con manejo automático
// de token.
func (c *Client) FetchPackage(ctx context.Context, packageID string) (*DownloadedPackage, error) {
	packageID = strings.TrimSpace(packageID)
	if packageID == "" {
		return nil, fmt.Errorf("satflow: packageID es requerido")
	}

	resp, err := withToken(c, ctx, func(ctx context.Context, token string) (*sat.DescargaPaqueteResponse, error) {
		return c.client.DescargarPaquete(ctx, c.fiel, sat.DescargaPaqueteRequest{
			Token:          token,
			RFCSolicitante: c.rfcSolicitante,
			IDPaquete:      packageID,
		})
	}, nil)
	if err != nil {
		return nil, err
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(resp.PaqueteB64))
	if err != nil {
		return nil, &InvalidPackagePayloadError{
			PackageID: packageID,
			Err:       err,
		}
	}

	return &DownloadedPackage{
		ID:       packageID,
		Base64:   resp.PaqueteB64,
		Bytes:    payload,
		Response: resp,
	}, nil
}

// DownloadPackage se mantiene como alias de conveniencia sobre FetchPackage.
func (c *Client) DownloadPackage(ctx context.Context, packageID string) (*DownloadedPackage, error) {
	return c.FetchPackage(ctx, packageID)
}

// FetchPackages descarga en orden los IDs de paquete SAT proporcionados.
func (c *Client) FetchPackages(ctx context.Context, packageIDs []string) ([]DownloadedPackage, error) {
	packages := make([]DownloadedPackage, 0, len(packageIDs))
	for _, packageID := range packageIDs {
		id := strings.TrimSpace(packageID)
		if id == "" {
			continue
		}

		pkg, err := c.FetchPackage(ctx, id)
		if err != nil {
			return packages, err
		}
		packages = append(packages, *pkg)
	}
	return packages, nil
}

// DownloadPackages se mantiene como alias de conveniencia sobre FetchPackages.
func (c *Client) DownloadPackages(ctx context.Context, packageIDs []string) ([]DownloadedPackage, error) {
	return c.FetchPackages(ctx, packageIDs)
}

// Download ejecuta el flujo completo: autenticar, enviar la solicitud, hacer
// polling y descargar cada paquete devuelto.
func (c *Client) Download(ctx context.Context, req DownloadRequest) (*DownloadResult, error) {
	result := &DownloadResult{}

	solicitud, err := c.Submit(ctx, req)
	result.Solicitud = solicitud
	if err != nil {
		return result, err
	}

	verificacion, err := c.Wait(ctx, solicitud.IDSolicitud)
	result.Verificacion = verificacion
	if err != nil {
		return result, err
	}

	packages, err := c.FetchPackages(ctx, verificacion.Paquetes)
	result.Packages = packages
	if err != nil {
		return result, err
	}

	return result, nil
}

// Run se mantiene como alias corto de Download.
func (c *Client) Run(ctx context.Context, req DownloadRequest) (*DownloadResult, error) {
	return c.Download(ctx, req)
}

func (c *Client) currentToken(ctx context.Context) (AccessToken, bool, error) {
	if err := ctx.Err(); err != nil {
		return AccessToken{}, false, err
	}

	c.stateMu.Lock()
	if c.cachedToken != nil {
		token := *c.cachedToken
		c.stateMu.Unlock()
		if token.usableAt(c.clock().UTC(), c.refreshBefore) {
			return token, true, nil
		}
		return AccessToken{}, false, nil
	}
	cacheLoaded := c.cacheLoaded
	c.stateMu.Unlock()

	if cacheLoaded {
		return AccessToken{}, false, nil
	}

	token, ok, err := c.tokenCache.Load(ctx)
	if err != nil {
		return AccessToken{}, false, err
	}

	c.stateMu.Lock()
	c.cacheLoaded = true
	if ok && token.usableAt(c.clock().UTC(), c.refreshBefore) {
		cached := token
		c.cachedToken = &cached
	} else {
		c.cachedToken = nil
	}
	cached := c.cachedToken
	c.stateMu.Unlock()

	if cached == nil {
		return AccessToken{}, false, nil
	}
	return *cached, true, nil
}

func (c *Client) storeToken(ctx context.Context, token AccessToken) error {
	if err := c.tokenCache.Store(ctx, token); err != nil {
		return err
	}

	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.cacheLoaded = true
	cached := token
	c.cachedToken = &cached
	return nil
}

func withToken[T any](
	c *Client,
	ctx context.Context,
	call func(context.Context, string) (T, error),
	tokenInvalid func(T, error) bool,
) (T, error) {
	var zero T

	for authAttempt := 0; authAttempt < 2; authAttempt++ {
		token, err := c.Authenticate(ctx)
		if err != nil {
			return zero, err
		}

		resp, err := retryCall(c, ctx, func(ctx context.Context) (T, error) {
			return call(ctx, token.Value)
		})

		if tokenInvalid != nil && tokenInvalid(resp, err) {
			if authAttempt == 1 {
				return resp, fmt.Errorf("satflow: token inválido después del refresh")
			}
			if invalidateErr := c.InvalidateAccessToken(ctx); invalidateErr != nil {
				return zero, invalidateErr
			}
			continue
		}

		if err != nil && sat.IsAuthenticationError(err) {
			if authAttempt == 1 {
				return resp, err
			}
			if invalidateErr := c.InvalidateAccessToken(ctx); invalidateErr != nil {
				return zero, invalidateErr
			}
			continue
		}

		return resp, err
	}

	return zero, fmt.Errorf("satflow: se agotaron los intentos de refresh de autenticación")
}

func retryCall[T any](c *Client, ctx context.Context, call func(context.Context) (T, error)) (T, error) {
	var zero T
	var lastResp T

	for attempt := 1; attempt <= c.retry.MaxAttempts; attempt++ {
		resp, err := call(ctx)
		lastResp = resp
		if err == nil {
			return resp, nil
		}
		if attempt == c.retry.MaxAttempts || !sat.IsRetryableError(err) {
			return resp, err
		}
		if err := c.sleep(ctx, c.backoff(attempt)); err != nil {
			return lastResp, err
		}
	}

	return zero, fmt.Errorf("satflow: el ciclo de reintentos terminó de forma inesperada")
}

func (c *Client) backoff(attempt int) time.Duration {
	wait := c.retry.InitialBackoff
	for i := 1; i < attempt; i++ {
		wait *= 2
		if wait >= c.retry.MaxBackoff {
			return c.retry.MaxBackoff
		}
	}
	if wait > c.retry.MaxBackoff {
		return c.retry.MaxBackoff
	}
	return wait
}

func sleepContext(ctx context.Context, wait time.Duration) error {
	if wait <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
