package satservice

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	satcfdiv1 "github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1"
	"github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1/satcfdiv1connect"
	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

const (
	defaultUpstreamTimeout        = 15 * time.Second
	defaultPollInterval           = 5 * time.Second
	defaultPollAttempts           = 60
	defaultMaxUnaryRequestBytes   = 10 << 20
	defaultMaxUnaryResponseBytes  = 16 << 20
	defaultMaxUnaryPackageBytes   = 16 << 20
	defaultStreamChunkSize        = 256 << 10
	defaultMaxConcurrentDownloads = 4
	defaultMaxConcurrentStreams   = 4
	handlerMountPath              = "/"

	operationAuthenticate    = "authenticate"
	operationConsultDownload = "consult_download"
	operationVerifyDownload  = "verify_download"
	operationDownloadPackage = "download_package"
	operationStreamDownload  = "stream_download_package"
	operationValidateCFDI    = "validate_cfdi"
	operationRunDownloadFlow = "run_download_flow"
)

var (
	_ satcfdiv1connect.SATServiceHandler     = (*Service)(nil)
	_ satcfdiv1connect.SATFlowServiceHandler = (*Service)(nil)
)

// Config permite personalizar los handlers del servicio y sus límites
// operativos.
type Config struct {
	Client *sat.Client

	Resolver                CredentialResolver
	CredentialFileAllowlist []string

	Logger   *slog.Logger
	Registry *prometheus.Registry
	Tracer   trace.Tracer

	UpstreamTimeout        time.Duration
	PollInterval           time.Duration
	PollMaxAttempts        int
	MaxUnaryRequestBytes   int
	MaxUnaryResponseBytes  int
	MaxUnaryPackageBytes   int
	StreamChunkSize        int
	MaxConcurrentDownloads int
	MaxConcurrentStreams   int
}

// Service expone la superficie SAT de bajo nivel y un servicio separado de
// flujo de alto nivel sin mover la lógica SAT fuera de los paquetes sat y
// satflow.
type Service struct {
	client   *sat.Client
	resolver CredentialResolver
	logger   *slog.Logger
	tracer   trace.Tracer
	metrics  *serviceMetrics

	upstreamTimeout       time.Duration
	pollInterval          time.Duration
	pollMaxAttempts       int
	maxUnaryRequestBytes  int
	maxUnaryResponseBytes int
	maxUnaryPackageBytes  int
	streamChunkSize       int

	downloadSlots chan struct{}
	streamSlots   chan struct{}
}

// NewService construye un servicio reutilizable con valores operativos
// predeterminados ya aplicados.
func NewService(cfg Config) (*Service, error) {
	upstreamTimeout := cfg.UpstreamTimeout
	if upstreamTimeout <= 0 {
		upstreamTimeout = defaultUpstreamTimeout
	}

	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}

	pollMaxAttempts := cfg.PollMaxAttempts
	if pollMaxAttempts <= 0 {
		pollMaxAttempts = defaultPollAttempts
	}

	maxUnaryRequestBytes := cfg.MaxUnaryRequestBytes
	if maxUnaryRequestBytes <= 0 {
		maxUnaryRequestBytes = defaultMaxUnaryRequestBytes
	}

	maxUnaryResponseBytes := cfg.MaxUnaryResponseBytes
	if maxUnaryResponseBytes <= 0 {
		maxUnaryResponseBytes = defaultMaxUnaryResponseBytes
	}

	maxUnaryPackageBytes := cfg.MaxUnaryPackageBytes
	if maxUnaryPackageBytes <= 0 {
		maxUnaryPackageBytes = defaultMaxUnaryPackageBytes
	}

	streamChunkSize := cfg.StreamChunkSize
	if streamChunkSize <= 0 {
		streamChunkSize = defaultStreamChunkSize
	}

	maxConcurrentDownloads := cfg.MaxConcurrentDownloads
	if maxConcurrentDownloads <= 0 {
		maxConcurrentDownloads = defaultMaxConcurrentDownloads
	}

	maxConcurrentStreams := cfg.MaxConcurrentStreams
	if maxConcurrentStreams <= 0 {
		maxConcurrentStreams = defaultMaxConcurrentStreams
	}

	if maxUnaryPackageBytes > maxUnaryResponseBytes {
		return nil, fmt.Errorf("satservice: MaxUnaryPackageBytes debe ser <= MaxUnaryResponseBytes")
	}

	client := cfg.Client
	if client == nil {
		client = sat.NewClient(sat.Config{
			HTTPClient: &http.Client{Timeout: upstreamTimeout},
		})
	}

	resolver := cfg.Resolver
	var err error
	if resolver == nil && len(cfg.CredentialFileAllowlist) > 0 {
		resolver, err = NewFileCredentialResolver(cfg.CredentialFileAllowlist)
		if err != nil {
			return nil, err
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = discardLogger()
	}

	tracer := cfg.Tracer
	if tracer == nil {
		tracer = otel.Tracer("github.com/herramientassatgobmx/go-satcfdi/satservice")
	}

	return &Service{
		client:                client,
		resolver:              resolver,
		logger:                logger,
		tracer:                tracer,
		metrics:               newServiceMetrics(cfg.Registry),
		upstreamTimeout:       upstreamTimeout,
		pollInterval:          pollInterval,
		pollMaxAttempts:       pollMaxAttempts,
		maxUnaryRequestBytes:  maxUnaryRequestBytes,
		maxUnaryResponseBytes: maxUnaryResponseBytes,
		maxUnaryPackageBytes:  maxUnaryPackageBytes,
		streamChunkSize:       streamChunkSize,
		downloadSlots:         make(chan struct{}, maxConcurrentDownloads),
		streamSlots:           make(chan struct{}, maxConcurrentStreams),
	}, nil
}

// NewHandler devuelve un handler HTTP que sirve tanto SATService como
// SATFlowService sobre Connect, gRPC y gRPC-Web.
func NewHandler(cfg Config, opts ...connect.HandlerOption) (string, http.Handler, error) {
	service, err := NewService(cfg)
	if err != nil {
		return "", nil, err
	}
	return handlerMountPath, service.Handler(opts...), nil
}

// Handler construye el handler HTTP combinado para el servicio de bajo nivel y
// el servicio de flujo.
func (s *Service) Handler(opts ...connect.HandlerOption) http.Handler {
	options := s.handlerOptions(opts...)
	satPath, satHandler := satcfdiv1connect.NewSATServiceHandler(s, options...)
	flowPath, flowHandler := satcfdiv1connect.NewSATFlowServiceHandler(s, options...)

	mux := http.NewServeMux()
	mux.Handle(satPath, satHandler)
	mux.Handle(flowPath, flowHandler)
	return mux
}

// MetricsHandler expone el registro de métricas Prometheus del servicio.
func (s *Service) MetricsHandler() http.Handler {
	return s.metrics.handler()
}

// Ready valida la configuración local del servicio sin llamar a SAT.
func (s *Service) Ready(ctx context.Context) error {
	if s.client == nil {
		return errors.New("satservice: client no está configurado")
	}
	if s.streamChunkSize <= 0 {
		return errors.New("satservice: tamaño de bloque de stream inválido")
	}
	if s.maxUnaryRequestBytes <= 0 || s.maxUnaryResponseBytes <= 0 || s.maxUnaryPackageBytes <= 0 {
		return errors.New("satservice: límites unary inválidos")
	}
	if s.resolver != nil {
		return s.resolver.Ready(ctx)
	}
	return nil
}

func (s *Service) Authenticate(
	ctx context.Context,
	req *connect.Request[satcfdiv1.AuthenticateRequest],
) (*connect.Response[satcfdiv1.AuthenticateResponse], error) {
	fiel, err := s.resolveFiel(ctx, req.Msg)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationAuthenticate}))
	}

	callCtx, cancel := s.withUpstreamTimeout(ctx)
	defer cancel()

	token, err := s.client.ObtenerToken(callCtx, fiel)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationAuthenticate}))
	}

	return connect.NewResponse(&satcfdiv1.AuthenticateResponse{
		AccessToken: token,
	}), nil
}

func (s *Service) ConsultDownload(
	ctx context.Context,
	req *connect.Request[satcfdiv1.ConsultDownloadRequest],
) (*connect.Response[satcfdiv1.ConsultDownloadResponse], error) {
	fiel, err := s.resolveFiel(ctx, req.Msg)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationConsultDownload}))
	}

	consulta, err := consultaRequestFromProto(req.Msg)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationConsultDownload}))
	}

	callCtx, cancel := s.withUpstreamTimeout(ctx)
	defer cancel()

	resp, err := s.client.Consultar(callCtx, fiel, consulta)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationConsultDownload}))
	}

	return connect.NewResponse(&satcfdiv1.ConsultDownloadResponse{
		SatStatusCode: resp.CodEstatus,
		SatMessage:    resp.Mensaje,
		RequestId:     resp.IDSolicitud,
	}), nil
}

func (s *Service) VerifyDownload(
	ctx context.Context,
	req *connect.Request[satcfdiv1.VerifyDownloadRequest],
) (*connect.Response[satcfdiv1.VerifyDownloadResponse], error) {
	fiel, err := s.resolveFiel(ctx, req.Msg)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{
			Operation: operationVerifyDownload,
			RequestID: req.Msg.GetRequestId(),
		}))
	}

	callCtx, cancel := s.withUpstreamTimeout(ctx)
	defer cancel()

	resp, err := s.client.VerificarDescarga(callCtx, fiel, sat.VerificaSolicitudRequest{
		Token:          req.Msg.GetAccessToken(),
		RFCSolicitante: req.Msg.GetRfcSolicitante(),
		IDSolicitud:    req.Msg.GetRequestId(),
	})
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{
			Operation: operationVerifyDownload,
			RequestID: req.Msg.GetRequestId(),
		}))
	}

	return connect.NewResponse(&satcfdiv1.VerifyDownloadResponse{
		SatStatusCode:     resp.CodEstatus,
		RequestStatus:     downloadRequestStatusToProto(resp.EstadoSolicitud),
		RequestStatusCode: resp.CodigoEstadoSolicitud,
		CfdiCount:         int32(resp.NumeroCFDIs),
		SatMessage:        resp.Mensaje,
		PackageIds:        append([]string(nil), resp.Paquetes...),
		RawRequestStatus:  int32(resp.EstadoSolicitud),
	}), nil
}

func (s *Service) DownloadPackage(
	ctx context.Context,
	req *connect.Request[satcfdiv1.DownloadPackageRequest],
) (*connect.Response[satcfdiv1.DownloadPackageResponse], error) {
	releaseDownload, err := s.acquire(ctx, s.downloadSlots, s.metrics.inflightDownloads)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{
			Operation: operationDownloadPackage,
			PackageID: req.Msg.GetPackageId(),
		}))
	}
	defer releaseDownload()

	resp, payload, err := s.downloadPackagePayload(ctx, req.Msg, operationDownloadPackage)
	if err != nil {
		return nil, mapError(err)
	}
	if len(payload) > s.maxUnaryPackageBytes {
		return nil, mapError(withErrorContext(&packageTooLargeError{
			Actual: len(payload),
			Limit:  s.maxUnaryPackageBytes,
		}, errorContext{
			Operation:     operationDownloadPackage,
			PackageID:     req.Msg.GetPackageId(),
			SatStatusCode: resp.CodEstatus,
			SatMessage:    resp.Mensaje,
		}))
	}

	return connect.NewResponse(&satcfdiv1.DownloadPackageResponse{
		SatStatusCode: resp.CodEstatus,
		SatMessage:    resp.Mensaje,
		PackageId:     req.Msg.GetPackageId(),
		PackageBase64: resp.PaqueteB64,
		PackageBytes:  payload,
	}), nil
}

func (s *Service) StreamDownloadPackage(
	ctx context.Context,
	req *connect.Request[satcfdiv1.StreamDownloadPackageRequest],
	stream *connect.ServerStream[satcfdiv1.StreamDownloadPackageResponse],
) error {
	releaseStream, err := s.acquire(ctx, s.streamSlots, s.metrics.inflightStreams)
	if err != nil {
		return mapError(withErrorContext(err, errorContext{
			Operation: operationStreamDownload,
			PackageID: req.Msg.GetPackageId(),
		}))
	}
	defer releaseStream()

	releaseDownload, err := s.acquire(ctx, s.downloadSlots, s.metrics.inflightDownloads)
	if err != nil {
		return mapError(withErrorContext(err, errorContext{
			Operation: operationStreamDownload,
			PackageID: req.Msg.GetPackageId(),
		}))
	}
	defer releaseDownload()

	resp, payload, err := s.downloadPackagePayload(ctx, req.Msg, operationStreamDownload)
	if err != nil {
		return mapError(err)
	}

	if len(payload) == 0 {
		return stream.Send(&satcfdiv1.StreamDownloadPackageResponse{
			PackageId:     req.Msg.GetPackageId(),
			Eof:           true,
			TotalBytes:    0,
			SatStatusCode: resp.CodEstatus,
			SatMessage:    resp.Mensaje,
		})
	}

	for offset := 0; offset < len(payload); offset += s.streamChunkSize {
		end := offset + s.streamChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		if err := stream.Send(&satcfdiv1.StreamDownloadPackageResponse{
			PackageId:     req.Msg.GetPackageId(),
			Offset:        int64(offset),
			Data:          payload[offset:end],
			Eof:           end == len(payload),
			TotalBytes:    int64(len(payload)),
			SatStatusCode: resp.CodEstatus,
			SatMessage:    resp.Mensaje,
		}); err != nil {
			return mapError(withErrorContext(err, errorContext{
				Operation:     operationStreamDownload,
				PackageID:     req.Msg.GetPackageId(),
				SatStatusCode: resp.CodEstatus,
				SatMessage:    resp.Mensaje,
			}))
		}
	}

	return nil
}

func (s *Service) ValidateCfdi(
	ctx context.Context,
	req *connect.Request[satcfdiv1.ValidateCfdiRequest],
) (*connect.Response[satcfdiv1.ValidateCfdiResponse], error) {
	callCtx, cancel := s.withUpstreamTimeout(ctx)
	defer cancel()

	resp, err := s.client.ObtenerEstadoCFDI(callCtx, sat.ValidacionRequest{
		RFCEmisor:   req.Msg.GetRfcEmisor(),
		RFCReceptor: req.Msg.GetRfcReceptor(),
		Total:       req.Msg.GetTotal(),
		UUID:        req.Msg.GetUuid(),
	})
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationValidateCFDI}))
	}

	return connect.NewResponse(&satcfdiv1.ValidateCfdiResponse{
		CodigoEstatus: resp.CodigoEstatus,
		EsCancelable:  resp.EsCancelable,
		Estado:        resp.Estado,
	}), nil
}

func (s *Service) RunDownloadFlow(
	ctx context.Context,
	req *connect.Request[satcfdiv1.RunDownloadFlowRequest],
) (*connect.Response[satcfdiv1.RunDownloadFlowResponse], error) {
	fiel, err := s.resolveFiel(ctx, req.Msg)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationRunDownloadFlow}))
	}

	downloadReq, err := flowRequestFromProto(req.Msg)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationRunDownloadFlow}))
	}

	pollPolicy, err := s.pollPolicyFromProto(req.Msg.GetPollPolicy())
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationRunDownloadFlow}))
	}

	flowClient, err := satflow.New(satflow.Config{
		Client:         s.client,
		Fiel:           fiel,
		RFCSolicitante: req.Msg.GetRfcSolicitante(),
		Poll:           pollPolicy,
	})
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationRunDownloadFlow}))
	}

	solicitud, err := flowClient.Submit(ctx, downloadReq)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{Operation: operationRunDownloadFlow}))
	}

	verificacion, err := flowClient.Wait(ctx, solicitud.IDSolicitud)
	if err != nil {
		return nil, mapError(withErrorContext(err, errorContext{
			Operation:     operationRunDownloadFlow,
			RequestID:     solicitud.IDSolicitud,
			SatStatusCode: responseValue(verificacion, func(resp *sat.VerificaSolicitudResponse) string { return resp.CodEstatus }),
			RequestStatusCode: responseValue(verificacion, func(resp *sat.VerificaSolicitudResponse) string {
				return resp.CodigoEstadoSolicitud
			}),
			SatMessage: responseValue(verificacion, func(resp *sat.VerificaSolicitudResponse) string { return resp.Mensaje }),
		}))
	}

	return connect.NewResponse(&satcfdiv1.RunDownloadFlowResponse{
		RequestId:           solicitud.IDSolicitud,
		SubmitSatStatusCode: solicitud.CodEstatus,
		SubmitSatMessage:    solicitud.Mensaje,
		VerifySatStatusCode: verificacion.CodEstatus,
		RequestStatus:       downloadRequestStatusToProto(verificacion.EstadoSolicitud),
		RequestStatusCode:   verificacion.CodigoEstadoSolicitud,
		CfdiCount:           int32(verificacion.NumeroCFDIs),
		VerifySatMessage:    verificacion.Mensaje,
		PackageIds:          append([]string(nil), verificacion.Paquetes...),
		RawRequestStatus:    int32(verificacion.EstadoSolicitud),
	}), nil
}

func (s *Service) handlerOptions(userOpts ...connect.HandlerOption) []connect.HandlerOption {
	options := []connect.HandlerOption{
		connect.WithReadMaxBytes(s.maxUnaryRequestBytes),
		connect.WithSendMaxBytes(s.maxUnaryResponseBytes),
		connect.WithRecover(s.recoverPanic),
		connect.WithInterceptors(
			s.requestIDInterceptor(),
			s.tracingInterceptor(),
			s.metrics.interceptor(),
			s.loggingInterceptor(),
		),
	}
	return append(options, userOpts...)
}

func (s *Service) withUpstreamTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.upstreamTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, s.upstreamTimeout)
}

func (s *Service) acquire(
	ctx context.Context,
	sem chan struct{},
	gauge prometheus.Gauge,
) (func(), error) {
	select {
	case sem <- struct{}{}:
		if gauge != nil {
			gauge.Inc()
		}
		return func() {
			if gauge != nil {
				gauge.Dec()
			}
			<-sem
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Service) downloadPackagePayload(
	ctx context.Context,
	msg interface {
		credentialCarrier
		GetAccessToken() string
		GetRfcSolicitante() string
		GetPackageId() string
	},
	operation string,
) (*sat.DescargaPaqueteResponse, []byte, error) {
	fiel, err := s.resolveFiel(ctx, msg)
	if err != nil {
		return nil, nil, withErrorContext(err, errorContext{
			Operation: operation,
			PackageID: msg.GetPackageId(),
		})
	}

	callCtx, cancel := s.withUpstreamTimeout(ctx)
	defer cancel()

	resp, err := s.client.DescargarPaquete(callCtx, fiel, sat.DescargaPaqueteRequest{
		Token:          msg.GetAccessToken(),
		RFCSolicitante: msg.GetRfcSolicitante(),
		IDPaquete:      msg.GetPackageId(),
	})
	if err != nil {
		return nil, nil, withErrorContext(err, errorContext{
			Operation: operation,
			PackageID: msg.GetPackageId(),
		})
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(resp.PaqueteB64))
	if err != nil {
		return resp, nil, withErrorContext(fmt.Errorf("%w: el cuerpo del paquete no es base64 válido", errInvalidPackagePayload), errorContext{
			Operation:     operation,
			PackageID:     msg.GetPackageId(),
			SatStatusCode: resp.CodEstatus,
			SatMessage:    resp.Mensaje,
		})
	}

	return resp, payload, nil
}

func consultaRequestFromProto(msg *satcfdiv1.ConsultDownloadRequest) (sat.ConsultaRequest, error) {
	fechaInicial, err := requiredTimestamp(msg.GetFechaInicial(), "fecha_inicial")
	if err != nil {
		return sat.ConsultaRequest{}, err
	}
	fechaFinal, err := requiredTimestamp(msg.GetFechaFinal(), "fecha_final")
	if err != nil {
		return sat.ConsultaRequest{}, err
	}

	tipoDescarga, err := downloadTypeFromProto(msg.GetDownloadType())
	if err != nil {
		return sat.ConsultaRequest{}, err
	}
	tipoSolicitud, err := queryTypeFromProto(msg.GetQueryType())
	if err != nil {
		return sat.ConsultaRequest{}, err
	}

	return sat.ConsultaRequest{
		Token:              msg.GetAccessToken(),
		RFCSolicitante:     msg.GetRfcSolicitante(),
		FechaInicial:       fechaInicial,
		FechaFinal:         fechaFinal,
		TipoDescarga:       tipoDescarga,
		TipoSolicitud:      tipoSolicitud,
		RFCContrapartes:    append([]string(nil), msg.GetCounterpartRfc()...),
		TipoComprobante:    msg.GetInvoiceType(),
		EstadoComprobante:  invoiceStatusFromProto(msg.GetInvoiceStatus()),
		RFCACuentaTerceros: msg.GetThirdPartyRfc(),
		Complemento:        msg.GetComplemento(),
		UUID:               msg.GetUuid(),
	}, nil
}

func flowRequestFromProto(msg *satcfdiv1.RunDownloadFlowRequest) (satflow.DownloadRequest, error) {
	fechaInicial, err := requiredTimestamp(msg.GetFechaInicial(), "fecha_inicial")
	if err != nil {
		return satflow.DownloadRequest{}, err
	}
	fechaFinal, err := requiredTimestamp(msg.GetFechaFinal(), "fecha_final")
	if err != nil {
		return satflow.DownloadRequest{}, err
	}

	tipoDescarga, err := downloadTypeFromProto(msg.GetDownloadType())
	if err != nil {
		return satflow.DownloadRequest{}, err
	}
	tipoSolicitud, err := queryTypeFromProto(msg.GetQueryType())
	if err != nil {
		return satflow.DownloadRequest{}, err
	}

	return satflow.DownloadRequest{
		FechaInicial:       fechaInicial,
		FechaFinal:         fechaFinal,
		TipoDescarga:       tipoDescarga,
		TipoSolicitud:      tipoSolicitud,
		RFCContrapartes:    append([]string(nil), msg.GetCounterpartRfc()...),
		TipoComprobante:    msg.GetInvoiceType(),
		EstadoComprobante:  invoiceStatusFromProto(msg.GetInvoiceStatus()),
		RFCACuentaTerceros: msg.GetThirdPartyRfc(),
		Complemento:        msg.GetComplemento(),
		UUID:               msg.GetUuid(),
	}, nil
}

func (s *Service) pollPolicyFromProto(msg *satcfdiv1.PollPolicy) (satflow.PollPolicy, error) {
	policy := satflow.PollPolicy{
		Interval:    s.pollInterval,
		MaxAttempts: s.pollMaxAttempts,
	}
	if msg == nil {
		return policy, nil
	}
	if interval := msg.GetInterval(); interval != nil {
		value, err := durationFromProto(interval, "poll_policy.interval")
		if err != nil {
			return satflow.PollPolicy{}, err
		}
		policy.Interval = value
	}
	if msg.GetMaxAttempts() < 0 {
		return satflow.PollPolicy{}, fmt.Errorf("%w: poll_policy.max_attempts debe ser >= 0", sat.ErrInvalidRequest)
	}
	if msg.GetMaxAttempts() > 0 {
		policy.MaxAttempts = int(msg.GetMaxAttempts())
	}
	return policy, nil
}

func requiredTimestamp(ts *timestamppb.Timestamp, field string) (time.Time, error) {
	if ts == nil {
		return time.Time{}, fmt.Errorf("%w: %s es requerido", sat.ErrInvalidRequest, field)
	}
	if err := ts.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("%w: %s es inválido: %v", sat.ErrInvalidRequest, field, err)
	}
	return ts.AsTime().UTC(), nil
}

func durationFromProto(value *durationpb.Duration, field string) (time.Duration, error) {
	if value == nil {
		return 0, fmt.Errorf("%w: %s es requerido", sat.ErrInvalidRequest, field)
	}
	if err := value.CheckValid(); err != nil {
		return 0, fmt.Errorf("%w: %s es inválido: %v", sat.ErrInvalidRequest, field, err)
	}
	if value.AsDuration() <= 0 {
		return 0, fmt.Errorf("%w: %s debe ser > 0", sat.ErrInvalidRequest, field)
	}
	return value.AsDuration(), nil
}

func downloadTypeFromProto(value satcfdiv1.DownloadType) (sat.TipoDescarga, error) {
	switch value {
	case satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS:
		return sat.TipoDescargaRecibidos, nil
	case satcfdiv1.DownloadType_DOWNLOAD_TYPE_EMITIDOS:
		return sat.TipoDescargaEmitidos, nil
	default:
		return "", fmt.Errorf("%w: download_type es requerido", sat.ErrInvalidRequest)
	}
}

func queryTypeFromProto(value satcfdiv1.QueryType) (sat.TipoSolicitud, error) {
	switch value {
	case satcfdiv1.QueryType_QUERY_TYPE_CFDI:
		return sat.TipoSolicitudCFDI, nil
	case satcfdiv1.QueryType_QUERY_TYPE_METADATA:
		return sat.TipoSolicitudMetadata, nil
	default:
		return "", fmt.Errorf("%w: query_type es requerido", sat.ErrInvalidRequest)
	}
}

func invoiceStatusFromProto(value satcfdiv1.InvoiceStatus) sat.EstadoComprobante {
	switch value {
	case satcfdiv1.InvoiceStatus_INVOICE_STATUS_VIGENTE:
		return sat.EstadoComprobanteVigente
	case satcfdiv1.InvoiceStatus_INVOICE_STATUS_CANCELADO:
		return sat.EstadoComprobanteCancelado
	default:
		return sat.EstadoComprobanteTodos
	}
}

func downloadRequestStatusToProto(value int) satcfdiv1.DownloadRequestStatus {
	switch value {
	case sat.EstadoSolicitudAceptada:
		return satcfdiv1.DownloadRequestStatus_DOWNLOAD_REQUEST_STATUS_ACCEPTED
	case sat.EstadoSolicitudEnProceso:
		return satcfdiv1.DownloadRequestStatus_DOWNLOAD_REQUEST_STATUS_IN_PROGRESS
	case sat.EstadoSolicitudTerminada:
		return satcfdiv1.DownloadRequestStatus_DOWNLOAD_REQUEST_STATUS_FINISHED
	case sat.EstadoSolicitudError:
		return satcfdiv1.DownloadRequestStatus_DOWNLOAD_REQUEST_STATUS_ERROR
	case sat.EstadoSolicitudRechazada:
		return satcfdiv1.DownloadRequestStatus_DOWNLOAD_REQUEST_STATUS_REJECTED
	case sat.EstadoSolicitudVencida:
		return satcfdiv1.DownloadRequestStatus_DOWNLOAD_REQUEST_STATUS_EXPIRED
	default:
		return satcfdiv1.DownloadRequestStatus_DOWNLOAD_REQUEST_STATUS_TOKEN_INVALID
	}
}

func responseValue[T any](value *T, pick func(*T) string) string {
	if value == nil {
		return ""
	}
	return pick(value)
}
