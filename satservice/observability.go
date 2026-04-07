package satservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const requestIDHeader = "X-Request-Id"

type requestIDContextKey struct{}

type serviceMetrics struct {
	registry          *prometheus.Registry
	requestsTotal     *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	inflightDownloads prometheus.Gauge
	inflightStreams   prometheus.Gauge
}

type dualInterceptor struct {
	unary            func(connect.UnaryFunc) connect.UnaryFunc
	streamingHandler func(connect.StreamingHandlerFunc) connect.StreamingHandlerFunc
}

func newServiceMetrics(registry *prometheus.Registry) *serviceMetrics {
	if registry == nil {
		registry = prometheus.NewRegistry()
	}

	metrics := &serviceMetrics{
		registry: registry,
		requestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "satservice_rpc_requests_total",
				Help: "Total de solicitudes RPC atendidas por satservice.",
			},
			[]string{"procedure", "protocol", "code", "stream_type"},
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "satservice_rpc_duration_seconds",
				Help:    "Duración de solicitudes RPC en segundos.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"procedure", "protocol", "code", "stream_type"},
		),
		inflightDownloads: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "satservice_downloads_inflight",
				Help: "Cantidad actual de descargas de paquetes SAT en curso.",
			},
		),
		inflightStreams: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "satservice_streams_inflight",
				Help: "Cantidad actual de RPCs de streaming de paquetes en curso.",
			},
		),
	}

	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		metrics.requestsTotal,
		metrics.requestDuration,
		metrics.inflightDownloads,
		metrics.inflightStreams,
	)

	return metrics
}

func (m *serviceMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *serviceMetrics) interceptor() connect.Interceptor {
	return dualInterceptor{
		unary: func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				start := time.Now()
				resp, err := next(ctx, req)
				labels := []string{
					req.Spec().Procedure,
					req.Peer().Protocol,
					connect.CodeOf(err).String(),
					req.Spec().StreamType.String(),
				}
				m.requestsTotal.WithLabelValues(labels...).Inc()
				m.requestDuration.WithLabelValues(labels...).Observe(time.Since(start).Seconds())
				return resp, err
			}
		},
		streamingHandler: func(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
			return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
				start := time.Now()
				err := next(ctx, conn)
				labels := []string{
					conn.Spec().Procedure,
					conn.Peer().Protocol,
					connect.CodeOf(err).String(),
					conn.Spec().StreamType.String(),
				}
				m.requestsTotal.WithLabelValues(labels...).Inc()
				m.requestDuration.WithLabelValues(labels...).Observe(time.Since(start).Seconds())
				return err
			}
		},
	}
}

func (s *Service) requestIDInterceptor() connect.Interceptor {
	return dualInterceptor{
		unary: func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				requestID := incomingOrGeneratedRequestID(req.Header())
				ctx = context.WithValue(ctx, requestIDContextKey{}, requestID)
				if info, ok := connect.CallInfoForHandlerContext(ctx); ok {
					info.ResponseHeader().Set(requestIDHeader, requestID)
				}
				return next(ctx, req)
			}
		},
		streamingHandler: func(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
			return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
				requestID := incomingOrGeneratedRequestID(conn.RequestHeader())
				ctx = context.WithValue(ctx, requestIDContextKey{}, requestID)
				conn.ResponseHeader().Set(requestIDHeader, requestID)
				return next(ctx, conn)
			}
		},
	}
}

func (s *Service) tracingInterceptor() connect.Interceptor {
	tracer := s.tracer
	if tracer == nil {
		tracer = otel.Tracer("github.com/herramientassatgobmx/go-satcfdi/satservice")
	}

	return dualInterceptor{
		unary: func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				ctx, span := tracer.Start(ctx, req.Spec().Procedure,
					trace.WithAttributes(
						attribute.String("rpc.system", req.Peer().Protocol),
						attribute.String("rpc.method", req.Spec().Procedure),
						attribute.String("net.peer.addr", req.Peer().Addr),
					),
				)
				defer span.End()

				resp, err := next(ctx, req)
				if err != nil {
					span.RecordError(err)
					span.SetStatus(otelcodes.Error, connect.CodeOf(err).String())
				} else {
					span.SetStatus(otelcodes.Ok, "ok")
				}
				return resp, err
			}
		},
		streamingHandler: func(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
			return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
				ctx, span := tracer.Start(ctx, conn.Spec().Procedure,
					trace.WithAttributes(
						attribute.String("rpc.system", conn.Peer().Protocol),
						attribute.String("rpc.method", conn.Spec().Procedure),
						attribute.String("net.peer.addr", conn.Peer().Addr),
					),
				)
				defer span.End()

				err := next(ctx, conn)
				if err != nil {
					span.RecordError(err)
					span.SetStatus(otelcodes.Error, connect.CodeOf(err).String())
				} else {
					span.SetStatus(otelcodes.Ok, "ok")
				}
				return err
			}
		},
	}
}

func (s *Service) loggingInterceptor() connect.Interceptor {
	logger := s.logger
	return dualInterceptor{
		unary: func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				start := time.Now()
				resp, err := next(ctx, req)
				s.logRPC(ctx, logger, req.Spec(), req.Peer(), time.Since(start), err)
				return resp, err
			}
		},
		streamingHandler: func(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
			return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
				start := time.Now()
				err := next(ctx, conn)
				s.logRPC(ctx, logger, conn.Spec(), conn.Peer(), time.Since(start), err)
				return err
			}
		},
	}
}

func (s *Service) logRPC(
	ctx context.Context,
	logger *slog.Logger,
	spec connect.Spec,
	peer connect.Peer,
	duration time.Duration,
	err error,
) {
	if logger == nil {
		return
	}

	level := slog.LevelInfo
	if err != nil {
		level = slog.LevelWarn
	}

	logger.LogAttrs(
		ctx,
		level,
		"rpc",
		slog.String("request_id", RequestIDFromContext(ctx)),
		slog.String("procedure", spec.Procedure),
		slog.String("protocol", peer.Protocol),
		slog.String("peer_addr", peer.Addr),
		slog.String("stream_type", spec.StreamType.String()),
		slog.String("code", connect.CodeOf(err).String()),
		slog.Int64("duration_ms", duration.Milliseconds()),
	)
}

func (s *Service) recoverPanic(ctx context.Context, spec connect.Spec, _ http.Header, recovered any) error {
	if s.logger != nil {
		s.logger.LogAttrs(
			ctx,
			slog.LevelError,
			"rpc panic recovered",
			slog.String("request_id", RequestIDFromContext(ctx)),
			slog.String("procedure", spec.Procedure),
			slog.String("panic_type", fmt.Sprintf("%T", recovered)),
		)
	}
	return connect.NewError(connect.CodeInternal, errors.New("internal server error"))
}

// RequestIDFromContext devuelve el identificador de solicitud asignado por
// satservice.
func RequestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func incomingOrGeneratedRequestID(header http.Header) string {
	if candidate := sanitizeRequestID(header.Get(requestIDHeader)); candidate != "" {
		return candidate
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}

func sanitizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return ""
		}
	}
	return value
}

func (i dualInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	if i.unary == nil {
		return next
	}
	return i.unary(next)
}

func (i dualInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i dualInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	if i.streamingHandler == nil {
		return next
	}
	return i.streamingHandler(next)
}
