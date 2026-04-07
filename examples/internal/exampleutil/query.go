package exampleutil

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	satcfdiv1 "github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1"
	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

type QueryInput struct {
	RFCSolicitante     string
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

type PollSettings struct {
	Interval    time.Duration
	MaxAttempts int
}

func MustRFCSolicitante() string {
	return RequireAny("SAT_RFC_SOLICITANTE", "SAT_RFC")
}

func MustQueryInput() QueryInput {
	now := time.Now().UTC()
	query := QueryInput{
		RFCSolicitante:     MustRFCSolicitante(),
		FechaInicial:       parseTimeEnv("SAT_FECHA_INICIAL", now.AddDate(0, 0, -7), false),
		FechaFinal:         parseTimeEnv("SAT_FECHA_FINAL", now, true),
		TipoDescarga:       parseDownloadType(Env("SAT_TIPO_DESCARGA", "recibidos")),
		TipoSolicitud:      parseQueryType(Env("SAT_TIPO_SOLICITUD", "CFDI")),
		RFCContrapartes:    SplitCSV(Optional("SAT_RFC_CONTRAPARTES")),
		TipoComprobante:    Optional("SAT_TIPO_COMPROBANTE"),
		RFCACuentaTerceros: Optional("SAT_RFC_TERCERO"),
		Complemento:        Optional("SAT_COMPLEMENTO"),
		UUID:               Optional("SAT_UUID"),
	}

	if raw := Optional("SAT_ESTADO_COMPROBANTE"); raw != "" {
		query.EstadoComprobante = parseInvoiceStatus(raw)
	} else if query.TipoDescarga == sat.TipoDescargaRecibidos && query.TipoSolicitud == sat.TipoSolicitudCFDI {
		query.EstadoComprobante = sat.EstadoComprobanteVigente
	}

	if !query.FechaInicial.Before(query.FechaFinal) {
		Usagef("SAT_FECHA_INICIAL debe ser menor que SAT_FECHA_FINAL")
	}

	return query
}

func MustPollSettings() PollSettings {
	settings := PollSettings{
		Interval:    5 * time.Second,
		MaxAttempts: 60,
	}

	if raw := Optional("SAT_POLL_INTERVAL"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil {
			Usagef("SAT_POLL_INTERVAL debe ser un duration válido: %v", err)
		}
		settings.Interval = value
	}

	if raw := Optional("SAT_POLL_MAX_ATTEMPTS"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			Usagef("SAT_POLL_MAX_ATTEMPTS debe ser un entero válido: %v", err)
		}
		if value <= 0 {
			Usagef("SAT_POLL_MAX_ATTEMPTS debe ser > 0")
		}
		settings.MaxAttempts = value
	}

	return settings
}

func (q QueryInput) SATConsulta(token string) sat.ConsultaRequest {
	return sat.ConsultaRequest{
		Token:              token,
		RFCSolicitante:     q.RFCSolicitante,
		FechaInicial:       q.FechaInicial,
		FechaFinal:         q.FechaFinal,
		TipoDescarga:       q.TipoDescarga,
		TipoSolicitud:      q.TipoSolicitud,
		RFCContrapartes:    append([]string(nil), q.RFCContrapartes...),
		TipoComprobante:    q.TipoComprobante,
		EstadoComprobante:  q.EstadoComprobante,
		RFCACuentaTerceros: q.RFCACuentaTerceros,
		Complemento:        q.Complemento,
		UUID:               q.UUID,
	}
}

func (q QueryInput) SATFlowRequest() satflow.DownloadRequest {
	return satflow.DownloadRequest{
		FechaInicial:       q.FechaInicial,
		FechaFinal:         q.FechaFinal,
		TipoDescarga:       q.TipoDescarga,
		TipoSolicitud:      q.TipoSolicitud,
		RFCContrapartes:    append([]string(nil), q.RFCContrapartes...),
		TipoComprobante:    q.TipoComprobante,
		EstadoComprobante:  q.EstadoComprobante,
		RFCACuentaTerceros: q.RFCACuentaTerceros,
		Complemento:        q.Complemento,
		UUID:               q.UUID,
	}
}

func (q QueryInput) ProtoRunDownloadFlowRequest(creds ServiceCredentialSource, poll PollSettings) *satcfdiv1.RunDownloadFlowRequest {
	return &satcfdiv1.RunDownloadFlowRequest{
		Credentials:    creds.Credentials,
		CredentialRef:  creds.CredentialRef,
		RfcSolicitante: q.RFCSolicitante,
		FechaInicial:   timestamppb.New(q.FechaInicial),
		FechaFinal:     timestamppb.New(q.FechaFinal),
		DownloadType:   protoDownloadType(q.TipoDescarga),
		QueryType:      protoQueryType(q.TipoSolicitud),
		CounterpartRfc: append([]string(nil), q.RFCContrapartes...),
		InvoiceType:    q.TipoComprobante,
		InvoiceStatus:  protoInvoiceStatus(q.EstadoComprobante),
		ThirdPartyRfc:  q.RFCACuentaTerceros,
		Complemento:    q.Complemento,
		Uuid:           q.UUID,
		PollPolicy: &satcfdiv1.PollPolicy{
			Interval:    durationpb.New(poll.Interval),
			MaxAttempts: int32(poll.MaxAttempts),
		},
	}
}

func (p PollSettings) SATFlowPolicy() satflow.PollPolicy {
	return satflow.PollPolicy{
		Interval:    p.Interval,
		MaxAttempts: p.MaxAttempts,
	}
}

func SATRequestStatusName(value int) string {
	switch value {
	case sat.EstadoSolicitudTokenInvalido:
		return "TOKEN_INVALID"
	case sat.EstadoSolicitudAceptada:
		return "ACCEPTED"
	case sat.EstadoSolicitudEnProceso:
		return "IN_PROGRESS"
	case sat.EstadoSolicitudTerminada:
		return "FINISHED"
	case sat.EstadoSolicitudError:
		return "ERROR"
	case sat.EstadoSolicitudRechazada:
		return "REJECTED"
	case sat.EstadoSolicitudVencida:
		return "EXPIRED"
	default:
		return fmt.Sprintf("UNKNOWN_%d", value)
	}
}

func parseTimeEnv(name string, fallback time.Time, endOfDay bool) time.Time {
	raw := Optional(name)
	if raw == "" {
		return fallback.UTC()
	}
	value, err := parseFlexibleTime(raw, endOfDay)
	if err != nil {
		Usagef("%s debe ser RFC3339 o YYYY-MM-DD: %v", name, err)
	}
	return value.UTC()
}

func parseFlexibleTime(raw string, endOfDay bool) (time.Time, error) {
	if value, err := time.Parse(time.RFC3339, raw); err == nil {
		return value.UTC(), nil
	}
	if value, err := time.Parse("2006-01-02", raw); err == nil {
		if endOfDay {
			return value.Add(23*time.Hour + 59*time.Minute + 59*time.Second).UTC(), nil
		}
		return value.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("valor %q inválido", raw)
}

func parseDownloadType(raw string) sat.TipoDescarga {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "recibidos":
		return sat.TipoDescargaRecibidos
	case "emitidos":
		return sat.TipoDescargaEmitidos
	default:
		Usagef("SAT_TIPO_DESCARGA debe ser recibidos o emitidos")
		return ""
	}
}

func parseQueryType(raw string) sat.TipoSolicitud {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "cfdi":
		return sat.TipoSolicitudCFDI
	case "metadata":
		return sat.TipoSolicitudMetadata
	default:
		Usagef("SAT_TIPO_SOLICITUD debe ser CFDI o Metadata")
		return ""
	}
}

func parseInvoiceStatus(raw string) sat.EstadoComprobante {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "todos", "all":
		return sat.EstadoComprobanteTodos
	case "vigente":
		return sat.EstadoComprobanteVigente
	case "cancelado":
		return sat.EstadoComprobanteCancelado
	default:
		Usagef("SAT_ESTADO_COMPROBANTE debe ser todos, vigente o cancelado")
		return ""
	}
}

func protoDownloadType(value sat.TipoDescarga) satcfdiv1.DownloadType {
	switch value {
	case sat.TipoDescargaEmitidos:
		return satcfdiv1.DownloadType_DOWNLOAD_TYPE_EMITIDOS
	default:
		return satcfdiv1.DownloadType_DOWNLOAD_TYPE_RECIBIDOS
	}
}

func protoQueryType(value sat.TipoSolicitud) satcfdiv1.QueryType {
	switch value {
	case sat.TipoSolicitudMetadata:
		return satcfdiv1.QueryType_QUERY_TYPE_METADATA
	default:
		return satcfdiv1.QueryType_QUERY_TYPE_CFDI
	}
}

func protoInvoiceStatus(value sat.EstadoComprobante) satcfdiv1.InvoiceStatus {
	switch value {
	case sat.EstadoComprobanteVigente:
		return satcfdiv1.InvoiceStatus_INVOICE_STATUS_VIGENTE
	case sat.EstadoComprobanteCancelado:
		return satcfdiv1.InvoiceStatus_INVOICE_STATUS_CANCELADO
	default:
		return satcfdiv1.InvoiceStatus_INVOICE_STATUS_ALL
	}
}
