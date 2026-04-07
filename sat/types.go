package sat

import "time"

const (
	EstadoSolicitudTokenInvalido = 0
	EstadoSolicitudAceptada      = 1
	EstadoSolicitudEnProceso     = 2
	EstadoSolicitudTerminada     = 3
	EstadoSolicitudError         = 4
	EstadoSolicitudRechazada     = 5
	EstadoSolicitudVencida       = 6
)

// TipoDescarga identifica si la consulta SAT apunta a documentos emitidos o
// recibidos.
type TipoDescarga string

const (
	TipoDescargaEmitidos  TipoDescarga = "Emitidos"
	TipoDescargaRecibidos TipoDescarga = "Recibidos"
)

// TipoSolicitud identifica si la consulta SAT pide archivos XML de CFDI o
// registros de metadatos.
type TipoSolicitud string

const (
	TipoSolicitudCFDI     TipoSolicitud = "CFDI"
	TipoSolicitudMetadata TipoSolicitud = "Metadata"
)

// EstadoComprobante filtra la consulta SAT por estado del comprobante.
type EstadoComprobante string

const (
	EstadoComprobanteTodos     EstadoComprobante = ""
	EstadoComprobanteVigente   EstadoComprobante = "Vigente"
	EstadoComprobanteCancelado EstadoComprobante = "Cancelado"
)

// ConsultaRequest contiene los datos de la solicitud para crear una consulta
// SAT.
type ConsultaRequest struct {
	Token              string
	RFCSolicitante     string
	FechaInicial       time.Time
	FechaFinal         time.Time
	TipoDescarga       TipoDescarga
	TipoSolicitud      TipoSolicitud
	RFCContrapartes    []string
	TipoComprobante    string
	EstadoComprobante  EstadoComprobante
	RFCACuentaTerceros string
	Complemento        string
	UUID               string
}

// ConsultaResponse contiene la respuesta SAT a una consulta.
type ConsultaResponse struct {
	CodEstatus  string
	Mensaje     string
	IDSolicitud string
}

// VerificaSolicitudRequest contiene los datos para consultar el estado de una
// solicitud SAT existente.
type VerificaSolicitudRequest struct {
	Token          string
	RFCSolicitante string
	IDSolicitud    string
}

// VerificaSolicitudResponse contiene el estado actual SAT y los IDs de
// paquetes.
type VerificaSolicitudResponse struct {
	CodEstatus            string
	EstadoSolicitud       int
	CodigoEstadoSolicitud string
	NumeroCFDIs           int
	Mensaje               string
	Paquetes              []string
}

// DescargaPaqueteRequest contiene los datos de la solicitud para descargar un
// paquete.
type DescargaPaqueteRequest struct {
	Token          string
	RFCSolicitante string
	IDPaquete      string
}

// DescargaPaqueteResponse contiene el paquete base64 crudo devuelto por SAT.
type DescargaPaqueteResponse struct {
	CodEstatus string
	Mensaje    string
	PaqueteB64 string
}

// ValidacionRequest contiene los campos requeridos para validar un CFDI con
// SAT.
type ValidacionRequest struct {
	RFCEmisor   string
	RFCReceptor string
	Total       string
	UUID        string
}

// ValidacionResponse contiene el resultado de validación SAT de un CFDI.
type ValidacionResponse struct {
	CodigoEstatus string
	EsCancelable  string
	Estado        string
}
