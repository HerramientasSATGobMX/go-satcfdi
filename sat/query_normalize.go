package sat

import (
	"strings"
)

func normalizeConsulta(req ConsultaRequest) ConsultaRequest {
	req.Token = strings.TrimSpace(req.Token)
	req.RFCSolicitante = normalizeRFCValue(req.RFCSolicitante)
	req.TipoDescarga = normalizeTipoDescarga(req.TipoDescarga)
	req.TipoSolicitud = normalizeTipoSolicitud(req.TipoSolicitud)
	req.RFCContrapartes = normalizeRFCValues(req.RFCContrapartes)
	req.TipoComprobante = strings.ToUpper(strings.TrimSpace(req.TipoComprobante))
	req.EstadoComprobante = normalizeEstadoComprobante(req.EstadoComprobante)
	req.RFCACuentaTerceros = normalizeRFCValue(req.RFCACuentaTerceros)
	req.Complemento = strings.TrimSpace(req.Complemento)
	req.UUID = strings.TrimSpace(req.UUID)
	return req
}

func normalizeTipoDescarga(value TipoDescarga) TipoDescarga {
	switch strings.ToLower(strings.TrimSpace(string(value))) {
	case strings.ToLower(string(TipoDescargaEmitidos)):
		return TipoDescargaEmitidos
	case strings.ToLower(string(TipoDescargaRecibidos)):
		return TipoDescargaRecibidos
	default:
		return TipoDescarga(strings.TrimSpace(string(value)))
	}
}

func normalizeTipoSolicitud(value TipoSolicitud) TipoSolicitud {
	switch strings.ToLower(strings.TrimSpace(string(value))) {
	case "xml", strings.ToLower(string(TipoSolicitudCFDI)):
		return TipoSolicitudCFDI
	case strings.ToLower(string(TipoSolicitudMetadata)):
		return TipoSolicitudMetadata
	default:
		return TipoSolicitud(strings.TrimSpace(string(value)))
	}
}

func normalizeEstadoComprobante(value EstadoComprobante) EstadoComprobante {
	switch strings.ToLower(strings.TrimSpace(string(value))) {
	case "", "todos", "all":
		return EstadoComprobanteTodos
	case "1", "active", strings.ToLower(string(EstadoComprobanteVigente)):
		return EstadoComprobanteVigente
	case "0", "cancelled", strings.ToLower(string(EstadoComprobanteCancelado)):
		return EstadoComprobanteCancelado
	default:
		return EstadoComprobante(strings.TrimSpace(string(value)))
	}
}

func normalizeRFCValues(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		rfc := normalizeRFCValue(value)
		if rfc == "" {
			continue
		}
		if _, exists := seen[rfc]; exists {
			continue
		}
		seen[rfc] = struct{}{}
		normalized = append(normalized, rfc)
	}
	return normalized
}

func normalizeRFCValue(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}
