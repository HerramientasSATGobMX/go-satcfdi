package sat

import (
	"fmt"
	"time"
)

func validateConsulta(req ConsultaRequest, now time.Time) error {
	if err := requireFields(
		requiredField{name: "Token", value: req.Token},
		requiredField{name: "RFCSolicitante", value: req.RFCSolicitante},
		requiredField{name: "TipoDescarga", value: string(req.TipoDescarga)},
		requiredField{name: "TipoSolicitud", value: string(req.TipoSolicitud)},
	); err != nil {
		return err
	}

	if req.FechaInicial.IsZero() || req.FechaFinal.IsZero() {
		return fmt.Errorf("%w: FechaInicial y FechaFinal son requeridas", ErrInvalidRequest)
	}
	if !req.FechaInicial.Before(req.FechaFinal) {
		return fmt.Errorf("%w: FechaInicial debe ser anterior a FechaFinal", ErrInvalidRequest)
	}

	minDate := time.Date(now.UTC().Year()-6, now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	if req.FechaInicial.Before(minDate) {
		return fmt.Errorf("%w: FechaInicial no puede ser anterior a %s", ErrInvalidRequest, minDate.Format("2006-01-02T15:04:05"))
	}

	if !isValidTipoDescarga(req.TipoDescarga) {
		return fmt.Errorf("%w: TipoDescarga no soportado %q", ErrInvalidRequest, req.TipoDescarga)
	}
	if !isValidTipoSolicitud(req.TipoSolicitud) {
		return fmt.Errorf("%w: TipoSolicitud no soportado %q", ErrInvalidRequest, req.TipoSolicitud)
	}
	if !isValidEstadoComprobante(req.EstadoComprobante) {
		return fmt.Errorf("%w: EstadoComprobante no soportado %q", ErrInvalidRequest, req.EstadoComprobante)
	}

	if req.UUID != "" {
		if len(req.RFCContrapartes) > 0 || req.TipoComprobante != "" || req.EstadoComprobante != EstadoComprobanteTodos || req.Complemento != "" || req.RFCACuentaTerceros != "" {
			return fmt.Errorf("%w: UUID no se puede combinar con RFCContrapartes, TipoComprobante, EstadoComprobante, Complemento ni RFCACuentaTerceros", ErrInvalidRequest)
		}
	}

	if req.TipoDescarga == TipoDescargaRecibidos && len(req.RFCContrapartes) > 1 {
		return fmt.Errorf("%w: Recibidos acepta como máximo 1 RFCContraparte", ErrInvalidRequest)
	}
	if req.TipoDescarga == TipoDescargaEmitidos && len(req.RFCContrapartes) > 5 {
		return fmt.Errorf("%w: Emitidos acepta como máximo 5 RFCContrapartes", ErrInvalidRequest)
	}
	if req.TipoDescarga == TipoDescargaRecibidos && req.TipoSolicitud == TipoSolicitudCFDI && req.EstadoComprobante != EstadoComprobanteVigente {
		return fmt.Errorf("%w: Recibidos + CFDI requiere EstadoComprobante Vigente", ErrInvalidRequest)
	}

	return nil
}

func isValidTipoDescarga(value TipoDescarga) bool {
	switch value {
	case TipoDescargaEmitidos, TipoDescargaRecibidos:
		return true
	default:
		return false
	}
}

func isValidTipoSolicitud(value TipoSolicitud) bool {
	switch value {
	case TipoSolicitudCFDI, TipoSolicitudMetadata:
		return true
	default:
		return false
	}
}

func isValidEstadoComprobante(value EstadoComprobante) bool {
	switch value {
	case EstadoComprobanteTodos, EstadoComprobanteVigente, EstadoComprobanteCancelado:
		return true
	default:
		return false
	}
}
