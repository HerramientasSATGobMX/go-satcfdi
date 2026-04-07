package sat

import (
	"fmt"

	"github.com/beevik/etree"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
)

const requestTimeFormat = "2006-01-02T15:04:05"

type consultaSpec struct {
	templateName string
	action       string
	bodyPath     []string
	responsePath []string
	populate     func(*etree.Element) error
}

func translateConsulta(req ConsultaRequest) consultaSpec {
	spec := consultaSpec{
		templateName: "solicita_recibidos.xml",
		action:       solicitaRecSOAPAction,
		bodyPath:     []string{"s:Body", "des:SolicitaDescargaRecibidos", "des:solicitud"},
		responsePath: []string{"Body", "SolicitaDescargaRecibidosResponse", "SolicitaDescargaRecibidosResult"},
	}
	if req.TipoDescarga == TipoDescargaEmitidos {
		spec.templateName = "solicita_emitidos.xml"
		spec.action = solicitaEmitSOAPAction
		spec.bodyPath = []string{"s:Body", "des:SolicitaDescargaEmitidos", "des:solicitud"}
		spec.responsePath = []string{"Body", "SolicitaDescargaEmitidosResponse", "SolicitaDescargaEmitidosResult"}
	}

	spec.populate = func(root *etree.Element) error {
		solicitud := soap.FindElement(root, spec.bodyPath...)
		if solicitud == nil {
			return fmt.Errorf("sat: solicitud node not found")
		}

		soap.SetAttr(solicitud, "RfcSolicitante", req.RFCSolicitante)
		soap.SetAttr(solicitud, "TipoSolicitud", string(req.TipoSolicitud))
		soap.SetAttr(solicitud, "FechaInicial", req.FechaInicial.UTC().Format(requestTimeFormat))
		soap.SetAttr(solicitud, "FechaFinal", req.FechaFinal.UTC().Format(requestTimeFormat))
		setOptionalAttr(solicitud, "TipoComprobante", req.TipoComprobante)
		setOptionalAttr(solicitud, "EstadoComprobante", string(req.EstadoComprobante))
		setOptionalAttr(solicitud, "RfcACuentaTerceros", req.RFCACuentaTerceros)
		setOptionalAttr(solicitud, "Complemento", req.Complemento)
		setOptionalAttr(solicitud, "UUID", req.UUID)

		if req.TipoDescarga == TipoDescargaRecibidos {
			soap.SetAttr(solicitud, "RfcReceptor", req.RFCSolicitante)
			if len(req.RFCContrapartes) == 1 {
				soap.SetAttr(solicitud, "RfcEmisor", req.RFCContrapartes[0])
			}
			return nil
		}

		soap.SetAttr(solicitud, "RfcEmisor", req.RFCSolicitante)
		rfcReceptores := soap.FindElement(solicitud, "des:RfcReceptores")
		if rfcReceptores == nil {
			if len(req.RFCContrapartes) == 0 {
				return nil
			}
			return fmt.Errorf("sat: emitidos template missing RfcReceptores node")
		}

		if len(req.RFCContrapartes) == 0 {
			solicitud.RemoveChild(rfcReceptores)
			return nil
		}

		rfcReceptores.Child = nil
		for _, contraparte := range req.RFCContrapartes {
			child := etree.NewElement("RfcReceptor")
			child.Space = "des"
			child.SetText(contraparte)
			rfcReceptores.AddChild(child)
		}
		return nil
	}

	return spec
}
