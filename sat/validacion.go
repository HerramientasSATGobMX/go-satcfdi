package sat

import (
	"context"
	"fmt"

	"github.com/beevik/etree"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
)

// ObtenerEstadoCFDI valida un CFDI contra el servicio de validación del SAT.
func (c *Client) ObtenerEstadoCFDI(ctx context.Context, req ValidacionRequest) (*ValidacionResponse, error) {
	if err := requireFields(
		requiredField{name: "RFCEmisor", value: req.RFCEmisor},
		requiredField{name: "RFCReceptor", value: req.RFCReceptor},
		requiredField{name: "Total", value: req.Total},
		requiredField{name: "UUID", value: req.UUID},
	); err != nil {
		return nil, err
	}

	root, err := c.executeTemplate(ctx, templateRequest{
		templateName: "validacion.xml",
		url:          c.endpoints.ValidacionURL,
		action:       validacionSOAPAction,
		populate: func(root *etree.Element) error {
			expresion := soap.FindElement(root, "soapenv:Body", "tem:Consulta", "tem:expresionImpresa")
			if expresion == nil {
				return fmt.Errorf("sat: validacion template missing expresionImpresa")
			}
			soap.SetCData(expresion, fmt.Sprintf("?re=%s&rr=%s&tt=%s&id=%s", req.RFCEmisor, req.RFCReceptor, req.Total, req.UUID))
			return nil
		},
	})
	if err != nil {
		return nil, err
	}

	result := soap.FindElement(root, "Body", "ConsultaResponse", "ConsultaResult")
	if result == nil {
		return nil, fmt.Errorf("sat: validacion response missing result")
	}

	out := &ValidacionResponse{}
	if code := soap.FindElement(result, "CodigoEstatus"); code != nil {
		out.CodigoEstatus = code.Text()
	}
	if cancelable := soap.FindElement(result, "EsCancelable"); cancelable != nil {
		out.EsCancelable = cancelable.Text()
	}
	if estado := soap.FindElement(result, "Estado"); estado != nil {
		out.Estado = estado.Text()
	}

	return out, nil
}
