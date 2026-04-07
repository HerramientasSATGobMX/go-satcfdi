package sat

import (
	"context"
	"fmt"

	"github.com/beevik/etree"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/xmlsig"
)

// Consultar crea una solicitud SAT para consultar paquetes de CFDI o metadatos
// emitidos o recibidos.
func (c *Client) Consultar(ctx context.Context, fiel *Fiel, req ConsultaRequest) (*ConsultaResponse, error) {
	req = normalizeConsulta(req)

	if err := requireFiel(fiel); err != nil {
		return nil, err
	}
	if err := validateConsulta(req, c.clock()); err != nil {
		return nil, err
	}

	spec := translateConsulta(req)
	root, err := c.executeTemplate(ctx, templateRequest{
		templateName: spec.templateName,
		url:          c.endpoints.SolicitaURL,
		action:       spec.action,
		token:        req.Token,
		populate:     spec.populate,
		sign: func(doc *etree.Document) error {
			return xmlsig.SignRequest(doc, spec.bodyPath, fiel)
		},
	})
	if err != nil {
		return nil, err
	}

	result := soap.FindElement(root, spec.responsePath...)
	if result == nil {
		return nil, fmt.Errorf("sat: consulta response missing result")
	}

	out := &ConsultaResponse{
		CodEstatus:  result.SelectAttrValue("CodEstatus", ""),
		Mensaje:     result.SelectAttrValue("Mensaje", ""),
		IDSolicitud: result.SelectAttrValue("IdSolicitud", ""),
	}
	if err := satBusinessError(out.CodEstatus, out.Mensaje); err != nil {
		return out, err
	}
	return out, nil
}
