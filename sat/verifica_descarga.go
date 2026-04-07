package sat

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/beevik/etree"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/xmlsig"
)

// VerificarDescarga consulta el estado actual de una solicitud de descarga SAT
// existente.
func (c *Client) VerificarDescarga(ctx context.Context, fiel *Fiel, req VerificaSolicitudRequest) (*VerificaSolicitudResponse, error) {
	if err := requireFiel(fiel); err != nil {
		return nil, err
	}
	if err := requireFields(
		requiredField{name: "Token", value: req.Token},
		requiredField{name: "RFCSolicitante", value: req.RFCSolicitante},
		requiredField{name: "IDSolicitud", value: req.IDSolicitud},
	); err != nil {
		return nil, err
	}

	path := []string{"s:Body", "des:VerificaSolicitudDescarga", "des:solicitud"}
	root, err := c.executeTemplate(ctx, templateRequest{
		templateName: "verifica.xml",
		url:          c.endpoints.VerificaURL,
		action:       verificaSOAPAction,
		token:        req.Token,
		populate: func(root *etree.Element) error {
			solicitud := soap.FindElement(root, path...)
			if solicitud == nil {
				return fmt.Errorf("sat: verifica solicitud node not found")
			}
			soap.SetAttr(solicitud, "RfcSolicitante", strings.ToUpper(req.RFCSolicitante))
			soap.SetAttr(solicitud, "IdSolicitud", req.IDSolicitud)
			return nil
		},
		sign: func(doc *etree.Document) error {
			return xmlsig.SignRequest(doc, path, fiel)
		},
	})
	if err != nil {
		return nil, err
	}

	result := soap.FindElement(root, "Body", "VerificaSolicitudDescargaResponse", "VerificaSolicitudDescargaResult")
	if result == nil {
		return nil, fmt.Errorf("sat: verificar response missing result")
	}

	out := &VerificaSolicitudResponse{
		CodEstatus:            result.SelectAttrValue("CodEstatus", ""),
		CodigoEstadoSolicitud: result.SelectAttrValue("CodigoEstadoSolicitud", ""),
		Mensaje:               result.SelectAttrValue("Mensaje", ""),
		Paquetes:              []string{},
	}

	if estado, err := strconv.Atoi(result.SelectAttrValue("EstadoSolicitud", "0")); err == nil {
		out.EstadoSolicitud = estado
	}
	if numero, err := strconv.Atoi(result.SelectAttrValue("NumeroCFDIs", "0")); err == nil {
		out.NumeroCFDIs = numero
	}

	for _, child := range result.ChildElements() {
		if child.Tag == "IdsPaquetes" {
			out.Paquetes = append(out.Paquetes, strings.TrimSpace(child.Text()))
		}
	}

	if err := satBusinessError(out.CodEstatus, out.Mensaje); err != nil {
		return out, err
	}
	return out, nil
}
