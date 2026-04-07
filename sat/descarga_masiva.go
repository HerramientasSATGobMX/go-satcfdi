package sat

import (
	"context"
	"fmt"
	"strings"

	"github.com/beevik/etree"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/xmlsig"
)

// DescargarPaquete descarga un paquete SAT y devuelve su contenido en base64.
func (c *Client) DescargarPaquete(ctx context.Context, fiel *Fiel, req DescargaPaqueteRequest) (*DescargaPaqueteResponse, error) {
	if err := requireFiel(fiel); err != nil {
		return nil, err
	}
	if err := requireFields(
		requiredField{name: "Token", value: req.Token},
		requiredField{name: "RFCSolicitante", value: req.RFCSolicitante},
		requiredField{name: "IDPaquete", value: req.IDPaquete},
	); err != nil {
		return nil, err
	}

	path := []string{"s:Body", "des:PeticionDescargaMasivaTercerosEntrada", "des:peticionDescarga"}
	root, err := c.executeTemplate(ctx, templateRequest{
		templateName: "descarga.xml",
		url:          c.endpoints.DescargaURL,
		action:       descargaSOAPAction,
		token:        req.Token,
		populate: func(root *etree.Element) error {
			solicitud := soap.FindElement(root, path...)
			if solicitud == nil {
				return fmt.Errorf("sat: descarga node not found")
			}
			soap.SetAttr(solicitud, "RfcSolicitante", strings.ToUpper(req.RFCSolicitante))
			soap.SetAttr(solicitud, "IdPaquete", req.IDPaquete)
			return nil
		},
		sign: func(doc *etree.Document) error {
			return xmlsig.SignRequest(doc, path, fiel)
		},
	})
	if err != nil {
		return nil, err
	}

	paquete := soap.FindElement(root, "Body", "RespuestaDescargaMasivaTercerosSalida", "Paquete")
	headerRespuesta := soap.FindElement(root, "Header", "respuesta")
	if paquete == nil {
		return nil, fmt.Errorf("sat: descarga response missing package")
	}

	out := &DescargaPaqueteResponse{
		PaqueteB64: strings.TrimSpace(paquete.Text()),
	}
	if headerRespuesta != nil {
		out.CodEstatus = headerRespuesta.SelectAttrValue("CodEstatus", "")
		out.Mensaje = headerRespuesta.SelectAttrValue("Mensaje", "")
	}

	if err := satBusinessError(out.CodEstatus, out.Mensaje); err != nil {
		return out, err
	}
	return out, nil
}
