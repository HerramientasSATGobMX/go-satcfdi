package sat

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/xmlsig"
)

const authTokenTTL = 5 * time.Minute

// ObtenerToken autentica contra SAT usando la Fiel proporcionada y devuelve un
// token de acceso.
func (c *Client) ObtenerToken(ctx context.Context, fiel *Fiel) (string, error) {
	if err := requireFiel(fiel); err != nil {
		return "", err
	}

	root, err := c.executeTemplate(ctx, templateRequest{
		templateName: "auth.xml",
		url:          c.endpoints.AuthURL,
		action:       authSOAPAction,
		sign: func(doc *etree.Document) error {
			return xmlsig.SignAuthentication(doc, c.clock(), authTokenTTL, fiel)
		},
	})
	if err != nil {
		return "", err
	}

	tokenEl := soap.FindElement(root, "Body", "AutenticaResponse", "AutenticaResult")
	if tokenEl == nil {
		return "", fmt.Errorf("sat: auth response missing token")
	}
	return strings.TrimSpace(tokenEl.Text()), nil
}
