package sat

import (
	"context"

	"github.com/beevik/etree"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
)

type templateRequest struct {
	templateName string
	url          string
	action       string
	token        string
	populate     func(*etree.Element) error
	sign         func(*etree.Document) error
}

func (c *Client) executeTemplate(ctx context.Context, req templateRequest) (*etree.Element, error) {
	doc, err := soap.NewTemplateDocument(req.templateName)
	if err != nil {
		return nil, err
	}

	root := doc.Root()
	if req.populate != nil {
		if err := req.populate(root); err != nil {
			return nil, err
		}
	}
	if req.sign != nil {
		if err := req.sign(doc); err != nil {
			return nil, err
		}
	}

	raw, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	resp, err := soap.Do(ctx, c.httpClient, soap.Operation{
		URL:    req.url,
		Action: req.action,
		Token:  req.token,
		Body:   raw,
	})
	if err != nil {
		return nil, err
	}

	return requireSOAPRoot(resp)
}
