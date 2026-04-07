package sat

import (
	"fmt"
	"strings"

	"github.com/beevik/etree"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
)

func requireFiel(fiel *Fiel) error {
	if fiel == nil {
		return ErrNilFiel
	}
	return nil
}

func requireSOAPRoot(resp *soap.Response) (*etree.Element, error) {
	if resp.FaultString != "" {
		return nil, &SOAPFaultError{
			StatusCode:  resp.StatusCode,
			FaultString: resp.FaultString,
			Body:        string(resp.Raw),
		}
	}
	if resp.StatusCode != 200 {
		return nil, &SOAPFaultError{
			StatusCode:  resp.StatusCode,
			FaultString: resp.FaultString,
			Body:        string(resp.Raw),
		}
	}
	if resp.Document == nil || resp.Document.Root() == nil {
		return nil, &SOAPFaultError{
			StatusCode: resp.StatusCode,
			Body:       string(resp.Raw),
		}
	}
	return resp.Document.Root(), nil
}

func satBusinessError(code, message string) error {
	if code == "" || code == "5000" {
		return nil
	}
	return &SATBusinessError{Code: code, Message: message}
}

func setOptionalAttr(el *etree.Element, name, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	soap.SetAttr(el, name, value)
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

type requiredField struct {
	name  string
	value string
}

func requireFields(fields ...requiredField) error {
	for _, field := range fields {
		name := field.name
		value := field.value
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s es requerido", ErrInvalidRequest, name)
		}
	}
	return nil
}
