package soap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/beevik/etree"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/templates"
)

type Operation struct {
	URL    string
	Action string
	Token  string
	Body   []byte
}

type Response struct {
	StatusCode  int
	Raw         []byte
	Document    *etree.Document
	FaultString string
}

func Headers(action, token string) http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", `text/xml;charset="utf-8"`)
	headers.Set("Accept", "text/xml")
	headers.Set("Cache-Control", "no-cache")
	headers.Set("SOAPAction", action)
	if token != "" {
		headers.Set("Authorization", fmt.Sprintf(`WRAP access_token="%s"`, token))
	}
	return headers
}

func Do(ctx context.Context, client *http.Client, op Operation) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, op.URL, bytes.NewReader(op.Body))
	if err != nil {
		return nil, err
	}
	req.Header = Headers(op.Action, op.Token)

	httpResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	raw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	resp := &Response{
		StatusCode: httpResp.StatusCode,
		Raw:        raw,
	}

	doc, err := ParseDocument(raw)
	if err == nil {
		resp.Document = doc
		if root := doc.Root(); root != nil {
			if fault := FindElement(root, "Body", "Fault", "faultstring"); fault != nil {
				resp.FaultString = strings.TrimSpace(fault.Text())
			}
		}
	}

	return resp, nil
}

func ParseDocument(raw []byte) (*etree.Document, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, err
	}
	return doc, nil
}

func NewTemplateDocument(name string) (*etree.Document, error) {
	raw, err := templates.Read(name)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, err
	}
	return doc, nil
}

func FindElement(root *etree.Element, path ...string) *etree.Element {
	current := root
	for _, part := range path {
		if current == nil {
			return nil
		}
		current = findChild(current, part)
	}
	return current
}

func findChild(root *etree.Element, name string) *etree.Element {
	space, tag := splitQName(name)
	for _, child := range root.ChildElements() {
		if child.Tag != tag {
			continue
		}
		if space == "" || child.Space == space {
			return child
		}
	}
	return nil
}

func SetText(el *etree.Element, value string) {
	el.SetText(value)
}

func SetCData(el *etree.Element, value string) {
	el.SetCData(value)
}

func SetAttr(el *etree.Element, name, value string) {
	space, key := splitQName(name)
	for i := range el.Attr {
		attr := &el.Attr[i]
		if attr.Key == key && attr.Space == space {
			attr.Value = value
			return
		}
	}
	el.Attr = append(el.Attr, etree.Attr{
		Space: space,
		Key:   key,
		Value: value,
	})
}

func splitQName(name string) (string, string) {
	parts := strings.SplitN(name, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", name
}
