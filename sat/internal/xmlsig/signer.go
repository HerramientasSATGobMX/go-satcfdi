package xmlsig

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/ucarion/c14n"

	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
)

type Credentials interface {
	CertificateBase64() string
	IssuerName() string
	SerialNumber() string
	SignSHA1([]byte) (string, error)
}

const authTimeFormat = "2006-01-02T15:04:05.000000Z"

func SignAuthentication(doc *etree.Document, now time.Time, ttl time.Duration, cred Credentials) error {
	root := doc.Root()
	if root == nil {
		return fmt.Errorf("xmlsig: missing auth root")
	}

	timestamp := soap.FindElement(root, "s:Header", "o:Security", "u:Timestamp")
	created := soap.FindElement(timestamp, "u:Created")
	expires := soap.FindElement(timestamp, "u:Expires")
	token := soap.FindElement(root, "s:Header", "o:Security", "o:BinarySecurityToken")
	digest := soap.FindElement(root, "s:Header", "o:Security", "Signature", "SignedInfo", "Reference", "DigestValue")
	signedInfo := soap.FindElement(root, "s:Header", "o:Security", "Signature", "SignedInfo")
	signatureValue := soap.FindElement(root, "s:Header", "o:Security", "Signature", "SignatureValue")

	if created == nil || expires == nil || token == nil || digest == nil || signedInfo == nil || signatureValue == nil {
		return fmt.Errorf("xmlsig: auth template is incomplete")
	}

	soap.SetText(created, now.UTC().Format(authTimeFormat))
	soap.SetText(expires, now.UTC().Add(ttl).Format(authTimeFormat))
	soap.SetText(token, cred.CertificateBase64())

	digestBytes, err := Canonicalize(timestamp)
	if err != nil {
		return err
	}
	soap.SetText(digest, sha1DigestBase64(digestBytes))

	signedInfoBytes, err := Canonicalize(signedInfo)
	if err != nil {
		return err
	}

	sig, err := cred.SignSHA1(signedInfoBytes)
	if err != nil {
		return err
	}
	soap.SetText(signatureValue, sig)
	return nil
}

func SignRequest(doc *etree.Document, appendPath []string, cred Credentials) error {
	root := doc.Root()
	if root == nil {
		return fmt.Errorf("xmlsig: missing request root")
	}

	appendTarget := soap.FindElement(root, appendPath...)
	if appendTarget == nil {
		return fmt.Errorf("xmlsig: append target not found")
	}

	parent := appendTarget.Parent()
	if parent == nil {
		return fmt.Errorf("xmlsig: append target has no parent element")
	}

	digestBytes, err := Canonicalize(parent)
	if err != nil {
		return err
	}

	sigDoc, err := soap.NewTemplateDocument("signer.xml")
	if err != nil {
		return err
	}

	sigRoot := sigDoc.Root()
	if sigRoot == nil {
		return fmt.Errorf("xmlsig: signer template missing root")
	}

	digest := soap.FindElement(sigRoot, "SignedInfo", "Reference", "DigestValue")
	signedInfo := soap.FindElement(sigRoot, "SignedInfo")
	signatureValue := soap.FindElement(sigRoot, "SignatureValue")
	cert := soap.FindElement(sigRoot, "KeyInfo", "X509Data", "X509Certificate")
	issuer := soap.FindElement(sigRoot, "KeyInfo", "X509Data", "X509IssuerSerial", "X509IssuerName")
	serial := soap.FindElement(sigRoot, "KeyInfo", "X509Data", "X509IssuerSerial", "X509SerialNumber")
	if digest == nil || signedInfo == nil || signatureValue == nil || cert == nil || issuer == nil || serial == nil {
		return fmt.Errorf("xmlsig: signer template is incomplete")
	}

	soap.SetText(digest, sha1DigestBase64(digestBytes))
	soap.SetText(cert, cred.CertificateBase64())
	soap.SetText(issuer, cred.IssuerName())
	soap.SetText(serial, cred.SerialNumber())

	signedInfoBytes, err := Canonicalize(signedInfo)
	if err != nil {
		return err
	}

	sig, err := cred.SignSHA1(signedInfoBytes)
	if err != nil {
		return err
	}
	soap.SetText(signatureValue, sig)

	appendTarget.AddChild(sigRoot)
	return nil
}

func Canonicalize(element *etree.Element) ([]byte, error) {
	clone := element.Copy()
	ensureVisibleNamespaces(clone, collectNamespaces(element))

	doc := etree.NewDocument()
	doc.SetRoot(clone)
	raw, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	decoder := xml.NewDecoder(bytes.NewReader(raw))
	return c14n.Canonicalize(decoder)
}

func sha1DigestBase64(data []byte) string {
	sum := sha1.Sum(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func collectNamespaces(element *etree.Element) map[string]string {
	namespaces := map[string]string{}
	for current := element; current != nil; current = parentElement(current) {
		for _, attr := range current.Attr {
			switch {
			case attr.Space == "xmlns":
				if _, exists := namespaces[attr.Key]; !exists {
					namespaces[attr.Key] = attr.Value
				}
			case attr.Space == "" && attr.Key == "xmlns":
				if _, exists := namespaces[""]; !exists {
					namespaces[""] = attr.Value
				}
			}
		}
	}
	return namespaces
}

func ensureVisibleNamespaces(root *etree.Element, namespaces map[string]string) {
	for prefix, uri := range namespaces {
		if hasNamespace(root, prefix) {
			continue
		}
		if prefix == "" {
			root.Attr = append(root.Attr, etree.Attr{Key: "xmlns", Value: uri})
			continue
		}
		root.Attr = append(root.Attr, etree.Attr{Space: "xmlns", Key: prefix, Value: uri})
	}
}

func hasNamespace(root *etree.Element, prefix string) bool {
	for _, attr := range root.Attr {
		if prefix == "" && attr.Space == "" && attr.Key == "xmlns" {
			return true
		}
		if prefix != "" && attr.Space == "xmlns" && attr.Key == prefix {
			return true
		}
	}
	return false
}

func parentElement(element *etree.Element) *etree.Element {
	return element.Parent()
}
