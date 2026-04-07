package sat

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/lafriks/pkcs8"
)

// Fiel contiene en memoria un certificado SAT y su llave privada RSA
// correspondiente.
type Fiel struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	cerDER      []byte
}

// NewFiel carga un certificado SAT y una llave privada RSA, cifrada o no, a
// partir de bytes DER.
func NewFiel(cerDER, keyDER, password []byte) (*Fiel, error) {
	cert, err := x509.ParseCertificate(cerDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	key, err := parseRSAPrivateKey(keyDER, password)
	if err != nil {
		return nil, err
	}

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: el certificado no es RSA", ErrInvalidCertificate)
	}
	if pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		return nil, fmt.Errorf("%w: el certificado y la llave privada no coinciden", ErrInvalidPrivateKey)
	}

	return &Fiel{
		certificate: cert,
		privateKey:  key,
		cerDER:      append([]byte(nil), cerDER...),
	}, nil
}

func parseRSAPrivateKey(keyDER, password []byte) (*rsa.PrivateKey, error) {
	if parsed, err := x509.ParsePKCS8PrivateKey(keyDER); err == nil {
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: tipo de llave privada PKCS#8 no soportado %T", ErrInvalidPrivateKey, parsed)
		}
		return key, nil
	}

	if parsed, err := pkcs8.ParsePKCS8PrivateKey(keyDER, password); err == nil {
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: tipo de llave privada cifrada no soportado %T", ErrInvalidPrivateKey, parsed)
		}
		return key, nil
	} else if errors.Is(err, x509.IncorrectPasswordError) {
		return nil, ErrIncorrectPassword
	}

	if parsed, err := x509.ParsePKCS1PrivateKey(keyDER); err == nil {
		return parsed, nil
	}

	return nil, fmt.Errorf("%w: llave privada RSA no soportada o ilegible", ErrInvalidPrivateKey)
}

// CertificateBase64 devuelve el DER crudo del certificado codificado en base64.
func (f *Fiel) CertificateBase64() string {
	return base64.StdEncoding.EncodeToString(f.cerDER)
}

// IssuerName devuelve el emisor del certificado en el formato esperado por las
// firmas XML del SAT.
func (f *Fiel) IssuerName() string {
	return issuerString(f.certificate)
}

// SerialNumber devuelve el número de serie del certificado como cadena
// decimal.
func (f *Fiel) SerialNumber() string {
	return f.certificate.SerialNumber.String()
}

// SignSHA1 firma los bytes proporcionados usando RSA PKCS#1 v1.5 con SHA-1 y
// devuelve la salida en base64.
func (f *Fiel) SignSHA1(data []byte) (string, error) {
	sum := sha1.Sum(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.privateKey, crypto.SHA1, sum[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func issuerString(cert *x509.Certificate) string {
	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawIssuer, &seq); err != nil {
		return cert.Issuer.String()
	}

	parts := make([]string, 0, len(seq))
	for _, set := range seq {
		for _, attr := range set {
			parts = append(parts, fmt.Sprintf("%s=%s", oidLabel(attr.Type), attributeValue(attr.Value)))
		}
	}

	return strings.Join(parts, ",")
}

func oidLabel(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal([]int{2, 5, 4, 6}):
		return "C"
	case oid.Equal([]int{2, 5, 4, 8}):
		return "ST"
	case oid.Equal([]int{2, 5, 4, 7}):
		return "L"
	case oid.Equal([]int{2, 5, 4, 10}):
		return "O"
	case oid.Equal([]int{2, 5, 4, 11}):
		return "OU"
	case oid.Equal([]int{2, 5, 4, 3}):
		return "CN"
	case oid.Equal([]int{2, 5, 4, 5}):
		return "SERIALNUMBER"
	default:
		return oid.String()
	}
}

func attributeValue(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case []byte:
		return string(bytes.TrimSpace(value))
	default:
		return fmt.Sprint(value)
	}
}
