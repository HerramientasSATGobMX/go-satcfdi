package sat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// ErrInvalidRequest indica que la entrada podría rechazarse localmente antes
	// de emitir una solicitud SOAP a SAT.
	ErrInvalidRequest = errors.New("sat: solicitud inválida")
	// ErrNilFiel indica que una Fiel requerida era nil.
	ErrNilFiel = errors.New("sat: fiel nula")
	// ErrSOAPFault indica que SAT devolvió un fault a nivel HTTP o SOAP.
	ErrSOAPFault = errors.New("sat: error soap")
	// ErrSATBusiness indica que SAT devolvió un código de error de negocio.
	ErrSATBusiness = errors.New("sat: error de negocio sat")
	// ErrInvalidCertificate indica que el DER del certificado no pudo
	// interpretarse.
	ErrInvalidCertificate = errors.New("sat: certificado inválido")
	// ErrInvalidPrivateKey indica que la llave privada no pudo interpretarse o
	// no coincidió.
	ErrInvalidPrivateKey = errors.New("sat: llave privada inválida")
	// ErrIncorrectPassword indica que la contraseña de la llave privada cifrada
	// era incorrecta.
	ErrIncorrectPassword = errors.New("sat: contraseña incorrecta")
)

// SOAPFaultError contiene los detalles HTTP/SOAP devueltos por SAT.
type SOAPFaultError struct {
	StatusCode  int
	FaultString string
	Body        string
}

func (e *SOAPFaultError) Error() string {
	if e.FaultString != "" {
		return fmt.Sprintf("sat soap fault (%d): %s", e.StatusCode, e.FaultString)
	}
	return fmt.Sprintf("sat soap fault (%d)", e.StatusCode)
}

func (e *SOAPFaultError) Unwrap() error {
	return ErrSOAPFault
}

// SATBusinessError representa una respuesta SAT con un código de negocio no
// exitoso.
type SATBusinessError struct {
	Code    string
	Message string
}

func (e *SATBusinessError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("sat business error: %s", e.Message)
	}
	return fmt.Sprintf("sat business error (%s): %s", e.Code, e.Message)
}

func (e *SATBusinessError) Unwrap() error {
	return ErrSATBusiness
}

// IsRetryableError indica si un error parece transitorio y vale la pena
// reintentarlo, incluyendo problemas de red y SOAP faults reintentables.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	var soapErr *SOAPFaultError
	if errors.As(err, &soapErr) {
		return soapErr.StatusCode == 429 || soapErr.StatusCode >= 500
	}

	return false
}

// IsAuthenticationError indica si un error corresponde a un token SAT inválido
// o expirado.
func IsAuthenticationError(err error) bool {
	if err == nil {
		return false
	}

	var soapErr *SOAPFaultError
	if errors.As(err, &soapErr) {
		if soapErr.StatusCode == 401 || soapErr.StatusCode == 403 {
			return true
		}
		return tokenHint(soapErr.FaultString)
	}

	var satErr *SATBusinessError
	if errors.As(err, &satErr) {
		return tokenHint(satErr.Code + " " + satErr.Message)
	}

	return false
}

func tokenHint(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	if strings.Contains(value, "access_token") {
		return true
	}
	if !strings.Contains(value, "token") {
		return false
	}
	return strings.Contains(value, "invalid") ||
		strings.Contains(value, "expire") ||
		strings.Contains(value, "expir") ||
		strings.Contains(value, "venc")
}
