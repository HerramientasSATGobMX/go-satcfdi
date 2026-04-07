package satservice

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	satcfdiv1 "github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1"
	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

var errInvalidPackagePayload = errors.New("satservice: contenido de paquete inválido")
var errPackageTooLarge = errors.New("satservice: el paquete excede el límite unary")

type packageTooLargeError struct {
	Actual int
	Limit  int
}

func (e *packageTooLargeError) Error() string {
	return fmt.Sprintf(
		"satservice: el paquete decodificado mide %d y excede el límite unary %d; usa StreamDownloadPackage",
		e.Actual,
		e.Limit,
	)
}

func (e *packageTooLargeError) Unwrap() error {
	return errPackageTooLarge
}

type errorContext struct {
	Operation         string
	RequestID         string
	PackageID         string
	SatStatusCode     string
	RequestStatusCode string
	SatMessage        string
}

type contextualError struct {
	err error
	ctx errorContext
}

func (e *contextualError) Error() string {
	return e.err.Error()
}

func (e *contextualError) Unwrap() error {
	return e.err
}

func withErrorContext(err error, ctx errorContext) error {
	if err == nil {
		return nil
	}

	var existing *contextualError
	if errors.As(err, &existing) {
		existing.ctx = mergeErrorContext(existing.ctx, ctx)
		return err
	}

	return &contextualError{err: err, ctx: ctx}
}

func mapError(err error) error {
	if err == nil {
		return nil
	}

	detailContext := extractErrorContext(err)
	detail := &satcfdiv1.ServiceErrorDetail{
		Category:          satcfdiv1.ErrorCategory_ERROR_CATEGORY_INTERNAL,
		Operation:         detailContext.Operation,
		RequestId:         detailContext.RequestID,
		PackageId:         detailContext.PackageID,
		SatStatusCode:     detailContext.SatStatusCode,
		RequestStatusCode: detailContext.RequestStatusCode,
		SatMessage:        detailContext.SatMessage,
	}

	switch {
	case errors.Is(err, context.Canceled):
		connectErr := connect.NewError(connect.CodeCanceled, err)
		addDetail(connectErr, detail)
		return connectErr
	case errors.Is(err, context.DeadlineExceeded):
		detail.Category = satcfdiv1.ErrorCategory_ERROR_CATEGORY_TIMEOUT
		detail.Retryable = true
		connectErr := connect.NewError(connect.CodeDeadlineExceeded, err)
		addDetail(connectErr, detail)
		return connectErr
	}

	code := connect.CodeInternal

	switch {
	case errors.Is(err, satflow.ErrPollExceeded):
		code = connect.CodeDeadlineExceeded
		detail.Category = satcfdiv1.ErrorCategory_ERROR_CATEGORY_TIMEOUT
		detail.Retryable = true
	case errors.Is(err, errInvalidPackagePayload),
		errors.Is(err, satflow.ErrInvalidPackagePayload):
		code = connect.CodeDataLoss
	case errors.Is(err, errPackageTooLarge):
		code = connect.CodeFailedPrecondition
		detail.Category = satcfdiv1.ErrorCategory_ERROR_CATEGORY_VALIDATION
	case errors.Is(err, sat.ErrInvalidRequest):
		code = connect.CodeInvalidArgument
		detail.Category = satcfdiv1.ErrorCategory_ERROR_CATEGORY_VALIDATION
	case errors.Is(err, errInvalidCredentialReference),
		errors.Is(err, errCredentialResolution),
		errors.Is(err, sat.ErrNilFiel),
		errors.Is(err, sat.ErrInvalidCertificate),
		errors.Is(err, sat.ErrInvalidPrivateKey),
		errors.Is(err, sat.ErrIncorrectPassword):
		code = connect.CodeInvalidArgument
		detail.Category = satcfdiv1.ErrorCategory_ERROR_CATEGORY_CREDENTIALS
	case sat.IsAuthenticationError(err):
		code = connect.CodeUnauthenticated
		detail.Category = satcfdiv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION
	case errors.Is(err, satflow.ErrTerminalStatus),
		errors.Is(err, sat.ErrSATBusiness):
		code = connect.CodeFailedPrecondition
		detail.Category = satcfdiv1.ErrorCategory_ERROR_CATEGORY_BUSINESS
	case errors.Is(err, sat.ErrSOAPFault):
		detail.Category = satcfdiv1.ErrorCategory_ERROR_CATEGORY_SOAP
		detail.Retryable = sat.IsRetryableError(err)
		if detail.Retryable {
			code = connect.CodeUnavailable
		}
	case sat.IsRetryableError(err):
		code = connect.CodeUnavailable
		detail.Category = satcfdiv1.ErrorCategory_ERROR_CATEGORY_TRANSPORT
		detail.Retryable = true
	}

	var satBusiness *sat.SATBusinessError
	if errors.As(err, &satBusiness) {
		detail.SatCode = satBusiness.Code
		if detail.SatMessage == "" {
			detail.SatMessage = satBusiness.Message
		}
	}

	var soapErr *sat.SOAPFaultError
	if errors.As(err, &soapErr) {
		detail.SoapHttpStatus = int32(soapErr.StatusCode)
		detail.SoapFaultString = soapErr.FaultString
	}

	connectErr := connect.NewError(code, err)
	addDetail(connectErr, detail)
	return connectErr
}

func addDetail(connectErr *connect.Error, detail *satcfdiv1.ServiceErrorDetail) {
	errorDetail, err := connect.NewErrorDetail(detail)
	if err == nil {
		connectErr.AddDetail(errorDetail)
	}
}

func extractErrorContext(err error) errorContext {
	var out errorContext

	var contextual *contextualError
	if errors.As(err, &contextual) {
		out = mergeErrorContext(out, contextual.ctx)
	}

	var pollExceeded *satflow.PollExceededError
	if errors.As(err, &pollExceeded) {
		out = mergeErrorContext(out, errorContext{
			RequestID: pollExceeded.RequestID,
			SatStatusCode: responseValue(pollExceeded.Last, func(resp *sat.VerificaSolicitudResponse) string {
				return resp.CodEstatus
			}),
			RequestStatusCode: responseValue(pollExceeded.Last, func(resp *sat.VerificaSolicitudResponse) string {
				return resp.CodigoEstadoSolicitud
			}),
			SatMessage: responseValue(pollExceeded.Last, func(resp *sat.VerificaSolicitudResponse) string {
				return resp.Mensaje
			}),
		})
	}

	var terminal *satflow.TerminalStatusError
	if errors.As(err, &terminal) {
		out = mergeErrorContext(out, errorContext{
			RequestID: terminal.RequestID,
			SatStatusCode: responseValue(terminal.Response, func(resp *sat.VerificaSolicitudResponse) string {
				return resp.CodEstatus
			}),
			RequestStatusCode: responseValue(terminal.Response, func(resp *sat.VerificaSolicitudResponse) string {
				return resp.CodigoEstadoSolicitud
			}),
			SatMessage: responseValue(terminal.Response, func(resp *sat.VerificaSolicitudResponse) string {
				return resp.Mensaje
			}),
		})
	}

	var invalidPayload *satflow.InvalidPackagePayloadError
	if errors.As(err, &invalidPayload) {
		out.PackageID = firstNonEmpty(out.PackageID, invalidPayload.PackageID)
	}

	return out
}

func mergeErrorContext(base, extra errorContext) errorContext {
	base.Operation = firstNonEmpty(base.Operation, extra.Operation)
	base.RequestID = firstNonEmpty(base.RequestID, extra.RequestID)
	base.PackageID = firstNonEmpty(base.PackageID, extra.PackageID)
	base.SatStatusCode = firstNonEmpty(base.SatStatusCode, extra.SatStatusCode)
	base.RequestStatusCode = firstNonEmpty(base.RequestStatusCode, extra.RequestStatusCode)
	base.SatMessage = firstNonEmpty(base.SatMessage, extra.SatMessage)
	return base
}

func firstNonEmpty(base, extra string) string {
	if base != "" {
		return base
	}
	return extra
}
