package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	case "shell", "interactive", "wizard":
		return runShell(args[1:], stdin, stdout, stderr)
	case "auth":
		return runAuth(args[1:], stdout, stderr)
	case "solicitar":
		return runSolicitar(args[1:], stdout, stderr)
	case "verificar":
		return runVerificar(args[1:], stdout, stderr)
	case "descargar":
		return runDescargar(args[1:], stdout, stderr)
	case "validar":
		return runValidar(args[1:], stdout, stderr)
	case "flujo":
		return runFlujo(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "comando desconocido: %s\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runAuth(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := bindCommonFlags(fs)
	credentials := bindCredentialFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Uso: satcfdi auth -cert cert.der -key key.der [-password secreto]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	fiel, err := loadFiel(credentials)
	if err != nil {
		return fail(stderr, err)
	}

	flow, err := newFlowClient(common, fiel, "CLI_AUTH")
	if err != nil {
		return fail(stderr, err)
	}

	token, err := flow.Authenticate(context.Background())
	if err != nil {
		return fail(stderr, err)
	}

	return writeJSON(stdout, map[string]string{"token": token.Value}, stderr)
}

func runSolicitar(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("solicitar", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := bindCommonFlags(fs)
	credentials := bindCredentialFlags(fs)

	var counterparts stringList
	var (
		token              = fs.String("token", os.Getenv("SAT_TOKEN"), "token SAT")
		rfcSolicitante     = fs.String("rfc-solicitante", os.Getenv("SAT_RFC"), "RFC solicitante")
		fechaInicial       = fs.String("fecha-inicial", currentMonthStart().Format("2006-01-02"), "fecha inicial (YYYY-MM-DD, RFC3339 o 2006-01-02T15:04:05)")
		fechaFinal         = fs.String("fecha-final", cliNow().Format("2006-01-02"), "fecha final (YYYY-MM-DD, RFC3339 o 2006-01-02T15:04:05)")
		tipoDescarga       = fs.String("tipo-descarga", string(sat.TipoDescargaRecibidos), "tipo de descarga (recibidos o emitidos)")
		tipoSolicitud      = fs.String("tipo-solicitud", string(sat.TipoSolicitudCFDI), "tipo de solicitud (CFDI o Metadata)")
		tipoComprobante    = fs.String("tipo-comprobante", "", "tipo de comprobante")
		estadoComprobante  = fs.String("estado-comprobante", "", "estado del comprobante (Vigente, Cancelado o vacío)")
		rfcACuentaTerceros = fs.String("rfc-a-cuenta-terceros", "", "RFC a cuenta de terceros")
		complemento        = fs.String("complemento", "", "complemento")
		uuid               = fs.String("uuid", "", "UUID")
	)
	fs.Var(&counterparts, "rfc-contraparte", "RFC contraparte; puede repetirse o usar comas")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Uso: satcfdi solicitar -cert cert.der -key key.der -token TOKEN -rfc-solicitante RFC -fecha-inicial 2025-01-01 -fecha-final 2025-01-31")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	fiel, err := loadFiel(credentials)
	if err != nil {
		return fail(stderr, err)
	}

	req, err := buildConsultaRequest(
		*token,
		*rfcSolicitante,
		*fechaInicial,
		*fechaFinal,
		*tipoDescarga,
		*tipoSolicitud,
		counterparts,
		*tipoComprobante,
		*estadoComprobante,
		*rfcACuentaTerceros,
		*complemento,
		*uuid,
	)
	if err != nil {
		return fail(stderr, err)
	}

	client := newClient(common)
	resp, err := client.Consultar(context.Background(), fiel, req)
	if err != nil {
		return fail(stderr, err)
	}

	return writeJSON(stdout, resp, stderr)
}

func buildConsultaRequest(token, rfcSolicitante, fechaInicial, fechaFinal, tipoDescarga, tipoSolicitud string, counterparts []string, tipoComprobante, estadoComprobante, rfcACuentaTerceros, complemento, uuid string) (sat.ConsultaRequest, error) {
	inicial, err := parseCLITime(fechaInicial)
	if err != nil {
		return sat.ConsultaRequest{}, fmt.Errorf("fecha-inicial inválida: %w", err)
	}
	final, err := parseCLITime(fechaFinal)
	if err != nil {
		return sat.ConsultaRequest{}, fmt.Errorf("fecha-final inválida: %w", err)
	}

	req := sat.ConsultaRequest{
		Token:              token,
		RFCSolicitante:     rfcSolicitante,
		FechaInicial:       inicial,
		FechaFinal:         final,
		TipoDescarga:       sat.TipoDescarga(tipoDescarga),
		TipoSolicitud:      sat.TipoSolicitud(tipoSolicitud),
		RFCContrapartes:    counterparts,
		TipoComprobante:    tipoComprobante,
		EstadoComprobante:  sat.EstadoComprobante(estadoComprobante),
		RFCACuentaTerceros: rfcACuentaTerceros,
		Complemento:        complemento,
		UUID:               uuid,
	}
	if strings.TrimSpace(estadoComprobante) == "" && strings.EqualFold(tipoDescarga, string(sat.TipoDescargaRecibidos)) && strings.EqualFold(tipoSolicitud, string(sat.TipoSolicitudCFDI)) {
		req.EstadoComprobante = sat.EstadoComprobanteVigente
	}
	return req, nil
}

func runVerificar(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verificar", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := bindCommonFlags(fs)
	credentials := bindCredentialFlags(fs)

	var (
		token          = fs.String("token", os.Getenv("SAT_TOKEN"), "token SAT")
		rfcSolicitante = fs.String("rfc-solicitante", os.Getenv("SAT_RFC"), "RFC solicitante")
		idSolicitud    = fs.String("id-solicitud", "", "ID de solicitud")
	)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Uso: satcfdi verificar -cert cert.der -key key.der -token TOKEN -rfc-solicitante RFC -id-solicitud REQ-123")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	fiel, err := loadFiel(credentials)
	if err != nil {
		return fail(stderr, err)
	}

	client := newClient(common)
	resp, err := client.VerificarDescarga(context.Background(), fiel, sat.VerificaSolicitudRequest{
		Token:          *token,
		RFCSolicitante: *rfcSolicitante,
		IDSolicitud:    *idSolicitud,
	})
	if err != nil {
		return fail(stderr, err)
	}

	return writeJSON(stdout, resp, stderr)
}

func runDescargar(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("descargar", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := bindCommonFlags(fs)
	credentials := bindCredentialFlags(fs)

	var (
		token          = fs.String("token", os.Getenv("SAT_TOKEN"), "token SAT")
		rfcSolicitante = fs.String("rfc-solicitante", os.Getenv("SAT_RFC"), "RFC solicitante")
		idPaquete      = fs.String("id-paquete", "", "ID del paquete")
	)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Uso: satcfdi descargar -cert cert.der -key key.der -token TOKEN -rfc-solicitante RFC -id-paquete PKG_01")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	fiel, err := loadFiel(credentials)
	if err != nil {
		return fail(stderr, err)
	}

	client := newClient(common)
	resp, err := client.DescargarPaquete(context.Background(), fiel, sat.DescargaPaqueteRequest{
		Token:          *token,
		RFCSolicitante: *rfcSolicitante,
		IDPaquete:      *idPaquete,
	})
	if err != nil {
		return fail(stderr, err)
	}

	return writeJSON(stdout, resp, stderr)
}

func runValidar(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validar", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := bindCommonFlags(fs)

	var (
		rfcEmisor   = fs.String("rfc-emisor", "", "RFC emisor")
		rfcReceptor = fs.String("rfc-receptor", "", "RFC receptor")
		total       = fs.String("total", "", "total del CFDI")
		uuid        = fs.String("uuid", "", "UUID")
	)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Uso: satcfdi validar -rfc-emisor RFC -rfc-receptor RFC -total 100.00 -uuid UUID")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	client := newClient(common)
	resp, err := client.ObtenerEstadoCFDI(context.Background(), sat.ValidacionRequest{
		RFCEmisor:   *rfcEmisor,
		RFCReceptor: *rfcReceptor,
		Total:       *total,
		UUID:        *uuid,
	})
	if err != nil {
		return fail(stderr, err)
	}

	return writeJSON(stdout, resp, stderr)
}

func runFlujo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("flujo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := bindCommonFlags(fs)
	credentials := bindCredentialFlags(fs)

	var counterparts stringList
	var (
		rfcSolicitante     = fs.String("rfc-solicitante", os.Getenv("SAT_RFC"), "RFC solicitante")
		fechaInicial       = fs.String("fecha-inicial", currentMonthStart().Format("2006-01-02"), "fecha inicial (YYYY-MM-DD, RFC3339 o 2006-01-02T15:04:05)")
		fechaFinal         = fs.String("fecha-final", cliNow().Format("2006-01-02"), "fecha final (YYYY-MM-DD, RFC3339 o 2006-01-02T15:04:05)")
		tipoDescarga       = fs.String("tipo-descarga", string(sat.TipoDescargaRecibidos), "tipo de descarga (recibidos o emitidos)")
		tipoSolicitud      = fs.String("tipo-solicitud", string(sat.TipoSolicitudCFDI), "tipo de solicitud (CFDI o Metadata)")
		tipoComprobante    = fs.String("tipo-comprobante", "", "tipo de comprobante")
		estadoComprobante  = fs.String("estado-comprobante", "", "estado del comprobante (Vigente, Cancelado o vacío)")
		rfcACuentaTerceros = fs.String("rfc-a-cuenta-terceros", "", "RFC a cuenta de terceros")
		complemento        = fs.String("complemento", "", "complemento")
		uuid               = fs.String("uuid", "", "UUID")
		pollInterval       = fs.Duration("poll-interval", 5*time.Second, "intervalo entre verificaciones")
		pollAttempts       = fs.Int("poll-attempts", 60, "máximo de verificaciones antes de abortar")
	)
	fs.Var(&counterparts, "rfc-contraparte", "RFC contraparte; puede repetirse o usar comas")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Uso: satcfdi flujo -cert cert.der -key key.der -password secreto -rfc-solicitante RFC -fecha-inicial 2025-01-01 -fecha-final 2025-01-31")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	fiel, err := loadFiel(credentials)
	if err != nil {
		return fail(stderr, err)
	}

	req, err := buildConsultaRequest(
		"",
		*rfcSolicitante,
		*fechaInicial,
		*fechaFinal,
		*tipoDescarga,
		*tipoSolicitud,
		counterparts,
		*tipoComprobante,
		*estadoComprobante,
		*rfcACuentaTerceros,
		*complemento,
		*uuid,
	)
	if err != nil {
		return fail(stderr, err)
	}

	flow, err := satflow.New(satflow.Config{
		Client:         newClient(common),
		Fiel:           fiel,
		RFCSolicitante: *rfcSolicitante,
		Poll: satflow.PollPolicy{
			Interval:    *pollInterval,
			MaxAttempts: *pollAttempts,
		},
	})
	if err != nil {
		return fail(stderr, err)
	}

	resp, err := flow.Run(context.Background(), satflow.DownloadRequest{
		FechaInicial:       req.FechaInicial,
		FechaFinal:         req.FechaFinal,
		TipoDescarga:       req.TipoDescarga,
		TipoSolicitud:      req.TipoSolicitud,
		RFCContrapartes:    req.RFCContrapartes,
		TipoComprobante:    req.TipoComprobante,
		EstadoComprobante:  req.EstadoComprobante,
		RFCACuentaTerceros: req.RFCACuentaTerceros,
		Complemento:        req.Complemento,
		UUID:               req.UUID,
	})
	if err != nil {
		return fail(stderr, err)
	}

	return writeJSON(stdout, resp, stderr)
}
