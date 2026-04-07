package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

type shellSession struct {
	client         *sat.Client
	fiel           *sat.Fiel
	token          string
	rfcSolicitante string
	lastSolicitud  string
	tokenStore     tokenStore
}

func runShell(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flagSetForShell(stderr)
	common := bindCommonFlags(fs)
	credentials := bindCredentialFlags(fs)
	initialRFC := fs.String("rfc-solicitante", os.Getenv("SAT_RFC"), "RFC solicitante inicial")
	initialToken := fs.String("token", os.Getenv("SAT_TOKEN"), "token SAT inicial")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	reader := bufio.NewReader(stdin)
	fmt.Fprintln(stdout, "Shell interactiva de go-satcfdi")
	fmt.Fprintln(stdout, "Presiona Enter para aceptar el valor predeterminado mostrado entre corchetes.")
	fmt.Fprintln(stdout, "Escribe help para ver comandos.")
	fmt.Fprintln(stdout)

	certPath, err := prompt(reader, stdout, "Ruta del certificado .cer", credentials.certPath, true)
	if err != nil {
		return fail(stderr, err)
	}
	keyPath, err := prompt(reader, stdout, "Ruta de la llave .key", credentials.keyPath, true)
	if err != nil {
		return fail(stderr, err)
	}
	password, err := prompt(reader, stdout, "Contraseña de la llave", credentials.password, false)
	if err != nil {
		return fail(stderr, err)
	}
	rfcSolicitante, err := prompt(reader, stdout, "RFC solicitante", *initialRFC, false)
	if err != nil {
		return fail(stderr, err)
	}

	fiel, err := loadFiel(&credentialOptions{certPath: certPath, keyPath: keyPath, password: password})
	if err != nil {
		return fail(stderr, err)
	}

	store, err := newTokenStore(common.tokenStore, effectiveEndpoints(common))
	if err != nil {
		return fail(stderr, err)
	}

	session := &shellSession{
		client:         newClient(common),
		fiel:           fiel,
		token:          strings.TrimSpace(*initialToken),
		rfcSolicitante: rfcSolicitante,
		tokenStore:     store,
	}

	for {
		fmt.Fprint(stdout, "satcfdi> ")
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return fail(stderr, err)
		}
		command := strings.TrimSpace(line)
		if command == "" {
			if err == io.EOF {
				fmt.Fprintln(stdout, "Sesión terminada.")
				return 0
			}
			continue
		}

		if exit := executeShellCommand(reader, stdout, stderr, session, command); exit {
			return 0
		}
		if err == io.EOF {
			fmt.Fprintln(stdout, "Sesión terminada.")
			return 0
		}
	}
}

func flagSetForShell(stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Uso: satcfdi shell [-cert cert.der] [-key key.der] [-password secreto] [-rfc-solicitante RFC] [-token TOKEN] [-token-store keychain]")
		fs.PrintDefaults()
	}
	return fs
}

func executeShellCommand(reader *bufio.Reader, stdout, stderr io.Writer, session *shellSession, command string) bool {
	fields := strings.Fields(command)
	switch fields[0] {
	case "help":
		printShellHelp(stdout)
	case "exit", "quit", "salir":
		fmt.Fprintln(stdout, "Sesión terminada.")
		return true
	case "auth":
		flow, err := session.newFlow()
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return false
		}
		token, err := flow.Authenticate(context.Background())
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return false
		}
		session.token = token.Value
		_ = writeJSON(stdout, map[string]string{"token": token.Value}, stderr)
	case "solicitar":
		if err := shellSolicitar(reader, stdout, stderr, session); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
	case "verificar":
		if err := shellVerificar(reader, stdout, stderr, session); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
	case "descargar":
		if err := shellDescargar(reader, stdout, stderr, session); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
	case "flujo":
		if err := shellFlujo(reader, stdout, stderr, session); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
	case "validar":
		if err := shellValidar(reader, stdout, stderr, session); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
	case "context":
		payload := map[string]any{
			"rfc_solicitante": session.rfcSolicitante,
			"has_token":       strings.TrimSpace(session.token) != "",
			"last_solicitud":  session.lastSolicitud,
			"token_store":     session.tokenStore.mode,
		}
		_ = writeJSON(stdout, payload, stderr)
	case "set":
		if len(fields) < 3 {
			fmt.Fprintln(stderr, "uso: set rfc <RFC> | set token <TOKEN>")
			return false
		}
		value := strings.Join(fields[2:], " ")
		switch fields[1] {
		case "rfc":
			session.rfcSolicitante = strings.TrimSpace(value)
		case "token":
			session.token = strings.TrimSpace(value)
		default:
			fmt.Fprintln(stderr, "uso: set rfc <RFC> | set token <TOKEN>")
		}
	case "token":
		if len(fields) < 2 {
			fmt.Fprintln(stderr, "uso: token load | token save | token clear")
			return false
		}
		switch fields[1] {
		case "load":
			token, err := session.tokenStore.Load(session.rfcSolicitante)
			if err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return false
			}
			session.token = token
			if strings.TrimSpace(token) == "" {
				fmt.Fprintln(stdout, "No hay token almacenado para este RFC y endpoint.")
			} else {
				fmt.Fprintf(stdout, "Token cargado para %s.\n", normalizeRFC(session.rfcSolicitante))
			}
		case "save":
			if err := session.tokenStore.Save(session.rfcSolicitante, session.token); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return false
			}
			fmt.Fprintf(stdout, "Token guardado para %s.\n", normalizeRFC(session.rfcSolicitante))
		case "clear":
			if err := session.tokenStore.Clear(session.rfcSolicitante); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return false
			}
			fmt.Fprintf(stdout, "Token eliminado para %s.\n", normalizeRFC(session.rfcSolicitante))
		default:
			fmt.Fprintln(stderr, "uso: token load | token save | token clear")
		}
	default:
		fmt.Fprintf(stderr, "comando desconocido: %s\n", fields[0])
	}
	return false
}

func shellSolicitar(reader *bufio.Reader, stdout, stderr io.Writer, session *shellSession) error {
	token, rfcSolicitante, err := promptTokenAndRFC(reader, stdout, session)
	if err != nil {
		return err
	}

	fechaInicial, err := prompt(reader, stdout, "Fecha inicial", currentMonthStart().Format("2006-01-02"), false)
	if err != nil {
		return err
	}
	fechaFinal, err := prompt(reader, stdout, "Fecha final", cliNow().Format("2006-01-02"), false)
	if err != nil {
		return err
	}
	tipoDescarga, err := prompt(reader, stdout, "Tipo de descarga", string(sat.TipoDescargaRecibidos), false)
	if err != nil {
		return err
	}
	tipoSolicitud, err := prompt(reader, stdout, "Tipo de solicitud", string(sat.TipoSolicitudCFDI), false)
	if err != nil {
		return err
	}
	contrapartes, err := prompt(reader, stdout, "RFC contraparte(s) (opcional, separadas por coma)", "", false)
	if err != nil {
		return err
	}
	tipoComprobante, err := prompt(reader, stdout, "Tipo de comprobante (opcional)", "", false)
	if err != nil {
		return err
	}
	estadoDefault := ""
	if strings.EqualFold(tipoDescarga, string(sat.TipoDescargaRecibidos)) && strings.EqualFold(tipoSolicitud, string(sat.TipoSolicitudCFDI)) {
		estadoDefault = string(sat.EstadoComprobanteVigente)
	}
	estadoComprobante, err := prompt(reader, stdout, "Estado del comprobante (opcional)", estadoDefault, false)
	if err != nil {
		return err
	}
	rfcACuentaTerceros, err := prompt(reader, stdout, "RFC a cuenta de terceros (opcional)", "", false)
	if err != nil {
		return err
	}
	complemento, err := prompt(reader, stdout, "Complemento (opcional)", "", false)
	if err != nil {
		return err
	}
	uuid, err := prompt(reader, stdout, "UUID (opcional)", "", false)
	if err != nil {
		return err
	}

	var counterparts stringList
	_ = counterparts.Set(contrapartes)
	req, err := buildConsultaRequest(token, rfcSolicitante, fechaInicial, fechaFinal, tipoDescarga, tipoSolicitud, counterparts, tipoComprobante, estadoComprobante, rfcACuentaTerceros, complemento, uuid)
	if err != nil {
		return err
	}

	resp, err := session.client.Consultar(context.Background(), session.fiel, req)
	if err != nil {
		return err
	}
	session.lastSolicitud = resp.IDSolicitud
	return decodeWriteJSON(stdout, resp, stderr)
}

func shellVerificar(reader *bufio.Reader, stdout, stderr io.Writer, session *shellSession) error {
	token, rfcSolicitante, err := promptTokenAndRFC(reader, stdout, session)
	if err != nil {
		return err
	}
	idSolicitud, err := prompt(reader, stdout, "ID de solicitud", session.lastSolicitud, true)
	if err != nil {
		return err
	}

	resp, err := session.client.VerificarDescarga(context.Background(), session.fiel, sat.VerificaSolicitudRequest{
		Token:          token,
		RFCSolicitante: rfcSolicitante,
		IDSolicitud:    idSolicitud,
	})
	if err != nil {
		return err
	}
	return decodeWriteJSON(stdout, resp, stderr)
}

func shellDescargar(reader *bufio.Reader, stdout, stderr io.Writer, session *shellSession) error {
	token, rfcSolicitante, err := promptTokenAndRFC(reader, stdout, session)
	if err != nil {
		return err
	}
	idPaquete, err := prompt(reader, stdout, "ID del paquete", "", true)
	if err != nil {
		return err
	}

	resp, err := session.client.DescargarPaquete(context.Background(), session.fiel, sat.DescargaPaqueteRequest{
		Token:          token,
		RFCSolicitante: rfcSolicitante,
		IDPaquete:      idPaquete,
	})
	if err != nil {
		return err
	}
	return decodeWriteJSON(stdout, resp, stderr)
}

func shellValidar(reader *bufio.Reader, stdout, stderr io.Writer, session *shellSession) error {
	rfcEmisor, err := prompt(reader, stdout, "RFC emisor", "", true)
	if err != nil {
		return err
	}
	rfcReceptor, err := prompt(reader, stdout, "RFC receptor", "", true)
	if err != nil {
		return err
	}
	total, err := prompt(reader, stdout, "Total", "", true)
	if err != nil {
		return err
	}
	uuid, err := prompt(reader, stdout, "UUID", "", true)
	if err != nil {
		return err
	}

	resp, err := session.client.ObtenerEstadoCFDI(context.Background(), sat.ValidacionRequest{
		RFCEmisor:   rfcEmisor,
		RFCReceptor: rfcReceptor,
		Total:       total,
		UUID:        uuid,
	})
	if err != nil {
		return err
	}
	return decodeWriteJSON(stdout, resp, stderr)
}

func shellFlujo(reader *bufio.Reader, stdout, stderr io.Writer, session *shellSession) error {
	rfcSolicitante, err := prompt(reader, stdout, "RFC solicitante", session.rfcSolicitante, true)
	if err != nil {
		return err
	}
	session.rfcSolicitante = rfcSolicitante

	fechaInicial, err := prompt(reader, stdout, "Fecha inicial", currentMonthStart().Format("2006-01-02"), false)
	if err != nil {
		return err
	}
	fechaFinal, err := prompt(reader, stdout, "Fecha final", cliNow().Format("2006-01-02"), false)
	if err != nil {
		return err
	}
	tipoDescarga, err := prompt(reader, stdout, "Tipo de descarga", string(sat.TipoDescargaRecibidos), false)
	if err != nil {
		return err
	}
	tipoSolicitud, err := prompt(reader, stdout, "Tipo de solicitud", string(sat.TipoSolicitudCFDI), false)
	if err != nil {
		return err
	}
	contrapartes, err := prompt(reader, stdout, "RFC contraparte(s) (opcional, separadas por coma)", "", false)
	if err != nil {
		return err
	}
	tipoComprobante, err := prompt(reader, stdout, "Tipo de comprobante (opcional)", "", false)
	if err != nil {
		return err
	}
	estadoDefault := ""
	if strings.EqualFold(tipoDescarga, string(sat.TipoDescargaRecibidos)) && strings.EqualFold(tipoSolicitud, string(sat.TipoSolicitudCFDI)) {
		estadoDefault = string(sat.EstadoComprobanteVigente)
	}
	estadoComprobante, err := prompt(reader, stdout, "Estado del comprobante (opcional)", estadoDefault, false)
	if err != nil {
		return err
	}
	rfcACuentaTerceros, err := prompt(reader, stdout, "RFC a cuenta de terceros (opcional)", "", false)
	if err != nil {
		return err
	}
	complemento, err := prompt(reader, stdout, "Complemento (opcional)", "", false)
	if err != nil {
		return err
	}
	uuid, err := prompt(reader, stdout, "UUID (opcional)", "", false)
	if err != nil {
		return err
	}

	var counterparts stringList
	_ = counterparts.Set(contrapartes)
	req, err := buildConsultaRequest("", rfcSolicitante, fechaInicial, fechaFinal, tipoDescarga, tipoSolicitud, counterparts, tipoComprobante, estadoComprobante, rfcACuentaTerceros, complemento, uuid)
	if err != nil {
		return err
	}

	flow, err := session.newFlow()
	if err != nil {
		return err
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
		return err
	}

	session.lastSolicitud = resp.Solicitud.IDSolicitud
	token, tokenErr := flow.Authenticate(context.Background())
	if tokenErr == nil {
		session.token = token.Value
	}
	return decodeWriteJSON(stdout, resp, stderr)
}

func promptTokenAndRFC(reader *bufio.Reader, stdout io.Writer, session *shellSession) (string, string, error) {
	rfcSolicitante, err := prompt(reader, stdout, "RFC solicitante", session.rfcSolicitante, true)
	if err != nil {
		return "", "", err
	}
	token, err := prompt(reader, stdout, "Token SAT", session.token, false)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(token) == "" {
		return "", "", fmt.Errorf("token SAT requerido; usa auth o set token")
	}
	session.rfcSolicitante = rfcSolicitante
	session.token = token
	return token, rfcSolicitante, nil
}

func decodeWriteJSON(stdout io.Writer, v any, stderr io.Writer) error {
	if code := writeJSON(stdout, v, stderr); code != 0 {
		return fmt.Errorf("no se pudo escribir JSON")
	}
	return nil
}

func (s *shellSession) newFlow() (*satflow.Client, error) {
	return satflow.New(satflow.Config{
		Client:         s.client,
		Fiel:           s.fiel,
		RFCSolicitante: s.rfcSolicitante,
	})
}

func printShellHelp(stdout io.Writer) {
	fmt.Fprintln(stdout, "Comandos disponibles:")
	fmt.Fprintln(stdout, "  help")
	fmt.Fprintln(stdout, "  auth")
	fmt.Fprintln(stdout, "  solicitar")
	fmt.Fprintln(stdout, "  verificar")
	fmt.Fprintln(stdout, "  descargar")
	fmt.Fprintln(stdout, "  flujo")
	fmt.Fprintln(stdout, "  validar")
	fmt.Fprintln(stdout, "  context")
	fmt.Fprintln(stdout, "  set rfc <RFC>")
	fmt.Fprintln(stdout, "  set token <TOKEN>")
	fmt.Fprintln(stdout, "  token load")
	fmt.Fprintln(stdout, "  token save")
	fmt.Fprintln(stdout, "  token clear")
	fmt.Fprintln(stdout, "  exit")
}
