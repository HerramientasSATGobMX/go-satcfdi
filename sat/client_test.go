package sat_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
)

func TestObtenerToken(t *testing.T) {
	server := newSOAPServer(t, "auth_success.xml", func(r *http.Request, body []byte) {
		if got := r.Header.Get("SOAPAction"); got != "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica" {
			t.Fatalf("SOAPAction = %q", got)
		}
		assertGolden(t, "auth_request.xml", body)
	})
	defer server.Close()

	client := newTestClient(server)
	token, err := client.ObtenerToken(context.Background(), loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der"))
	if err != nil {
		t.Fatalf("ObtenerToken() error = %v", err)
	}
	if token != "test-token" {
		t.Fatalf("ObtenerToken() = %q", token)
	}
}

func TestConsultarRecibidosGolden(t *testing.T) {
	server := newSOAPServer(t, "solicita_recibidos_success.xml", func(r *http.Request, body []byte) {
		if got := r.Header.Get("SOAPAction"); got != "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos" {
			t.Fatalf("SOAPAction = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != `WRAP access_token="token"` {
			t.Fatalf("Authorization = %q", got)
		}
		assertGolden(t, "solicita_recibidos_request.xml", body)
	})
	defer server.Close()

	client := newTestClient(server)
	resp, err := client.Consultar(context.Background(), loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der"), sat.ConsultaRequest{
		Token:             "token",
		RFCSolicitante:    "xaxx010101000",
		FechaInicial:      time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
		FechaFinal:        time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		TipoDescarga:      sat.TipoDescargaRecibidos,
		TipoSolicitud:     sat.TipoSolicitudCFDI,
		EstadoComprobante: sat.EstadoComprobanteVigente,
	})
	if err != nil {
		t.Fatalf("Consultar() error = %v", err)
	}
	if resp.IDSolicitud != "REQ-REC-123" {
		t.Fatalf("IDSolicitud = %q", resp.IDSolicitud)
	}
}

func TestConsultarEmitidosGolden(t *testing.T) {
	server := newSOAPServer(t, "solicita_emitidos_success.xml", func(r *http.Request, body []byte) {
		if got := r.Header.Get("SOAPAction"); got != "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaEmitidos" {
			t.Fatalf("SOAPAction = %q", got)
		}
		assertGolden(t, "solicita_emitidos_request.xml", body)
	})
	defer server.Close()

	client := newTestClient(server)
	resp, err := client.Consultar(context.Background(), loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der"), sat.ConsultaRequest{
		Token:          "token",
		RFCSolicitante: "AAA010101AAA",
		FechaInicial:   time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
		FechaFinal:     time.Date(2025, 2, 28, 23, 59, 59, 0, time.UTC),
		TipoDescarga:   sat.TipoDescargaEmitidos,
		TipoSolicitud:  sat.TipoSolicitudMetadata,
		RFCContrapartes: []string{
			"BBB010101BBB",
		},
	})
	if err != nil {
		t.Fatalf("Consultar() error = %v", err)
	}
	if resp.IDSolicitud != "REQ-EMI-456" {
		t.Fatalf("IDSolicitud = %q", resp.IDSolicitud)
	}
}

func TestConsultarRecibidosWithCounterpartyUsesRFCEmisor(t *testing.T) {
	server := newSOAPServer(t, "solicita_recibidos_success.xml", func(_ *http.Request, body []byte) {
		request := string(body)
		if !strings.Contains(request, `RfcReceptor="AAA010101AAA"`) {
			t.Fatalf("expected RfcReceptor to use RFC solicitante, got %s", request)
		}
		if !strings.Contains(request, `RfcEmisor="BBB010101BBB"`) {
			t.Fatalf("expected RfcEmisor from RFCContrapartes, got %s", request)
		}
	})
	defer server.Close()

	client := newTestClient(server)
	_, err := client.Consultar(context.Background(), loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der"), sat.ConsultaRequest{
		Token:             "token",
		RFCSolicitante:    "AAA010101AAA",
		FechaInicial:      time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
		FechaFinal:        time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		TipoDescarga:      sat.TipoDescargaRecibidos,
		TipoSolicitud:     sat.TipoSolicitudCFDI,
		EstadoComprobante: sat.EstadoComprobanteVigente,
		RFCContrapartes:   []string{"bbb010101bbb"},
	})
	if err != nil {
		t.Fatalf("Consultar() error = %v", err)
	}
}

func TestConsultarEmitidosSupportsUpToFiveCounterparties(t *testing.T) {
	server := newSOAPServer(t, "solicita_emitidos_success.xml", func(_ *http.Request, body []byte) {
		request := string(body)
		if strings.Contains(request, "<des:RfcReceptor></des:RfcReceptor>") {
			t.Fatalf("request should not keep placeholder receptor nodes: %s", request)
		}
		if got := strings.Count(request, "<des:RfcReceptor>"); got != 5 {
			t.Fatalf("expected 5 RFC receptors, got %d in %s", got, request)
		}
	})
	defer server.Close()

	client := newTestClient(server)
	_, err := client.Consultar(context.Background(), loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der"), sat.ConsultaRequest{
		Token:          "token",
		RFCSolicitante: "AAA010101AAA",
		FechaInicial:   time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
		FechaFinal:     time.Date(2025, 2, 28, 23, 59, 59, 0, time.UTC),
		TipoDescarga:   sat.TipoDescargaEmitidos,
		TipoSolicitud:  sat.TipoSolicitudMetadata,
		RFCContrapartes: []string{
			"BBB010101BBB",
			"CCC010101CCC",
			"DDD010101DDD",
			"EEE010101EEE",
			"FFF010101FFF",
		},
	})
	if err != nil {
		t.Fatalf("Consultar() error = %v", err)
	}
}

func TestConsultarRejectsInvalidRequests(t *testing.T) {
	client := sat.NewClient(sat.Config{
		Clock: func() time.Time { return fixedTime },
	})
	fiel := loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der")

	valid := sat.ConsultaRequest{
		Token:             "token",
		RFCSolicitante:    "AAA010101AAA",
		FechaInicial:      time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
		FechaFinal:        time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		TipoDescarga:      sat.TipoDescargaRecibidos,
		TipoSolicitud:     sat.TipoSolicitudCFDI,
		EstadoComprobante: sat.EstadoComprobanteVigente,
	}

	cases := []struct {
		name    string
		mutate  func(*sat.ConsultaRequest)
		wantErr string
	}{
		{
			name: "equal dates",
			mutate: func(req *sat.ConsultaRequest) {
				req.FechaFinal = req.FechaInicial
			},
			wantErr: "FechaInicial debe ser anterior a FechaFinal",
		},
		{
			name: "outside six year window",
			mutate: func(req *sat.ConsultaRequest) {
				req.FechaInicial = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
			},
			wantErr: "FechaInicial no puede ser anterior a",
		},
		{
			name: "received xml requires vigente",
			mutate: func(req *sat.ConsultaRequest) {
				req.EstadoComprobante = sat.EstadoComprobanteCancelado
			},
			wantErr: "Recibidos + CFDI requiere EstadoComprobante Vigente",
		},
		{
			name: "uuid conflicts with extra filters",
			mutate: func(req *sat.ConsultaRequest) {
				req.UUID = "11111111-2222-3333-4444-555555555555"
				req.TipoComprobante = "I"
			},
			wantErr: "UUID no se puede combinar",
		},
		{
			name: "received max one counterparty",
			mutate: func(req *sat.ConsultaRequest) {
				req.RFCContrapartes = []string{"BBB010101BBB", "CCC010101CCC"}
			},
			wantErr: "Recibidos acepta como máximo 1 RFCContraparte",
		},
		{
			name: "issued max five counterparties",
			mutate: func(req *sat.ConsultaRequest) {
				req.TipoDescarga = sat.TipoDescargaEmitidos
				req.TipoSolicitud = sat.TipoSolicitudMetadata
				req.EstadoComprobante = sat.EstadoComprobanteTodos
				req.RFCContrapartes = []string{"B", "C", "D", "E", "F", "G"}
			},
			wantErr: "Emitidos acepta como máximo 5 RFCContrapartes",
		},
		{
			name: "unsupported tipo descarga",
			mutate: func(req *sat.ConsultaRequest) {
				req.TipoDescarga = sat.TipoDescarga("otra")
			},
			wantErr: "TipoDescarga no soportado",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := valid
			tc.mutate(&req)
			_, err := client.Consultar(context.Background(), fiel, req)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Consultar() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestConsultarRequiresFiel(t *testing.T) {
	client := sat.NewClient(sat.Config{
		Clock: func() time.Time { return fixedTime },
	})
	_, err := client.Consultar(context.Background(), nil, sat.ConsultaRequest{
		Token:             "token",
		RFCSolicitante:    "AAA010101AAA",
		FechaInicial:      time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
		FechaFinal:        time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		TipoDescarga:      sat.TipoDescargaRecibidos,
		TipoSolicitud:     sat.TipoSolicitudCFDI,
		EstadoComprobante: sat.EstadoComprobanteVigente,
	})
	if !errors.Is(err, sat.ErrNilFiel) {
		t.Fatalf("expected ErrNilFiel, got %v", err)
	}
}

func TestConsultarSOAPFault(t *testing.T) {
	server := newSOAPServer(t, "soap_fault.xml", nil)
	defer server.Close()

	client := newTestClient(server)
	_, err := client.Consultar(context.Background(), loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der"), sat.ConsultaRequest{
		Token:             "token",
		RFCSolicitante:    "AAA010101AAA",
		FechaInicial:      time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
		FechaFinal:        time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		TipoDescarga:      sat.TipoDescargaRecibidos,
		TipoSolicitud:     sat.TipoSolicitudCFDI,
		EstadoComprobante: sat.EstadoComprobanteVigente,
	})
	if err == nil || !errors.Is(err, sat.ErrSOAPFault) {
		t.Fatalf("expected ErrSOAPFault, got %v", err)
	}
}

func TestConsultarBusinessError(t *testing.T) {
	server := newSOAPServer(t, "solicita_rechazada.xml", nil)
	defer server.Close()

	client := newTestClient(server)
	resp, err := client.Consultar(context.Background(), loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der"), sat.ConsultaRequest{
		Token:             "token",
		RFCSolicitante:    "AAA010101AAA",
		FechaInicial:      time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
		FechaFinal:        time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		TipoDescarga:      sat.TipoDescargaRecibidos,
		TipoSolicitud:     sat.TipoSolicitudCFDI,
		EstadoComprobante: sat.EstadoComprobanteVigente,
	})
	if !errors.Is(err, sat.ErrSATBusiness) {
		t.Fatalf("expected ErrSATBusiness, got %v", err)
	}
	if resp == nil || resp.CodEstatus != "300" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestVerificarDescargaParsesPackages(t *testing.T) {
	server := newSOAPServer(t, "verifica_with_packages.xml", nil)
	defer server.Close()

	client := newTestClient(server)
	resp, err := client.VerificarDescarga(context.Background(), loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der"), sat.VerificaSolicitudRequest{
		Token:          "token",
		RFCSolicitante: "AAA010101AAA",
		IDSolicitud:    "REQ-123",
	})
	if err != nil {
		t.Fatalf("VerificarDescarga() error = %v", err)
	}
	if resp.EstadoSolicitud != sat.EstadoSolicitudTerminada || len(resp.Paquetes) != 2 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestDescargarPaqueteParsesPayload(t *testing.T) {
	server := newSOAPServer(t, "descarga_success.xml", nil)
	defer server.Close()

	client := newTestClient(server)
	resp, err := client.DescargarPaquete(context.Background(), loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der"), sat.DescargaPaqueteRequest{
		Token:          "token",
		RFCSolicitante: "AAA010101AAA",
		IDPaquete:      "PKG_01",
	})
	if err != nil {
		t.Fatalf("DescargarPaquete() error = %v", err)
	}
	if resp.PaqueteB64 != "UEsDBAoAAAAAAFRFU1Q=" {
		t.Fatalf("PaqueteB64 = %q", resp.PaqueteB64)
	}
}

func TestObtenerEstadoCFDI(t *testing.T) {
	server := newSOAPServer(t, "validacion_success.xml", nil)
	defer server.Close()

	client := newTestClient(server)
	resp, err := client.ObtenerEstadoCFDI(context.Background(), sat.ValidacionRequest{
		RFCEmisor:   "AAA010101AAA",
		RFCReceptor: "BBB010101BBB",
		Total:       "1000.41",
		UUID:        "11111111-2222-3333-4444-555555555555",
	})
	if err != nil {
		t.Fatalf("ObtenerEstadoCFDI() error = %v", err)
	}
	if resp.Estado != "Vigente" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
