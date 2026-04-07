package xmlsig_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/soap"
	"github.com/herramientassatgobmx/go-satcfdi/sat/internal/xmlsig"
)

func TestCanonicalizeTimestampGolden(t *testing.T) {
	doc, err := soap.NewTemplateDocument("auth.xml")
	if err != nil {
		t.Fatalf("NewTemplateDocument: %v", err)
	}

	timestamp := soap.FindElement(doc.Root(), "s:Header", "o:Security", "u:Timestamp")
	soap.SetText(soap.FindElement(timestamp, "u:Created"), "2025-01-02T03:04:05.000000Z")
	soap.SetText(soap.FindElement(timestamp, "u:Expires"), "2025-01-02T03:09:05.000000Z")

	got, err := xmlsig.Canonicalize(timestamp)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}

	assertGolden(t, "timestamp_c14n.xml", got)
}

func TestCanonicalizeSolicitudGolden(t *testing.T) {
	doc, err := soap.NewTemplateDocument("solicita_recibidos.xml")
	if err != nil {
		t.Fatalf("NewTemplateDocument: %v", err)
	}

	solicitud := soap.FindElement(doc.Root(), "s:Body", "des:SolicitaDescargaRecibidos", "des:solicitud")
	soap.SetAttr(solicitud, "RfcSolicitante", "XAXX010101000")
	soap.SetAttr(solicitud, "FechaInicial", "2025-01-01T00:00:01")
	soap.SetAttr(solicitud, "FechaFinal", "2025-01-31T23:59:59")
	soap.SetAttr(solicitud, "TipoSolicitud", string(sat.TipoSolicitudCFDI))
	soap.SetAttr(solicitud, "RfcReceptor", "XAXX010101000")

	got, err := xmlsig.Canonicalize(solicitud.Parent())
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}

	assertGolden(t, "solicita_recibidos_c14n.xml", got)
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "golden", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Fatalf("golden mismatch for %s\nwant:\n%s\n\ngot:\n%s", name, want, got)
	}
}
