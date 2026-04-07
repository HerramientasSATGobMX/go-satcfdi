# go-satcfdi

`go-satcfdi` es un cliente Go para conectar con los Web Services del SAT relacionados con CFDI.

Sirve para:

- autenticarse con e.firma
- solicitar descargas masivas de CFDI `recibidos` y `emitidos`
- verificar solicitudes y descargar paquetes
- validar el estado de un CFDI
- exponer la integración como servicio tipado para otros procesos o lenguajes

Úsalo si trabajas en:

- equipos backend que integran SAT desde Go
- plataformas internas de facturación, conciliación o backoffice
- proyectos que necesitan una base técnica reusable y no un flujo de negocio cerrado

## No reemplaza

- validación fiscal o legal
- criterio contable
- procesos de negocio propios de cada empresa

## Estado del proyecto

Úsalo para pruebas reales y uso técnico. Antes de llevarlo a producción, valida el flujo completo contra SAT con credenciales reales o de prueba y revisa los límites operativos de tu caso.

## Qué cubre

- autenticación SAT con e.firma
- consultas de descarga masiva para `recibidos` y `emitidos`
- verificación de solicitudes
- descarga de paquetes devueltos por SAT
- validación de estado de CFDI
- firmado XML, canonicalización y construcción de envelopes SOAP
- flujo de alto nivel con caché de token, reintentos y polling vía `satflow`
- servicio tipado sobre Connect + gRPC + gRPC-Web vía `satservice`

## Qué no cubre

- extracción de ZIPs
- parseo de CFDI
- reglas fiscales de negocio
- workers asíncronos por jobs
- SDKs nativos mantenidos para Python o PHP

## Instalación

```bash
go get github.com/herramientassatgobmx/go-satcfdi
```

Desde el repo:

```bash
go run ./cmd/satcfdi help
```

## Ruta recomendada

Usa `satflow` si quieres la ruta más simple desde Go.

```go
package main

import (
	"context"
	"os"
	"time"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

func main() {
	cerDER, _ := os.ReadFile("mi-certificado.cer")
	keyDER, _ := os.ReadFile("mi-llave.key")

	fiel, err := sat.NewFiel(cerDER, keyDER, []byte("mi-password"))
	if err != nil {
		panic(err)
	}

	flow, err := satflow.New(satflow.Config{
		Fiel:           fiel,
		RFCSolicitante: "XAXX010101000",
	})
	if err != nil {
		panic(err)
	}

	result, err := flow.Run(context.Background(), satflow.DownloadRequest{
		FechaInicial:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		FechaFinal:        time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		TipoDescarga:      sat.TipoDescargaRecibidos,
		TipoSolicitud:     sat.TipoSolicitudCFDI,
		EstadoComprobante: sat.EstadoComprobanteVigente,
	})
	if err != nil {
		panic(err)
	}

	_ = result
}
```

## Cómo elegir la capa correcta

- `sat`
  Úsalo si necesitas controlar autenticación, envío, verificación y descarga paso por paso.
- `satflow`
  Úsalo si quieres caché de token, refresh, reintentos, polling y descarga completa.
- `satservice`
  Úsalo si quieres exponer la integración a otros procesos o lenguajes usando Connect, gRPC y gRPC-Web.

Ver [docs/integration.md](./docs/integration.md) y [docs/service.md](./docs/service.md).

## Herramientas incluidas

- `./examples`
  Ejemplos mínimos en Go, Python y PHP
- `./cmd/satcfdi`
  CLI para pruebas manuales y recorridos interactivos
- `./cmd/satcfdid`
  Servicio local con HTTPS por defecto para exponer el contrato tipado

| Ruta | Capa | Qué demuestra |
| --- | --- | --- |
| `./examples/satflow-walkthrough` | `satflow` | Flujo paso a paso |
| `./examples/satflow-download` | `satflow` | Flujo completo de descarga |
| `./examples/service-run-download-flow` | `satservice` | Flujo alto nivel sobre servicio tipado |
| `./examples/python` | `python` | Consumo del servicio por gRPC |
| `./examples/php` | `php` | Consumo del servicio por gRPC |

Más ejemplos en [examples/README.md](./examples/README.md).

## Modelo de consulta

Campos clave:

- `RFCSolicitante`
  RFC dueño de la e.firma y de la consulta
- `TipoDescarga`
  `Recibidos` o `Emitidos`
- `RFCContrapartes`
  RFC o RFCs de contraparte

El cliente prevalida:

- `FechaInicial < FechaFinal`
- la ventana no puede salir del rango permitido por SAT
- `Recibidos + CFDI` usa `EstadoComprobante = Vigente` por defecto
- `UUID` no se puede combinar con filtros incompatibles

## Seguridad y accesibilidad

- nunca persiste `.cer` ni `.key`
- el token no se guarda por defecto
- el guardado en keychain es opcional y explícito
- `satcfdid` usa HTTPS por defecto
- `credential_ref` se resuelve solo dentro de directorios permitidos
- `-insecure-h2c` queda reservado para desarrollo local
- no subas credenciales, tokens, paquetes ni archivos sensibles al repositorio
- no pegues secretos en issues, PRs o discusiones
- usa credenciales controladas para smoke tests
- revisa logs antes de compartirlos públicamente
- ejemplos copiables y completos
- pasos numerados cuando el flujo lo necesita
- lenguaje directo y nombres consistentes
- salida JSON en ejemplos y CLI donde aplica
- documentación basada en texto, sin depender de imágenes para entender el flujo

## Soporte y comunidad

- bugs y propuestas: issues
- cambios acotados: pull requests
- vulnerabilidades: reporte privado por GitHub, según [SECURITY.md](./SECURITY.md)

Antes de abrir un issue:

- confirma que el problema sea reproducible
- no compartas secretos ni documentos sensibles
- incluye versión de Go, sistema operativo y el flujo afectado

## Desarrollo

Comandos recomendados:

```bash
go test ./...
go test -race ./...
go vet ./...
```

Los fixtures y golden files viven en `testdata/`.

## Smoke test manual

Haz una prueba manual fuera de CI:

1. Ejecuta `go test ./...`.
2. Prueba `go run ./examples/satflow-download`.
3. Si necesitas validar la capa tipada, levanta `satcfdid` y usa `./examples/service-run-download-flow`.

Guías:

- [docs/smoke-test.md](./docs/smoke-test.md)
- [docs/service.md](./docs/service.md)

## Documentación adicional

- [examples/README.md](./examples/README.md)
- [docs/integration.md](./docs/integration.md)
- [docs/service.md](./docs/service.md)
- [docs/smoke-test.md](./docs/smoke-test.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SECURITY.md](./SECURITY.md)

## Roadmap corto

Posibles siguientes pasos para el proyecto:

- soporte más explícito para `retenciones e información de pagos` dentro del flujo de recuperación
- capa de cancelación de CFDI: consulta de estatus, motivo de cancelación, folio de sustitución y acuses
- consulta de documentos relacionados por UUID
- validación más completa alrededor de servicios SAT complementarios, como LCO, CSD y folios
- utilidades opcionales de más alto nivel para extracción de paquetes, parseo básico y recorridos operativos
