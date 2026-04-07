# `satservice`

`satservice` expone la integración SAT como servicio tipado con un solo contrato Protobuf.

Expone:

- Connect
- gRPC
- gRPC-Web

## Contrato fuente

- [service.proto](../proto/satcfdi/v1/service.proto)

## Servicios expuestos

- `satcfdi.v1.SATService`
  - `Authenticate`
  - `ConsultDownload`
  - `VerifyDownload`
  - `DownloadPackage`
  - `StreamDownloadPackage`
  - `ValidateCfdi`
- `satcfdi.v1.SATFlowService`
  - `RunDownloadFlow`

`SATService` expone operaciones unitarias. `SATFlowService` expone orquestación síncrona de más alto nivel.

## Credenciales

Los RPCs firmados aceptan exactamente una fuente de credenciales:

- `credentials`
- `credential_ref`

Proveedor disponible hoy:

- `file`

`provider=file` resuelve un descriptor JSON dentro de un directorio permitido del servidor.

Descriptor esperado:

```json
{
  "certificate_path": "cert.der",
  "private_key_path": "key.der",
  "private_key_password": "password"
}
```

Las rutas relativas se resuelven con base en el directorio donde vive el descriptor.

## Descargas grandes

`DownloadPackage` se mantiene para compatibilidad y paquetes pequeños.

Para paquetes grandes, usa `StreamDownloadPackage`.

Valores base:

- límite unary para `DownloadPackage`: `16 MiB`
- tamaño de chunk de streaming: `256 KiB`

## Flujo `RunDownloadFlow`

`RunDownloadFlow` realiza:

1. autenticación
2. envío de solicitud SAT
3. polling hasta estado terminal o timeout

No descarga paquetes. El cliente recibe `request_id`, estado final y `package_ids`, y luego puede descargar cada paquete con `SATService`.

## Errores

El servicio adjunta `satcfdi.v1.ServiceErrorDetail` como detail de error.

Mapeo general:

- validación local: `InvalidArgument`
- credenciales inválidas: `InvalidArgument`
- autenticación/token inválido: `Unauthenticated`
- error de negocio SAT: `FailedPrecondition`
- timeout: `DeadlineExceeded`
- problemas SOAP o transporte: `Unavailable`
- contenido corrupto: `DataLoss`

Detalles enriquecidos disponibles:

- `operation`
- `request_id`
- `package_id`
- `sat_status_code`
- `request_status_code`

## Seguridad operativa

- `satcfdid` usa HTTPS por defecto
- `-insecure-h2c` existe solo para desarrollo local
- `credential_ref` solo puede resolver archivos dentro de directorios permitidos
- si habilitas mTLS, define también `-tls-client-ca`

No publiques:

- certificados
- llaves privadas
- contraseñas
- tokens
- paquetes descargados

## Operación

Valores del servidor:

- timeout upstream SAT: `15s`
- polling: `5s / 60 intentos`
- solicitud unary máxima: `10 MiB`
- respuesta unary máxima: `16 MiB`
- descargas concurrentes: `4`
- streams concurrentes: `4`

Endpoints HTTP:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `/<rpc>`

## Ejecución local

Genera un certificado local de prueba:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/satservice.key \
  -out /tmp/satservice.crt \
  -subj "/CN=127.0.0.1" \
  -days 1
```

Prepara un directorio permitido con tu descriptor:

```bash
mkdir -p /tmp/sat-creds
cat >/tmp/sat-creds/creds.json <<'EOF'
{
  "certificate_path": "/ruta/a/mi-certificado.cer",
  "private_key_path": "/ruta/a/mi-llave.key",
  "private_key_password": "secreto"
}
EOF
```

Levanta el servidor:

```bash
go run ./cmd/satcfdid \
  -listen :8443 \
  -tls-cert /tmp/satservice.crt \
  -tls-key /tmp/satservice.key \
  -credential-dirs /tmp/sat-creds
```

Flujo mínimo desde Go:

```bash
SAT_SERVICE_URL=https://127.0.0.1:8443 \
SAT_SERVICE_INSECURE_SKIP_VERIFY=1 \
SAT_CREDENTIAL_REF=creds.json \
SAT_RFC_SOLICITANTE=XAXX010101000 \
go run ./examples/service-run-download-flow
```

Ver [examples/README.md](../examples/README.md).

## Contrato y generación

```bash
./scripts/generate-proto.sh
./scripts/generate-example-clients.sh
```

## Validación live opcional

Existe una suite live deshabilitada por defecto en [satservice/live_test.go](../satservice/live_test.go).

Variables:

- `SAT_LIVE_ENABLE=1`
- `SAT_LIVE_CERT_PATH`
- `SAT_LIVE_KEY_PATH`
- `SAT_LIVE_KEY_PASSWORD`
- `SAT_LIVE_RFC_SOLICITANTE`
- `SAT_LIVE_RUN_FLOW=1`
