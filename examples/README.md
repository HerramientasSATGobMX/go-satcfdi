# Ejemplos

Todos los ejemplos usan:

- entrada solo por variables de entorno
- salida solo en JSON por `stdout`
- si faltan variables obligatorias, imprimen un mensaje corto en `stderr` y salen con `exit 2`
- no imprimen tokens, DER, contraseñas ni contenido binario crudo

## Variables comunes

- `SAT_FECHA_INICIAL` y `SAT_FECHA_FINAL`
  Aceptan `RFC3339` o `YYYY-MM-DD`. Si faltan, usan `ahora - 7d` y `ahora`.
- `SAT_TIPO_DESCARGA`
  Usa `recibidos` si no lo defines.
- `SAT_TIPO_SOLICITUD`
  Usa `CFDI` si no lo defines.
- `SAT_ESTADO_COMPROBANTE`
  Usa `Vigente` por defecto solo para `recibidos + CFDI`.
- `SAT_RFC_CONTRAPARTES`, `SAT_TIPO_COMPROBANTE`, `SAT_RFC_TERCERO`, `SAT_COMPLEMENTO`, `SAT_UUID`
- `SAT_POLL_INTERVAL` y `SAT_POLL_MAX_ATTEMPTS`

## Go con `satflow`

### 1. Flujo paso a paso

`./examples/satflow-walkthrough` muestra el recorrido completo en orden:

- `Authenticate` obtiene el token
- `Submit` crea la solicitud
- `Wait` hace polling hasta estado terminal
- `FetchPackages` descarga los paquetes ya terminados

```bash
SAT_CERT_PATH=mi-certificado.cer \
SAT_KEY_PATH=mi-llave.key \
SAT_KEY_PASSWORD=mi-password \
SAT_RFC=XAXX010101000 \
go run ./examples/satflow-walkthrough
```

### 2. Flujo completo

`./examples/satflow-download` ejecuta `Submit -> Wait -> FetchPackages`.

```bash
SAT_CERT_PATH=mi-certificado.cer \
SAT_KEY_PATH=mi-llave.key \
SAT_KEY_PASSWORD=mi-password \
SAT_RFC=XAXX010101000 \
go run ./examples/satflow-download
```

## `satservice`

Por defecto, los ejemplos del servicio apuntan a `SAT_SERVICE_URL=https://127.0.0.1:8443`.

Si usas `credential_ref`:

```bash
SAT_CREDENTIAL_REF=creds.json
```

O credenciales inline:

```bash
SAT_CERT_PATH=mi-certificado.cer
SAT_KEY_PATH=mi-llave.key
SAT_KEY_PASSWORD=mi-password
```

### 1. Go

```bash
SAT_SERVICE_INSECURE_SKIP_VERIFY=1 \
SAT_CREDENTIAL_REF=creds.json \
SAT_RFC_SOLICITANTE=XAXX010101000 \
go run ./examples/service-run-download-flow
```

### 2. Python

Instalación:

```bash
cd examples/python
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Ejecución:

```bash
SAT_SERVICE_CA_FILE=/tmp/satservice.crt \
SAT_CREDENTIAL_REF=creds.json \
SAT_RFC_SOLICITANTE=XAXX010101000 \
python run_download_flow.py
```

### 3. PHP

Instalación:

```bash
cd examples/php
composer install --ignore-platform-req=ext-grpc
```

Requiere `ext-grpc` para ejecutar RPCs reales.

```bash
SAT_SERVICE_CA_FILE=/tmp/satservice.crt \
SAT_CREDENTIAL_REF=creds.json \
SAT_RFC_SOLICITANTE=XAXX010101000 \
php run_download_flow.php
```
