# Ejemplos de Python por gRPC

Usan `satcfdid` por gRPC con el contrato `satcfdi.v1`.

## Instalación

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Variables compartidas

- `SAT_SERVICE_TARGET`
  Usa `127.0.0.1:8443` si no lo defines.
- `SAT_SERVICE_URL`
  Alternativa a `SAT_SERVICE_TARGET`; acepta `https://127.0.0.1:8443`
- `SAT_SERVICE_CA_FILE`
- `SAT_SERVICE_INSECURE_SKIP_VERIFY`
- `SAT_SERVICE_CLIENT_CERT_FILE`
- `SAT_SERVICE_CLIENT_KEY_FILE`
- `SAT_CREDENTIAL_REF`
  Úsalo si la credencial ya está disponible en el servidor.
- `SAT_CERT_PATH`, `SAT_KEY_PATH`, `SAT_KEY_PASSWORD`
  Úsalos si prefieres mandar la credencial inline.

## Flujo completo

```bash
SAT_SERVICE_CA_FILE=/tmp/satservice.crt \
SAT_CREDENTIAL_REF=creds.json \
SAT_RFC_SOLICITANTE=XAXX010101000 \
python run_download_flow.py
```
