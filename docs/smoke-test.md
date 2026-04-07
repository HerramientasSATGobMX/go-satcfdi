# Smoke test manual

Las pruebas automáticas cubren validación local, pero la compatibilidad real con SAT debe confirmarse manualmente con credenciales válidas.

## Antes de empezar

- usa una e.firma controlada
- confirma conectividad hacia SAT
- no compartas credenciales ni logs sensibles

## Pasos

1. Ejecuta la suite local:

```bash
go test ./...
```

2. Prueba el ejemplo completo:

```bash
SAT_CERT_PATH=mi-certificado.cer \
SAT_KEY_PATH=mi-llave.key \
SAT_KEY_PASSWORD=mi-password \
SAT_RFC=XAXX010101000 \
go run ./examples/satflow-download
```

3. Opcionalmente, valida el CLI:

```bash
go run ./cmd/satcfdi flujo \
  -cert mi-certificado.cer \
  -key mi-llave.key \
  -password mi-password \
  -rfc-solicitante XAXX010101000 \
  -tipo-descarga recibidos \
  -tipo-solicitud CFDI
```

4. Si usarás el servicio tipado, valida también `satcfdid` con `./examples/service-run-download-flow`.

## Qué confirmar

- autenticación exitosa
- solicitud aceptada por SAT
- polling hasta estado terminal
- presencia de `package_ids` cuando aplique
- descarga correcta de paquetes
- recuperación automática si el token expira durante el flujo

## Si falla

- revisa fechas, RFCs y filtros
- revisa si hubo `soap fault` o error de negocio
- repite primero con `satflow-download` o con el CLI `flujo`
- comparte solo logs ya revisados y sin secretos
