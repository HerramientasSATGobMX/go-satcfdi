# Integración

`go-satcfdi` concentra la parte técnica de integración con SAT:

- construcción y firmado de envelopes SOAP
- autenticación
- solicitudes de descarga masiva
- verificación de solicitudes
- descarga de paquetes
- validación de estado de CFDI
- exposición opcional como servicio tipado

## Capas del proyecto

- `sat`
  Núcleo de bajo nivel y sin estado. Recibe explícitamente credenciales, token y request.
- `satflow`
  Capa de alto nivel para Go. Maneja caché de token, refresh, reintentos y polling.
- `satservice`
  Capa de servicio tipado para otros procesos o lenguajes. Expone Connect, gRPC y gRPC-Web.

## Qué capa usar

- si integras desde Go y quieres simplicidad: usa `satflow`
- si integras desde Go y necesitas control fino: usa `sat`
- si integras desde otro proceso o lenguaje: usa `satservice`

## Alcance y límites

No incluye por defecto:

- extracción de ZIPs
- parseo de CFDI
- workers por jobs
- reglas fiscales o contables de negocio

## Riesgos técnicos a considerar

- SAT es sensible a namespaces, canonicalización y firma XML
- la compatibilidad real debe validarse con pruebas manuales contra SAT
- cualquier diferencia contra SAT debe tratarse como bug
- el uso de credenciales y tokens requiere cuidado operativo y de seguridad

## Validación recomendada

1. Ejecuta pruebas locales.
2. Prueba un flujo real con `satflow`.
3. Si usarás integración remota, valida también `satservice`.

Más detalle:

- [README.md](../README.md)
- [docs/service.md](./service.md)
- [docs/smoke-test.md](./smoke-test.md)
