# Política de seguridad

Si encuentras una vulnerabilidad o una exposición sensible relacionada con:

- manejo de certificados o llaves privadas
- firmado XML
- autenticación SAT
- transporte HTTP o TLS
- resolución de credenciales
- exposición de tokens o paquetes descargados

no la publiques primero en un issue abierto, pull request o discusión.

## Canal de reporte

Usa el mecanismo de reporte privado de seguridad de GitHub del repositorio.

Si el flujo privado todavía no está habilitado en el momento del hallazgo, evita publicar detalles técnicos en abierto y coordina el reporte de forma privada con las personas mantenedoras del proyecto.

## Qué incluir en el reporte

- descripción clara del problema
- impacto esperado
- versión o commit afectado
- pasos para reproducir
- evidencia mínima necesaria, sin adjuntar secretos reales

## Qué no compartir públicamente

- archivos `.cer` o `.key`
- contraseñas de llaves
- tokens SAT
- paquetes descargados
- logs sin revisar
- datos fiscales sensibles de terceros

## Alcance esperado

Se considera especialmente sensible cualquier hallazgo que afecte:

- confidencialidad de credenciales
- autenticación o renovación de token
- validación de rutas en `credential_ref`
- transporte inseguro fuera del modo local explícito
