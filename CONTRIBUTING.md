# Contribuir a `go-satcfdi`

## Antes de abrir un cambio

- usa issues para bugs, mejoras y dudas de diseño
- si el cambio modifica la API pública o el contrato Protobuf, abre primero un issue para discutirlo
- no abras issues públicos con credenciales, tokens, paquetes ni otra información sensible

## Flujo recomendado

1. Haz un fork y crea una rama descriptiva.
2. Mantén el cambio pequeño y enfocado.
3. Añade o actualiza pruebas junto con tu cambio.
4. Actualiza documentación si cambias comportamiento visible.
5. Ejecuta localmente:

```bash
go test ./...
go test -race ./...
go vet ./...
```

6. Abre un pull request con contexto claro.

## Qué tipo de contribuciones sí ayudan

- corrección de bugs
- pruebas faltantes
- mejoras de documentación
- endurecimiento de seguridad
- mejoras pequeñas de ergonomía en CLI o ejemplos

## Qué revisar antes de proponer un cambio grande

- compatibilidad con SAT real
- impacto sobre la API pública
- costo de mantenimiento
- claridad para personas integradoras en México

## Criterios del proyecto

- la librería debe seguir enfocada en integración técnica con SAT
- evita mover lógica de negocio específica de una empresa al core
- cualquier diferencia de comportamiento contra SAT debe tratarse como bug
- no agregues dependencias pesadas sin justificación clara

## Estilo

- usa `gofmt`
- mantén nombres idiomáticos de Go
- documenta símbolos exportados
- escribe documentación y comentarios públicos en español cuando el cambio lo amerite
- añade fixtures y pruebas si modificas firmado XML, parsing SOAP o manejo de credenciales

## Pull requests

En el PR explica:

- qué cambia
- por qué cambia
- cómo se probó
- si hubo impacto en documentación, seguridad o compatibilidad

Si toca seguridad, revisa también [SECURITY.md](./SECURITY.md).
