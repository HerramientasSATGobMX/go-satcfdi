// Package satflow ofrece una capa de orquestación de más alto nivel sobre el
// paquete sat. Mantiene a sat como núcleo SOAP/XML de bajo nivel y sin estado,
// mientras agrega caché de token, refresh proactivo, reintentos, polling y
// orquestación de descarga de paquetes para consumidores Go.
package satflow
