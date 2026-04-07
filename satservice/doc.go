// Package satservice expone el paquete sat mediante un servicio tipado de Connect
// y gRPC.
//
// La capa de transporte se mantiene delgada y sin estado: traduce solicitudes
// Protobuf a llamadas sobre sat.Client sin mover fuera del paquete sat las
// reglas específicas de SAT.
package satservice
