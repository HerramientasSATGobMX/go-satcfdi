package main

import (
	"context"

	"github.com/herramientassatgobmx/go-satcfdi/examples/internal/exampleutil"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

func main() {
	client, fiel := exampleutil.MustSATClientAndFiel()
	query := exampleutil.MustQueryInput()
	poll := exampleutil.MustPollSettings()
	flow, err := satflow.New(satflow.Config{
		Client:         client,
		Fiel:           fiel,
		RFCSolicitante: query.RFCSolicitante,
		Poll:           poll.SATFlowPolicy(),
	})
	exampleutil.Fail(err)

	// Download es el alias conveniente para Submit -> Wait -> FetchPackages.
	result, err := flow.Download(context.Background(), query.SATFlowRequest())
	exampleutil.Fail(err)

	packages := make([]map[string]any, 0, len(result.Packages))
	for _, pkg := range result.Packages {
		packages = append(packages, map[string]any{
			"package_id":      pkg.ID,
			"sat_status_code": pkg.Response.CodEstatus,
			"sat_message":     pkg.Response.Mensaje,
			"total_bytes":     len(pkg.Bytes),
		})
	}

	exampleutil.JSON(map[string]any{
		"layer":               "satflow",
		"operation":           "download",
		"request_id":          result.Solicitud.IDSolicitud,
		"submit_sat_status":   result.Solicitud.CodEstatus,
		"submit_sat_message":  result.Solicitud.Mensaje,
		"verify_sat_status":   result.Verificacion.CodEstatus,
		"request_status":      exampleutil.SATRequestStatusName(result.Verificacion.EstadoSolicitud),
		"request_status_code": result.Verificacion.CodigoEstadoSolicitud,
		"raw_request_status":  result.Verificacion.EstadoSolicitud,
		"cfdi_count":          result.Verificacion.NumeroCFDIs,
		"verify_sat_message":  result.Verificacion.Mensaje,
		"package_ids":         result.Verificacion.Paquetes,
		"packages":            packages,
	})
}
