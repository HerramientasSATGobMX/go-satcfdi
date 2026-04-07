package main

import (
	"context"

	"github.com/herramientassatgobmx/go-satcfdi/examples/internal/exampleutil"
	"github.com/herramientassatgobmx/go-satcfdi/satflow"
)

func main() {
	ctx := context.Background()
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

	// 1. Autenticar y calentar la caché interna de token.
	token, err := flow.Authenticate(ctx)
	exampleutil.Fail(err)

	// 2. Enviar la solicitud SAT. Submit consume el token cacheado de forma automática.
	solicitud, err := flow.Submit(ctx, query.SATFlowRequest())
	exampleutil.Fail(err)

	// 3. Esperar hasta que SAT lleve la solicitud a un estado terminal y devuelva IDs de paquete.
	verificacion, err := flow.Wait(ctx, solicitud.IDSolicitud)
	exampleutil.Fail(err)

	// 4. Descargar y decodificar cada paquete devuelto por SAT.
	packages, err := flow.FetchPackages(ctx, verificacion.Paquetes)
	exampleutil.Fail(err)

	summaries := make([]map[string]any, 0, len(packages))
	for _, pkg := range packages {
		summaries = append(summaries, map[string]any{
			"package_id":      pkg.ID,
			"sat_status_code": pkg.Response.CodEstatus,
			"sat_message":     pkg.Response.Mensaje,
			"total_bytes":     len(pkg.Bytes),
		})
	}

	exampleutil.JSON(map[string]any{
		"layer":     "satflow",
		"operation": "walkthrough",
		"flow": []string{
			"authenticate",
			"submit",
			"wait",
			"fetch_packages",
		},
		"authenticate": map[string]any{
			"produces":             "cached_access_token",
			"access_token_present": token.Value != "",
			"obtained_at":          token.ObtainedAt,
			"expires_at":           token.ExpiresAt,
		},
		"submit": map[string]any{
			"consumes":              "cached_access_token",
			"produces":              "request_id",
			"request_id":            solicitud.IDSolicitud,
			"sat_status_code":       solicitud.CodEstatus,
			"sat_message":           solicitud.Mensaje,
			"rfc_solicitante":       query.RFCSolicitante,
			"tipo_descarga":         query.TipoDescarga,
			"tipo_solicitud":        query.TipoSolicitud,
			"rfc_contrapartes":      query.RFCContrapartes,
			"estado_comprobante":    query.EstadoComprobante,
			"tipo_comprobante":      query.TipoComprobante,
			"rfc_a_cuenta_terceros": query.RFCACuentaTerceros,
			"complemento":           query.Complemento,
			"uuid":                  query.UUID,
		},
		"wait": map[string]any{
			"consumes":            "request_id",
			"produces":            []string{"request_status", "package_ids"},
			"request_id":          solicitud.IDSolicitud,
			"poll_interval":       poll.Interval.String(),
			"poll_max_attempts":   poll.MaxAttempts,
			"sat_status_code":     verificacion.CodEstatus,
			"request_status":      exampleutil.SATRequestStatusName(verificacion.EstadoSolicitud),
			"request_status_code": verificacion.CodigoEstadoSolicitud,
			"raw_request_status":  verificacion.EstadoSolicitud,
			"cfdi_count":          verificacion.NumeroCFDIs,
			"sat_message":         verificacion.Mensaje,
			"package_ids":         verificacion.Paquetes,
		},
		"fetch_packages": map[string]any{
			"consumes":      "package_ids",
			"produces":      "decoded_packages",
			"package_count": len(packages),
			"package_ids":   verificacion.Paquetes,
			"packages":      summaries,
		},
	})
}
