package main

import (
	"context"

	"connectrpc.com/connect"

	"github.com/herramientassatgobmx/go-satcfdi/examples/internal/exampleutil"
)

func main() {
	clients := exampleutil.MustServiceClients()
	creds := exampleutil.MustServiceCredentialSource()
	query := exampleutil.MustQueryInput()
	poll := exampleutil.MustPollSettings()

	resp, err := clients.Flow.RunDownloadFlow(context.Background(), connect.NewRequest(query.ProtoRunDownloadFlowRequest(creds, poll)))
	exampleutil.Fail(err)

	exampleutil.JSON(map[string]any{
		"layer":               "satservice",
		"operation":           "run_download_flow",
		"credential_source":   creds.Mode,
		"request_id":          resp.Msg.GetRequestId(),
		"submit_sat_status":   resp.Msg.GetSubmitSatStatusCode(),
		"submit_sat_message":  resp.Msg.GetSubmitSatMessage(),
		"verify_sat_status":   resp.Msg.GetVerifySatStatusCode(),
		"request_status":      resp.Msg.GetRequestStatus().String(),
		"request_status_code": resp.Msg.GetRequestStatusCode(),
		"raw_request_status":  resp.Msg.GetRawRequestStatus(),
		"cfdi_count":          resp.Msg.GetCfdiCount(),
		"verify_sat_message":  resp.Msg.GetVerifySatMessage(),
		"package_ids":         resp.Msg.GetPackageIds(),
	})
}
