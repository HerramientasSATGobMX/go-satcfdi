from common import (
    close_channel,
    create_stubs,
    emit,
    load_credentials_source,
    rpc_error_message,
    run_flow_request,
    service_pb2,
)


def main() -> None:
    channel, _, flow_stub, target = create_stubs()
    credentials, credential_ref, mode = load_credentials_source()
    try:
        response = flow_stub.RunDownloadFlow(run_flow_request(credentials, credential_ref))
        emit(
            {
                "layer": "python",
                "operation": "run_download_flow",
                "service_target": target,
                "credential_source": mode,
                "request_id": response.request_id,
                "submit_sat_status": response.submit_sat_status_code,
                "submit_sat_message": response.submit_sat_message,
                "verify_sat_status": response.verify_sat_status_code,
                "request_status": service_pb2.DownloadRequestStatus.Name(response.request_status),
                "request_status_code": response.request_status_code,
                "raw_request_status": response.raw_request_status,
                "cfdi_count": response.cfdi_count,
                "verify_sat_message": response.verify_sat_message,
                "package_ids": list(response.package_ids),
            }
        )
    except Exception as exc:  # pragma: no cover
        from grpc import RpcError

        if isinstance(exc, RpcError):
            raise SystemExit(rpc_error_message(exc))
        raise
    finally:
        close_channel(channel)


if __name__ == "__main__":
    main()

