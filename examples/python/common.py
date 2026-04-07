from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple
from urllib.parse import urlparse

import grpc
from google.protobuf.duration_pb2 import Duration
from google.protobuf.timestamp_pb2 import Timestamp

ROOT = Path(__file__).resolve().parent
GENERATED = ROOT / "generated"
if str(GENERATED) not in sys.path:
    sys.path.insert(0, str(GENERATED))

from satcfdi.v1 import service_pb2, service_pb2_grpc  # noqa: E402


def optional(name: str) -> str:
    return os.getenv(name, "").strip()


def env(name: str, fallback: str) -> str:
    value = optional(name)
    return value if value else fallback


def require(name: str) -> str:
    value = optional(name)
    if value:
        return value
    usage(f"{name} es requerido")
    raise AssertionError("unreachable")


def require_any(*names: str) -> str:
    for name in names:
        value = optional(name)
        if value:
            return value
    usage(f"{' o '.join(names)} es requerido")
    raise AssertionError("unreachable")


def usage(message: str) -> None:
    if not message.endswith("\n"):
        message += "\n"
    sys.stderr.write(message)
    raise SystemExit(2)


def fail(message: str) -> None:
    if not message.endswith("\n"):
        message += "\n"
    sys.stderr.write(message)
    raise SystemExit(1)


def emit(payload: object) -> None:
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def split_csv(value: str) -> list[str]:
    if not value.strip():
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def load_inline_credentials() -> service_pb2.SATCredentials:
    cert_path = Path(require("SAT_CERT_PATH"))
    key_path = Path(require("SAT_KEY_PATH"))
    return service_pb2.SATCredentials(
        certificate_der=cert_path.read_bytes(),
        private_key_der=key_path.read_bytes(),
        private_key_password=optional("SAT_KEY_PASSWORD"),
    )


def load_credentials_source() -> Tuple[service_pb2.SATCredentials | None, service_pb2.CredentialRef | None, str]:
    ref = optional("SAT_CREDENTIAL_REF")
    if ref:
        return (
            None,
            service_pb2.CredentialRef(
                provider=env("SAT_CREDENTIAL_PROVIDER", "file"),
                id=ref,
            ),
            "credential_ref",
        )
    return load_inline_credentials(), None, "inline"


def parse_service_target() -> tuple[str, str]:
    target = optional("SAT_SERVICE_TARGET")
    if target:
        return target, "secure"

    raw_url = optional("SAT_SERVICE_URL")
    if not raw_url:
        return "127.0.0.1:8443", "secure"

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        usage("SAT_SERVICE_URL debe usar http:// o https://")
    if not parsed.netloc:
        usage("SAT_SERVICE_URL debe incluir host:port")
    return parsed.netloc, "insecure" if parsed.scheme == "http" else "secure"


def create_channel() -> tuple[grpc.Channel, str]:
    target, mode = parse_service_target()
    if mode == "insecure":
        return grpc.insecure_channel(target), target

    root_certificates = None
    if ca_file := optional("SAT_SERVICE_CA_FILE"):
        root_certificates = Path(ca_file).read_bytes()

    private_key = None
    certificate_chain = None
    client_cert = optional("SAT_SERVICE_CLIENT_CERT_FILE")
    client_key = optional("SAT_SERVICE_CLIENT_KEY_FILE")
    if client_cert or client_key:
        if not client_cert or not client_key:
            usage("SAT_SERVICE_CLIENT_CERT_FILE y SAT_SERVICE_CLIENT_KEY_FILE deben venir juntos")
        certificate_chain = Path(client_cert).read_bytes()
        private_key = Path(client_key).read_bytes()

    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain,
    )

    options: list[tuple[str, str]] = []
    if optional("SAT_SERVICE_INSECURE_SKIP_VERIFY") == "1":
        authority = urlparse(env("SAT_SERVICE_URL", "https://127.0.0.1:8443")).hostname or target.split(":")[0]
        options.extend(
            [
                ("grpc.ssl_target_name_override", authority),
                ("grpc.default_authority", authority),
            ]
        )

    return grpc.secure_channel(target, credentials, options=options), target


def create_stubs() -> tuple[grpc.Channel, service_pb2_grpc.SATServiceStub, service_pb2_grpc.SATFlowServiceStub, str]:
    channel, target = create_channel()
    return channel, service_pb2_grpc.SATServiceStub(channel), service_pb2_grpc.SATFlowServiceStub(channel), target


def rfc_solicitante() -> str:
    return require_any("SAT_RFC_SOLICITANTE", "SAT_RFC")


def request_id() -> str:
    return require("SAT_REQUEST_ID")


def package_id() -> str:
    return require("SAT_PACKAGE_ID")


def parse_datetime(name: str, fallback: datetime, end_of_day: bool) -> datetime:
    raw = optional(name)
    if not raw:
        return fallback.astimezone(timezone.utc)
    try:
        if "T" in raw:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
        value = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if end_of_day:
            return value + timedelta(hours=23, minutes=59, seconds=59)
        return value
    except ValueError as exc:
        usage(f"{name} debe ser RFC3339 o YYYY-MM-DD: {exc}")
        raise AssertionError("unreachable")


def timestamp(value: datetime) -> Timestamp:
    message = Timestamp()
    message.FromDatetime(value.astimezone(timezone.utc))
    return message


def duration(value: timedelta) -> Duration:
    message = Duration()
    message.FromTimedelta(value)
    return message


def query_input() -> dict[str, object]:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "rfc_solicitante": rfc_solicitante(),
        "fecha_inicial": parse_datetime("SAT_FECHA_INICIAL", now - timedelta(days=7), False),
        "fecha_final": parse_datetime("SAT_FECHA_FINAL", now, True),
        "download_type": parse_download_type(env("SAT_TIPO_DESCARGA", "recibidos")),
        "query_type": parse_query_type(env("SAT_TIPO_SOLICITUD", "CFDI")),
        "counterpart_rfc": split_csv(optional("SAT_RFC_CONTRAPARTES")),
        "invoice_type": optional("SAT_TIPO_COMPROBANTE"),
        "invoice_status": parse_invoice_status(optional("SAT_ESTADO_COMPROBANTE")),
        "third_party_rfc": optional("SAT_RFC_TERCERO"),
        "complemento": optional("SAT_COMPLEMENTO"),
        "uuid": optional("SAT_UUID"),
    }
    if payload["fecha_inicial"] >= payload["fecha_final"]:
        usage("SAT_FECHA_INICIAL debe ser menor que SAT_FECHA_FINAL")

    if payload["invoice_status"] is None:
        if payload["download_type"] == service_pb2.DOWNLOAD_TYPE_RECIBIDOS and payload["query_type"] == service_pb2.QUERY_TYPE_CFDI:
            payload["invoice_status"] = service_pb2.INVOICE_STATUS_VIGENTE
        else:
            payload["invoice_status"] = service_pb2.INVOICE_STATUS_ALL
    return payload


def poll_settings() -> tuple[timedelta, int]:
    interval = timedelta(seconds=5)
    attempts = 60

    if raw_interval := optional("SAT_POLL_INTERVAL"):
        try:
            interval = parse_duration(raw_interval)
        except ValueError as exc:
            usage(f"SAT_POLL_INTERVAL debe ser un duration válido: {exc}")

    if raw_attempts := optional("SAT_POLL_MAX_ATTEMPTS"):
        try:
            attempts = int(raw_attempts)
        except ValueError as exc:
            usage(f"SAT_POLL_MAX_ATTEMPTS debe ser un entero válido: {exc}")
        if attempts <= 0:
            usage("SAT_POLL_MAX_ATTEMPTS debe ser > 0")

    return interval, attempts


def parse_duration(raw: str) -> timedelta:
    if raw.endswith("ms"):
        return timedelta(milliseconds=float(raw[:-2]))
    if raw.endswith("s"):
        return timedelta(seconds=float(raw[:-1]))
    if raw.endswith("m"):
        return timedelta(minutes=float(raw[:-1]))
    if raw.endswith("h"):
        return timedelta(hours=float(raw[:-1]))
    raise ValueError(f"valor {raw!r} inválido")


def parse_download_type(value: str) -> int:
    normalized = value.strip().lower()
    if normalized == "recibidos":
        return service_pb2.DOWNLOAD_TYPE_RECIBIDOS
    if normalized == "emitidos":
        return service_pb2.DOWNLOAD_TYPE_EMITIDOS
    usage("SAT_TIPO_DESCARGA debe ser recibidos o emitidos")
    raise AssertionError("unreachable")


def parse_query_type(value: str) -> int:
    normalized = value.strip().lower()
    if normalized == "cfdi":
        return service_pb2.QUERY_TYPE_CFDI
    if normalized == "metadata":
        return service_pb2.QUERY_TYPE_METADATA
    usage("SAT_TIPO_SOLICITUD debe ser CFDI o Metadata")
    raise AssertionError("unreachable")


def parse_invoice_status(value: str) -> int | None:
    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized in ("todos", "all"):
        return service_pb2.INVOICE_STATUS_ALL
    if normalized == "vigente":
        return service_pb2.INVOICE_STATUS_VIGENTE
    if normalized == "cancelado":
        return service_pb2.INVOICE_STATUS_CANCELADO
    usage("SAT_ESTADO_COMPROBANTE debe ser todos, vigente o cancelado")
    raise AssertionError("unreachable")


def authenticate(stub: service_pb2_grpc.SATServiceStub, credentials, credential_ref) -> str:
    response = stub.Authenticate(apply_credentials(service_pb2.AuthenticateRequest(), credentials, credential_ref))
    return response.access_token


def consult_request(access_token: str, credentials, credential_ref) -> service_pb2.ConsultDownloadRequest:
    query = query_input()
    request = service_pb2.ConsultDownloadRequest(
        access_token=access_token,
        rfc_solicitante=str(query["rfc_solicitante"]),
        fecha_inicial=timestamp(query["fecha_inicial"]),
        fecha_final=timestamp(query["fecha_final"]),
        download_type=int(query["download_type"]),
        query_type=int(query["query_type"]),
        counterpart_rfc=list(query["counterpart_rfc"]),
        invoice_type=str(query["invoice_type"]),
        invoice_status=int(query["invoice_status"]),
        third_party_rfc=str(query["third_party_rfc"]),
        complemento=str(query["complemento"]),
        uuid=str(query["uuid"]),
    )
    return apply_credentials(request, credentials, credential_ref)


def run_flow_request(credentials, credential_ref) -> service_pb2.RunDownloadFlowRequest:
    query = query_input()
    interval, attempts = poll_settings()
    request = service_pb2.RunDownloadFlowRequest(
        rfc_solicitante=str(query["rfc_solicitante"]),
        fecha_inicial=timestamp(query["fecha_inicial"]),
        fecha_final=timestamp(query["fecha_final"]),
        download_type=int(query["download_type"]),
        query_type=int(query["query_type"]),
        counterpart_rfc=list(query["counterpart_rfc"]),
        invoice_type=str(query["invoice_type"]),
        invoice_status=int(query["invoice_status"]),
        third_party_rfc=str(query["third_party_rfc"]),
        complemento=str(query["complemento"]),
        uuid=str(query["uuid"]),
        poll_policy=service_pb2.PollPolicy(
            interval=duration(interval),
            max_attempts=attempts,
        ),
    )
    return apply_credentials(request, credentials, credential_ref)


def validate_request() -> service_pb2.ValidateCfdiRequest:
    return service_pb2.ValidateCfdiRequest(
        rfc_emisor=require("SAT_RFC_EMISOR"),
        rfc_receptor=require("SAT_RFC_RECEPTOR"),
        total=require("SAT_TOTAL"),
        uuid=require("SAT_UUID"),
    )


def rpc_error_message(exc: grpc.RpcError) -> str:
    code = exc.code().name if exc.code() else "UNKNOWN"
    details = exc.details() or str(exc)
    return f"{code}: {details}"


def apply_credentials(message, credentials, credential_ref):
    if credentials is not None:
        message.credentials.CopyFrom(credentials)
    if credential_ref is not None:
        message.credential_ref.CopyFrom(credential_ref)
    return message


def enum_name(enum_type, value: int) -> str:
    return enum_type.Name(value)


def close_channel(channel: grpc.Channel) -> None:
    channel.close()
