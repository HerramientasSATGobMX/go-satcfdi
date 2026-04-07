<?php

declare(strict_types=1);

namespace SatcfdiExamples;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Google\Protobuf\Duration;
use Google\Protobuf\Timestamp;
use Satcfdi\V1\AuthenticateRequest;
use Satcfdi\V1\CredentialRef;
use Satcfdi\V1\PollPolicy;
use Satcfdi\V1\RunDownloadFlowRequest;
use Satcfdi\V1\SATCredentials;
use Satcfdi\V1\ValidateCfdiRequest;
use Satcfdi\V1\ConsultDownloadRequest;
use Satcfdi\V1\DownloadType;
use Satcfdi\V1\InvoiceStatus;
use Satcfdi\V1\QueryType;
use Throwable;

final class Common
{
    public static function optional(string $name): string
    {
        $value = getenv($name);
        return $value === false ? '' : trim($value);
    }

    public static function env(string $name, string $fallback): string
    {
        $value = self::optional($name);
        return $value !== '' ? $value : $fallback;
    }

    public static function require(string $name): string
    {
        $value = self::optional($name);
        if ($value !== '') {
            return $value;
        }
        self::usage(sprintf('%s es requerido', $name));
    }

    public static function requireAny(string ...$names): string
    {
        foreach ($names as $name) {
            $value = self::optional($name);
            if ($value !== '') {
                return $value;
            }
        }
        self::usage(sprintf('%s es requerido', implode(' o ', $names)));
    }

    public static function usage(string $message): never
    {
        fwrite(STDERR, rtrim($message) . PHP_EOL);
        exit(2);
    }

    public static function fail(string $message, int $code = 1): never
    {
        fwrite(STDERR, rtrim($message) . PHP_EOL);
        exit($code);
    }

    public static function emit(array $payload): void
    {
        echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    }

    public static function splitCsv(string $value): array
    {
        if (trim($value) === '') {
            return [];
        }
        return array_values(array_filter(array_map('trim', explode(',', $value)), static fn(string $part): bool => $part !== ''));
    }

    public static function credentialsSource(): array
    {
        $credentialRef = self::optional('SAT_CREDENTIAL_REF');
        if ($credentialRef !== '') {
            return [
                null,
                new CredentialRef([
                    'provider' => self::env('SAT_CREDENTIAL_PROVIDER', 'file'),
                    'id' => $credentialRef,
                ]),
                'credential_ref',
            ];
        }

        return [
            new SATCredentials([
                'certificate_der' => self::readFile(self::require('SAT_CERT_PATH')),
                'private_key_der' => self::readFile(self::require('SAT_KEY_PATH')),
                'private_key_password' => self::optional('SAT_KEY_PASSWORD'),
            ]),
            null,
            'inline',
        ];
    }

    public static function serviceTargetAndSecurity(): array
    {
        $target = self::optional('SAT_SERVICE_TARGET');
        if ($target !== '') {
            return [$target, 'secure'];
        }

        $serviceUrl = self::optional('SAT_SERVICE_URL');
        if ($serviceUrl === '') {
            return ['127.0.0.1:8443', 'secure'];
        }

        $parts = parse_url($serviceUrl);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            self::usage('SAT_SERVICE_URL debe incluir esquema y host');
        }

        $port = $parts['port'] ?? (($parts['scheme'] ?? 'https') === 'http' ? 80 : 443);
        return [sprintf('%s:%d', $parts['host'], $port), ($parts['scheme'] ?? 'https') === 'http' ? 'insecure' : 'secure'];
    }

    public static function rfcSolicitante(): string
    {
        return self::requireAny('SAT_RFC_SOLICITANTE', 'SAT_RFC');
    }

    public static function requestId(): string
    {
        return self::require('SAT_REQUEST_ID');
    }

    public static function packageId(): string
    {
        return self::require('SAT_PACKAGE_ID');
    }

    public static function authenticateRequest($credentials, $credentialRef): AuthenticateRequest
    {
        return self::applyCredentials(new AuthenticateRequest(), $credentials, $credentialRef);
    }

    public static function consultRequest(string $accessToken, $credentials, $credentialRef): ConsultDownloadRequest
    {
        $query = self::queryInput();
        $request = new ConsultDownloadRequest([
            'access_token' => $accessToken,
            'rfc_solicitante' => $query['rfc_solicitante'],
            'fecha_inicial' => self::timestamp($query['fecha_inicial']),
            'fecha_final' => self::timestamp($query['fecha_final']),
            'download_type' => $query['download_type'],
            'query_type' => $query['query_type'],
            'counterpart_rfc' => $query['counterpart_rfc'],
            'invoice_type' => $query['invoice_type'],
            'invoice_status' => $query['invoice_status'],
            'third_party_rfc' => $query['third_party_rfc'],
            'complemento' => $query['complemento'],
            'uuid' => $query['uuid'],
        ]);
        return self::applyCredentials($request, $credentials, $credentialRef);
    }

    public static function runFlowRequest($credentials, $credentialRef): RunDownloadFlowRequest
    {
        $query = self::queryInput();
        [$interval, $maxAttempts] = self::pollSettings();
        $request = new RunDownloadFlowRequest([
            'rfc_solicitante' => $query['rfc_solicitante'],
            'fecha_inicial' => self::timestamp($query['fecha_inicial']),
            'fecha_final' => self::timestamp($query['fecha_final']),
            'download_type' => $query['download_type'],
            'query_type' => $query['query_type'],
            'counterpart_rfc' => $query['counterpart_rfc'],
            'invoice_type' => $query['invoice_type'],
            'invoice_status' => $query['invoice_status'],
            'third_party_rfc' => $query['third_party_rfc'],
            'complemento' => $query['complemento'],
            'uuid' => $query['uuid'],
            'poll_policy' => new PollPolicy([
                'interval' => self::duration($interval),
                'max_attempts' => $maxAttempts,
            ]),
        ]);
        return self::applyCredentials($request, $credentials, $credentialRef);
    }

    public static function validateRequest(): ValidateCfdiRequest
    {
        return new ValidateCfdiRequest([
            'rfc_emisor' => self::require('SAT_RFC_EMISOR'),
            'rfc_receptor' => self::require('SAT_RFC_RECEPTOR'),
            'total' => self::require('SAT_TOTAL'),
            'uuid' => self::require('SAT_UUID'),
        ]);
    }

    public static function queryInput(): array
    {
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $downloadType = self::parseDownloadType(self::env('SAT_TIPO_DESCARGA', 'recibidos'));
        $queryType = self::parseQueryType(self::env('SAT_TIPO_SOLICITUD', 'CFDI'));
        $invoiceStatus = self::parseInvoiceStatus(self::optional('SAT_ESTADO_COMPROBANTE'));
        if ($invoiceStatus === null) {
            $invoiceStatus = $downloadType === DownloadType::DOWNLOAD_TYPE_RECIBIDOS && $queryType === QueryType::QUERY_TYPE_CFDI
                ? InvoiceStatus::INVOICE_STATUS_VIGENTE
                : InvoiceStatus::INVOICE_STATUS_ALL;
        }

        $payload = [
            'rfc_solicitante' => self::rfcSolicitante(),
            'fecha_inicial' => self::parseDateTime('SAT_FECHA_INICIAL', $now->modify('-7 days'), false),
            'fecha_final' => self::parseDateTime('SAT_FECHA_FINAL', $now, true),
            'download_type' => $downloadType,
            'query_type' => $queryType,
            'counterpart_rfc' => self::splitCsv(self::optional('SAT_RFC_CONTRAPARTES')),
            'invoice_type' => self::optional('SAT_TIPO_COMPROBANTE'),
            'invoice_status' => $invoiceStatus,
            'third_party_rfc' => self::optional('SAT_RFC_TERCERO'),
            'complemento' => self::optional('SAT_COMPLEMENTO'),
            'uuid' => self::optional('SAT_UUID'),
        ];

        if ($payload['fecha_inicial'] >= $payload['fecha_final']) {
            self::usage('SAT_FECHA_INICIAL debe ser menor que SAT_FECHA_FINAL');
        }

        return $payload;
    }

    public static function pollSettings(): array
    {
        $interval = new DateInterval('PT5S');
        $maxAttempts = 60;

        if (($raw = self::optional('SAT_POLL_INTERVAL')) !== '') {
            $interval = self::parseDuration($raw);
        }
        if (($raw = self::optional('SAT_POLL_MAX_ATTEMPTS')) !== '') {
            if (!ctype_digit($raw) || (int) $raw <= 0) {
                self::usage('SAT_POLL_MAX_ATTEMPTS debe ser un entero > 0');
            }
            $maxAttempts = (int) $raw;
        }

        return [$interval, $maxAttempts];
    }

    public static function timestamp(DateTimeImmutable $value): Timestamp
    {
        $seconds = (int) $value->format('U');
        $nanos = ((int) $value->format('u')) * 1000;
        $timestamp = new Timestamp();
        $timestamp->setSeconds($seconds);
        $timestamp->setNanos($nanos);
        return $timestamp;
    }

    public static function duration(DateInterval $value): Duration
    {
        $seconds = ($value->days !== false ? $value->days * 86400 : 0)
            + ($value->h * 3600)
            + ($value->i * 60)
            + $value->s;

        $duration = new Duration();
        $duration->setSeconds($value->invert === 1 ? -$seconds : $seconds);
        return $duration;
    }

    public static function parseDateTime(string $name, DateTimeImmutable $fallback, bool $endOfDay): DateTimeImmutable
    {
        $raw = self::optional($name);
        if ($raw === '') {
            return $fallback->setTimezone(new DateTimeZone('UTC'));
        }

        try {
            if (str_contains($raw, 'T')) {
                return new DateTimeImmutable($raw, new DateTimeZone('UTC'));
            }
            $value = new DateTimeImmutable($raw, new DateTimeZone('UTC'));
            if ($endOfDay) {
                return $value->setTime(23, 59, 59);
            }
            return $value->setTime(0, 0, 0);
        } catch (Throwable $exception) {
            self::usage(sprintf('%s debe ser RFC3339 o YYYY-MM-DD: %s', $name, $exception->getMessage()));
        }
    }

    public static function parseDuration(string $raw): DateInterval
    {
        if (str_ends_with($raw, 'ms')) {
            $seconds = (float) substr($raw, 0, -2) / 1000;
            return new DateInterval(sprintf('PT%dS', (int) ceil($seconds)));
        }
        if (str_ends_with($raw, 's')) {
            return new DateInterval(sprintf('PT%dS', (int) substr($raw, 0, -1)));
        }
        if (str_ends_with($raw, 'm')) {
            return new DateInterval(sprintf('PT%dM', (int) substr($raw, 0, -1)));
        }
        if (str_ends_with($raw, 'h')) {
            return new DateInterval(sprintf('PT%dH', (int) substr($raw, 0, -1)));
        }
        self::usage(sprintf('SAT_POLL_INTERVAL debe ser un duration válido: %s', $raw));
    }

    public static function parseDownloadType(string $value): int
    {
        return match (strtolower(trim($value))) {
            'recibidos' => DownloadType::DOWNLOAD_TYPE_RECIBIDOS,
            'emitidos' => DownloadType::DOWNLOAD_TYPE_EMITIDOS,
            default => self::usage('SAT_TIPO_DESCARGA debe ser recibidos o emitidos'),
        };
    }

    public static function parseQueryType(string $value): int
    {
        return match (strtolower(trim($value))) {
            'cfdi' => QueryType::QUERY_TYPE_CFDI,
            'metadata' => QueryType::QUERY_TYPE_METADATA,
            default => self::usage('SAT_TIPO_SOLICITUD debe ser CFDI o Metadata'),
        };
    }

    public static function parseInvoiceStatus(string $value): ?int
    {
        $normalized = strtolower(trim($value));
        return match ($normalized) {
            '' => null,
            'todos', 'all' => InvoiceStatus::INVOICE_STATUS_ALL,
            'vigente' => InvoiceStatus::INVOICE_STATUS_VIGENTE,
            'cancelado' => InvoiceStatus::INVOICE_STATUS_CANCELADO,
            default => self::usage('SAT_ESTADO_COMPROBANTE debe ser todos, vigente o cancelado'),
        };
    }

    public static function applyCredentials(object $message, $credentials, $credentialRef): object
    {
        if ($credentials !== null && method_exists($message, 'setCredentials')) {
            $message->setCredentials($credentials);
        }
        if ($credentialRef !== null && method_exists($message, 'setCredentialRef')) {
            $message->setCredentialRef($credentialRef);
        }
        return $message;
    }

    public static function readFile(string $path): string
    {
        $contents = file_get_contents($path);
        if ($contents === false) {
            self::fail(sprintf('no se pudo leer %s', $path));
        }
        return $contents;
    }
}
