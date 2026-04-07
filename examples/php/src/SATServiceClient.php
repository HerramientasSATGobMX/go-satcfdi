<?php

declare(strict_types=1);

namespace SatcfdiExamples;

use Grpc\BaseStub;
use Satcfdi\V1\AuthenticateRequest;
use Satcfdi\V1\AuthenticateResponse;
use Satcfdi\V1\ConsultDownloadRequest;
use Satcfdi\V1\ConsultDownloadResponse;
use Satcfdi\V1\StreamDownloadPackageRequest;
use Satcfdi\V1\StreamDownloadPackageResponse;
use Satcfdi\V1\ValidateCfdiRequest;
use Satcfdi\V1\ValidateCfdiResponse;
use Satcfdi\V1\VerifyDownloadRequest;
use Satcfdi\V1\VerifyDownloadResponse;

final class SATServiceClient extends BaseStub
{
    public function __construct(string $hostname, array $opts, $channel = null)
    {
        parent::__construct($hostname, $opts, $channel);
    }

    public function Authenticate(AuthenticateRequest $argument, array $metadata = [], array $options = [])
    {
        return $this->_simpleRequest(
            '/satcfdi.v1.SATService/Authenticate',
            $argument,
            [AuthenticateResponse::class, 'decode'],
            $metadata,
            $options
        );
    }

    public function ConsultDownload(ConsultDownloadRequest $argument, array $metadata = [], array $options = [])
    {
        return $this->_simpleRequest(
            '/satcfdi.v1.SATService/ConsultDownload',
            $argument,
            [ConsultDownloadResponse::class, 'decode'],
            $metadata,
            $options
        );
    }

    public function VerifyDownload(VerifyDownloadRequest $argument, array $metadata = [], array $options = [])
    {
        return $this->_simpleRequest(
            '/satcfdi.v1.SATService/VerifyDownload',
            $argument,
            [VerifyDownloadResponse::class, 'decode'],
            $metadata,
            $options
        );
    }

    public function StreamDownloadPackage(StreamDownloadPackageRequest $argument, array $metadata = [], array $options = [])
    {
        return $this->_serverStreamRequest(
            '/satcfdi.v1.SATService/StreamDownloadPackage',
            $argument,
            [StreamDownloadPackageResponse::class, 'decode'],
            $metadata,
            $options
        );
    }

    public function ValidateCfdi(ValidateCfdiRequest $argument, array $metadata = [], array $options = [])
    {
        return $this->_simpleRequest(
            '/satcfdi.v1.SATService/ValidateCfdi',
            $argument,
            [ValidateCfdiResponse::class, 'decode'],
            $metadata,
            $options
        );
    }
}

