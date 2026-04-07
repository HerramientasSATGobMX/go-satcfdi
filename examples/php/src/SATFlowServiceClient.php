<?php

declare(strict_types=1);

namespace SatcfdiExamples;

use Grpc\BaseStub;
use Satcfdi\V1\RunDownloadFlowRequest;
use Satcfdi\V1\RunDownloadFlowResponse;

final class SATFlowServiceClient extends BaseStub
{
    public function __construct(string $hostname, array $opts, $channel = null)
    {
        parent::__construct($hostname, $opts, $channel);
    }

    public function RunDownloadFlow(RunDownloadFlowRequest $argument, array $metadata = [], array $options = [])
    {
        return $this->_simpleRequest(
            '/satcfdi.v1.SATFlowService/RunDownloadFlow',
            $argument,
            [RunDownloadFlowResponse::class, 'decode'],
            $metadata,
            $options
        );
    }
}

