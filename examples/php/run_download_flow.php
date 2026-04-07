<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Satcfdi\V1\DownloadRequestStatus;
use SatcfdiExamples\Common;
use SatcfdiExamples\GrpcFactory;
use SatcfdiExamples\Rpc;
use SatcfdiExamples\SATFlowServiceClient;

[$target, $options] = GrpcFactory::channelOptions();
[$credentials, $credentialRef, $mode] = Common::credentialsSource();

$client = new SATFlowServiceClient($target, $options);
$response = Rpc::unary($client->RunDownloadFlow(Common::runFlowRequest($credentials, $credentialRef)));

Common::emit([
    'layer' => 'php',
    'operation' => 'run_download_flow',
    'service_target' => $target,
    'credential_source' => $mode,
    'request_id' => $response->getRequestId(),
    'submit_sat_status' => $response->getSubmitSatStatusCode(),
    'submit_sat_message' => $response->getSubmitSatMessage(),
    'verify_sat_status' => $response->getVerifySatStatusCode(),
    'request_status' => DownloadRequestStatus::name($response->getRequestStatus()),
    'request_status_code' => $response->getRequestStatusCode(),
    'raw_request_status' => $response->getRawRequestStatus(),
    'cfdi_count' => $response->getCfdiCount(),
    'verify_sat_message' => $response->getVerifySatMessage(),
    'package_ids' => iterator_to_array($response->getPackageIds()),
]);
