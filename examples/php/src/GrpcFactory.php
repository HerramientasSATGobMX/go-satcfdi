<?php

declare(strict_types=1);

namespace SatcfdiExamples;

use Grpc\BaseStub;
use Grpc\ChannelCredentials;

final class GrpcFactory
{
    public static function channelOptions(): array
    {
        [$target, $mode] = Common::serviceTargetAndSecurity();
        $options = [];

        if ($mode === 'insecure') {
            $options['credentials'] = ChannelCredentials::createInsecure();
            return [$target, $options];
        }

        $rootCerts = null;
        if (($caFile = Common::optional('SAT_SERVICE_CA_FILE')) !== '') {
            $rootCerts = file_get_contents($caFile);
        }

        $certificateChain = null;
        $privateKey = null;
        $clientCert = Common::optional('SAT_SERVICE_CLIENT_CERT_FILE');
        $clientKey = Common::optional('SAT_SERVICE_CLIENT_KEY_FILE');
        if ($clientCert !== '' || $clientKey !== '') {
            if ($clientCert === '' || $clientKey === '') {
                Common::usage('SAT_SERVICE_CLIENT_CERT_FILE y SAT_SERVICE_CLIENT_KEY_FILE deben venir juntos');
            }
            $certificateChain = file_get_contents($clientCert);
            $privateKey = file_get_contents($clientKey);
        }

        $options['credentials'] = ChannelCredentials::createSsl($rootCerts, $privateKey, $certificateChain);
        if (Common::optional('SAT_SERVICE_INSECURE_SKIP_VERIFY') === '1') {
            $authority = parse_url(Common::env('SAT_SERVICE_URL', 'https://127.0.0.1:8443'), PHP_URL_HOST) ?: explode(':', $target)[0];
            $options['grpc.ssl_target_name_override'] = $authority;
            $options['grpc.default_authority'] = $authority;
        }

        return [$target, $options];
    }
}

