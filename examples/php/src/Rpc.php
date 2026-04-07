<?php

declare(strict_types=1);

namespace SatcfdiExamples;

final class Rpc
{
    public static function unary($call)
    {
        [$response, $status] = $call->wait();
        if ($status->code !== \Grpc\STATUS_OK) {
            Common::fail(sprintf('%s: %s', $status->code, $status->details));
        }
        return $response;
    }
}
