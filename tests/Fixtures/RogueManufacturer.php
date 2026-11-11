<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Keyring\Testing\VirtualManufacturer;

/**
 * A maker whose keys are certified by one of its own keys' certificates
 * rather than by a certificate authority: what someone holding a genuine key
 * could put together.
 */
class RogueManufacturer extends VirtualManufacturer
{
    public function __construct()
    {
        parent::__construct();

        $genuine = $this->certify(str_repeat("\0", 16));

        $this->issuer = openssl_x509_read("-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($genuine['certificates'][0]), 64, "\n").'-----END CERTIFICATE-----')
            ?: throw new \RuntimeException('OpenSSL could not read the certificate.');
        $this->key = $genuine['key'];
        $this->intermediates = [$genuine['certificates'][0]];
    }
}
