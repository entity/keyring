<?php

declare(strict_types=1);

namespace Keyring\WebAuthn;

use Keyring\Contracts\TrustsAuthenticators;
use LogicException;

/**
 * Trusts the root certificates in keyring.webauthn.attestation_roots, for
 * every model: each entry is a PEM certificate, or the path to a file of them.
 */
class ConfiguredRoots implements TrustsAuthenticators
{
    public function roots(string $aaguid): array
    {
        $roots = array_merge(...array_map($this->certificates(...), array_values((array) config('keyring.webauthn.attestation_roots'))));

        // Nothing to chain to would refuse every key without saying why.
        throw_if($roots === [], LogicException::class, 'Keyring has no root certificate to check attestation against. List PEM certificates, or paths to PEM files, in keyring.webauthn.attestation_roots, or bind your own Keyring\Contracts\TrustsAuthenticators.');

        return $roots;
    }

    /**
     * Every certificate in an entry. One that has none is a mistake worth
     * hearing about, not a root to skip.
     *
     * @return list<string>
     */
    protected function certificates(string $root): array
    {
        $pem = match (true) {
            str_contains($root, '-----BEGIN') => $root,
            is_file($root) => (string) file_get_contents($root),
            default => throw new LogicException("The attestation root [{$root}] is neither a PEM certificate nor a file."),
        };

        preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $pem, $certificates);

        throw_if($certificates[0] === [], LogicException::class, "The attestation root [{$root}] holds no PEM certificate.");

        return $certificates[0];
    }
}
