<?php

namespace Keyring\Contracts;

/**
 * Says whose attestation to believe. Keyring's own reads the root
 * certificates listed in keyring.webauthn.attestation_roots; bind yours to
 * trust each model separately, from a FIDO Metadata Service blob you keep up
 * to date, say.
 */
interface TrustsAuthenticators
{
    /**
     * The root certificates a model's attestation may chain to, each one PEM
     * encoded (or the bare base64 a metadata statement lists). None when the
     * model isn't trusted, or no longer is.
     *
     * Keys that only speak U2F have no AAGUID and ask with all zeros.
     *
     * @return list<string>
     */
    public function roots(string $aaguid): array;
}
