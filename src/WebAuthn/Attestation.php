<?php

namespace Keyring\WebAuthn;

use Cose\Algorithms;
use Keyring\Contracts\TrustsAuthenticators;
use LogicException;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\Exception\CertificateChainException;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\StatusReportRepository;
use Webauthn\TrustPath\CertificateTrustPath;

/**
 * Decides whether an attestation shows who made a key: its certificates have
 * to chain to a root the app trusts for that model. Checking the statement's
 * own signature is left to the library.
 *
 * Nothing is fetched, so no certificate is looked up for revocation. An app
 * stops trusting a model by no longer returning its roots.
 *
 * The library can check a chain too, but only for some responses: it lets
 * through "none", self attestation and any key without an AAGUID. So Keyring
 * checks every response itself, and gives the library the same roots and the
 * same check for the ones it does look at.
 */
class Attestation implements CertificateChainValidator, MetadataStatementRepository, StatusReportRepository
{
    /**
     * The attestation types that come with certificates. "none" has nothing
     * to check, and a self attestation is signed by the key it describes.
     */
    protected const array CHAINED = [
        AttestationStatement::TYPE_BASIC,
        AttestationStatement::TYPE_ATTCA,
        AttestationStatement::TYPE_ANONCA,
    ];

    /**
     * More certificates than any maker's chain has. A response with more is
     * refused before any of them is read.
     */
    protected const int LONGEST_CHAIN = 6;

    /**
     * Whether the statement's certificates chain to a root trusted for the
     * model.
     */
    public function verifies(AttestationStatement $statement, Uuid $aaguid): bool
    {
        $path = $statement->trustPath;

        if (! in_array($statement->type, static::CHAINED, true) || ! $path instanceof CertificateTrustPath) {
            return false;
        }

        // A statement signed over SHA-1, which the library only warns about.
        if ($statement->has('alg') && is_numeric($alg = $statement->get('alg')) && (int) $alg === Algorithms::COSE_ALGORITHM_RS1) {
            return false;
        }

        try {
            $this->check($path->certificates, $this->roots($aaguid->toRfc4122()));
        } catch (CertificateChainException) {
            return false;
        }

        return true;
    }

    /**
     * @param  array<string>  $untrustedCertificates  the statement's, PEM encoded, the key's own first
     * @param  array<string>  $trustedCertificates  the roots, PEM encoded
     *
     * @throws CertificateChainException when they chain to none of the roots
     */
    public function check(array $untrustedCertificates, array $trustedCertificates): void
    {
        if ($untrustedCertificates === [] || count($untrustedCertificates) > static::LONGEST_CHAIN) {
            throw CertificateChainException::create($untrustedCertificates, $trustedCertificates);
        }

        try {
            $path = array_map($this->certificate(...), array_reverse(array_values($untrustedCertificates)));
        } catch (Throwable $e) {
            throw CertificateChainException::create($untrustedCertificates, $trustedCertificates, previous: $e);
        }

        if (! array_any($trustedCertificates, fn (string $root) => $this->chains($path, $this->root($root)))) {
            throw CertificateChainException::create($untrustedCertificates, $trustedCertificates);
        }
    }

    /**
     * What the library's own check asks for: the model's roots, as a
     * metadata statement that says nothing else about it.
     */
    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        $roots = $this->roots($aaguid);

        return $roots === [] ? null : MetadataStatement::create(
            description: 'Trusted by the app',
            authenticatorVersion: 0,
            protocolFamily: 'fido2',
            schema: 3,
            upv: [],
            authenticationAlgorithms: [],
            publicKeyAlgAndEncodings: [],
            attestationTypes: [],
            userVerificationDetails: null,
            matcherProtection: [],
            tcDisplay: [],
            attestationRootCertificates: $roots,
            aaguid: $aaguid,
        );
    }

    /**
     * Nothing to report: a model that's no longer trusted has no roots.
     */
    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        return [];
    }

    /**
     * The roots the app trusts for a model, PEM encoded.
     *
     * @return list<string>
     */
    protected function roots(string $aaguid): array
    {
        return array_map(
            fn (string $root) => CertificateToolbox::fixPEMStructure($root),
            app(TrustsAuthenticators::class)->roots($aaguid),
        );
    }

    /**
     * @param  non-empty-list<Certificate>  $path  from the one the root signed down to the key's own
     */
    protected function chains(array $path, Certificate $root): bool
    {
        // FIDO metadata lists some models' own attestation certificate as
        // the root. The statement still has to be signed with its key.
        if (count($path) === 1 && hash_equals($root->toDER(), $path[0]->toDER())) {
            return true;
        }

        try {
            CertificationPath::create(...$path)->validate($this->validation()->withTrustAnchor($root));
        } catch (PathValidationException) {
            return false;
        }

        return true;
    }

    /**
     * How a chain is checked: as of now on Laravel's clock, and without the
     * SHA-1 signatures and RSA keys under 2048 bits that the validator would
     * otherwise let through.
     */
    protected function validation(): PathValidationConfig
    {
        return PathValidationConfig::create(now()->toDateTimeImmutable(), static::LONGEST_CHAIN)
            ->withAllowedSignatureAlgorithms(...PathValidationConfig::HARDENED_ALLOWED_SIGNATURE_ALGORITHMS)
            ->withMinimumRSAKeySize(PathValidationConfig::HARDENED_MINIMUM_RSA_KEY_SIZE);
    }

    /**
     * A root that can't be read is a setting to fix, not a key to refuse.
     */
    protected function root(string $pem): Certificate
    {
        try {
            return $this->certificate($pem);
        } catch (Throwable $e) {
            throw new LogicException('Keyring could not read a root certificate to check attestation against. Each one has to be a single PEM encoded certificate.', $e->getCode(), previous: $e);
        }
    }

    protected function certificate(string $pem): Certificate
    {
        return Certificate::fromPEM(PEM::fromString($pem));
    }
}
