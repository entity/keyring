<?php

namespace Keyring\Testing;

use Illuminate\Support\Facades\File;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use RuntimeException;

/**
 * A maker of security keys for tests: a throwaway root certificate, and keys
 * whose attestation chains to it, so a factor that requires attestation can
 * be exercised without hardware.
 *
 *     $maker = new VirtualManufacturer;
 *     config(['keyring.webauthn.attestation_roots' => [$maker->root]]);
 *
 *     $key = $maker->key('2fc0579f-8113-47ea-b116-bb5a8db9202a');
 */
class VirtualManufacturer
{
    /**
     * The root certificate to trust, PEM encoded.
     */
    public readonly string $root;

    /**
     * The certificate that signs each model's, and its key.
     */
    protected OpenSSLCertificate $issuer;

    protected OpenSSLAsymmetricKey $key;

    /**
     * What comes between a model's certificate and the root, DER encoded.
     *
     * @var list<string>
     */
    protected array $intermediates = [];

    public function __construct(
        // Sign the models' certificates with an intermediate, not the root itself.
        bool $intermediate = false,
        // How long its certificates last.
        protected int $days = 3650,
    ) {
        $this->key = $this->newKey();
        $this->issuer = $this->issue('Virtual Root', $this->key, null, $this->key, "basicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign");
        $this->root = $this->pem($this->issuer);

        if ($intermediate) {
            $key = $this->newKey();
            $this->issuer = $this->issue('Virtual Intermediate', $key, $this->issuer, $this->key, "basicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign");
            $this->key = $key;
            $this->intermediates = [$this->der($this->issuer)];
        }
    }

    /**
     * One of its keys, of the model with this AAGUID, attesting as "packed"
     * or "fido-u2f".
     */
    public function key(string $aaguid = '00000000-0000-0000-0000-000000000000', string $format = 'packed', bool $userVerification = true): VirtualAuthenticator
    {
        $aaguid = hex2bin(str_replace('-', '', $aaguid)) ?: throw new RuntimeException('An AAGUID is a UUID.');

        return new VirtualAuthenticator(userVerification: $userVerification, aaguid: $aaguid)->attestedBy($this, $format);
    }

    /**
     * An attestation certificate for a model, given as the raw bytes of its
     * AAGUID: the key that signs with it, and the certificates a key sends,
     * DER encoded, its own first.
     *
     * @return array{key: OpenSSLAsymmetricKey, certificates: list<string>}
     */
    public function certify(string $aaguid): array
    {
        $key = $this->newKey();

        // A model with an AAGUID names it in the certificate too.
        $certificate = $this->issue('Virtual Key', $key, $this->issuer, $this->key, 'basicConstraints = critical, CA:FALSE'.(
            trim($aaguid, "\0") === '' ? '' : "\n1.3.6.1.4.1.45724.1.1.4 = DER:0410".bin2hex($aaguid)
        ));

        return ['key' => $key, 'certificates' => [$this->der($certificate), ...$this->intermediates]];
    }

    /**
     * A certificate for the key, signed by the issuer's (or its own, for a root).
     */
    protected function issue(string $name, OpenSSLAsymmetricKey $key, ?OpenSSLCertificate $issuer, OpenSSLAsymmetricKey $issuerKey, string $extensions): OpenSSLCertificate
    {
        // OpenSSL only takes extensions from a configuration file.
        $config = tempnam(sys_get_temp_dir(), 'keyring') ?: throw new RuntimeException('Could not write a temporary file.');
        file_put_contents($config, "[req]\ndistinguished_name = dn\n[dn]\n[extensions]\n{$extensions}\n");

        try {
            $options = ['config' => $config, 'digest_alg' => 'sha256', 'x509_extensions' => 'extensions'];

            // The subject a "packed" attestation certificate has to have.
            $request = openssl_csr_new([
                'countryName' => 'US',
                'organizationName' => 'Keyring',
                'organizationalUnitName' => 'Authenticator Attestation',
                'commonName' => $name,
            ], $key, $options);

            $certificate = $request instanceof \OpenSSLCertificateSigningRequest
                ? openssl_csr_sign($request, $issuer, $issuerKey, $this->days, $options, random_int(1, PHP_INT_MAX))
                : false;

            return $certificate ?: throw new RuntimeException('OpenSSL could not make a certificate: '.openssl_error_string());
        } finally {
            File::delete($config);
        }
    }

    protected function newKey(): OpenSSLAsymmetricKey
    {
        return openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC])
            ?: throw new RuntimeException('OpenSSL could not make a P-256 key pair.');
    }

    protected function pem(OpenSSLCertificate $certificate): string
    {
        openssl_x509_export($certificate, $pem);

        return $pem;
    }

    protected function der(OpenSSLCertificate $certificate): string
    {
        return base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $this->pem($certificate)));
    }
}
