<?php

declare(strict_types=1);

namespace Keyring\WebAuthn;

use CBOR\Decoder;
use CBOR\Normalizable;
use CBOR\StringStream;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\Key;
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;
use Illuminate\Container\Attributes\Singleton;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Keyring\KeyringManager;
use Keyring\Support\Duration;
use Keyring\Support\KeyedHash;
use LogicException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Uri\WhatWg\Url;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\CounterException;
use Webauthn\Exception\WebauthnException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * The WebAuthn plumbing: building options, (de)serializing and validating
 * responses with web-auth/webauthn-lib. Factors stay free of library details.
 */
#[Singleton]
class Ceremonies
{
    /**
     * The shortest RSA key an app can settle for, in bits: what RFC 8812
     * (Section 2) asks of RS256, and the 112 bits of strength NIST SP
     * 800-63B-4 wants (Sec. 3.1.6.2).
     */
    public const int SHORTEST_RSA_KEY = 2048;

    protected ?SerializerInterface $serializer = null;

    protected ?AttestationStatementSupportManager $attestation = null;

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * @param  list<PublicKeyCredentialDescriptor>  $exclude
     */
    public function creationOptions(Authenticatable&Model $user, Profile $profile, array $exclude): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create($this->relyingPartyName(), $this->relyingPartyId()),
            user: PublicKeyCredentialUserEntity::create(
                name: (string) $user->getAttribute($this->keyring->username()),
                id: $this->userHandle($user),
                displayName: (string) ($user->getAttribute('name') ?? $user->getAttribute($this->keyring->username())),
            ),
            challenge: random_bytes(32),
            pubKeyCredParams: array_map(
                fn (Algorithm $algorithm) => PublicKeyCredentialParameters::createPk($algorithm::identifier()),
                [...$this->algorithms()->all()],
            ),
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                authenticatorAttachment: $profile->attachment,
                userVerification: $profile->userVerification,
                residentKey: $profile->residentKey,
            ),
            // No attestation unless the profile wants it: any authenticator
            // is accepted, like Fortify.
            attestation: $this->attests($profile)
                ? PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
                : PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $exclude,
            timeout: $this->timeout(),
        );
    }

    /**
     * @param  list<PublicKeyCredentialDescriptor>  $allow  empty for discoverable (usernameless) logins
     */
    public function requestOptions(array $allow, string $userVerification): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $this->relyingPartyId(),
            allowCredentials: $allow,
            userVerification: $userVerification,
            timeout: $this->timeout(),
        );
    }

    /**
     * How long the browser waits for the user, in milliseconds.
     *
     * @return int<1, max>
     */
    protected function timeout(): int
    {
        return max(1, Duration::milliseconds(config('keyring.webauthn.timeout')));
    }

    /**
     * @param  list<string>  $transports
     */
    public function descriptor(string $credentialId, array $transports = []): PublicKeyCredentialDescriptor
    {
        return PublicKeyCredentialDescriptor::create(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            Base64UrlSafe::decodeNoPadding($credentialId),
            $transports,
        );
    }

    /**
     * Check a registration response. Returns null when it isn't valid, or
     * when the profile wants attestation and the key's doesn't show it to be
     * a model the profile takes.
     */
    public function register(string $credential, string $options, Profile $profile): ?CredentialRecord
    {
        try {
            $attested = $this->attests($profile);

            $credential = $this->fromJson($credential, PublicKeyCredential::class, $attested);
            $options = $this->fromJson($options, PublicKeyCredentialCreationOptions::class);

            if (! $credential->response instanceof AuthenticatorAttestationResponse) {
                return null;
            }

            if ($attested && ! $this->vouchedFor($credential->response->attestationObject, $profile)) {
                return null;
            }

            if ($attested && $this->claimsMoreThanSigned($credential->response->attestationObject)) {
                return null;
            }

            $record = AuthenticatorAttestationResponseValidator::create($this->steps($attested)->creationCeremony())
                ->check($credential->response, $options, $this->relyingPartyId());

            return $this->canVerify($record) ? $record : null;
        } catch (Throwable $e) {
            report_if(! $this->isRejection($e), $e);

            return null;
        }
    }

    /**
     * Check a login response against a stored credential. Returns the updated
     * record, whether the user was verified, whether the key may sync and
     * whether it has been backed up, or null when it isn't valid.
     *
     * @return array{record: CredentialRecord, userVerified: bool, backupEligible: bool, backedUp: bool}|null
     *
     * @throws CounterException when the counter went backwards (a cloned key)
     */
    public function assert(string $credential, string $options, CredentialRecord $record): ?array
    {
        try {
            $credential = $this->fromJson($credential, PublicKeyCredential::class);
            $options = $this->fromJson($options, PublicKeyCredentialRequestOptions::class);

            if (! $credential->response instanceof AuthenticatorAssertionResponse) {
                return null;
            }

            $record = AuthenticatorAssertionResponseValidator::create($this->steps()->requestCeremony())
                ->check($record, $credential->response, $options, $this->relyingPartyId(), $record->userHandle);

            return [
                'record' => $record,
                'userVerified' => $credential->response->authenticatorData->isUserVerified(),
                'backupEligible' => $credential->response->authenticatorData->isBackupEligible(),
                'backedUp' => $credential->response->authenticatorData->isBackedUp(),
            ];
        } catch (CounterException $e) {
            throw $e;
        } catch (Throwable $e) {
            report_if(! $this->isRejection($e), $e);

            return null;
        }
    }

    /**
     * The credential ID a response is for, without validating anything.
     */
    public function credentialId(string $credential): ?string
    {
        return rescue(fn () => Base64UrlSafe::encodeUnpadded($this->fromJson($credential, PublicKeyCredential::class)->rawId), report: false);
    }

    /**
     * An opaque, stable handle for the user. Never their real ID or email.
     * Taken from a key they already have, so one added after APP_KEY was
     * rotated doesn't show up as another account in their password manager.
     *
     * Made from the model as well as the ID. An authenticator keeps one
     * passkey per handle for a site, so two kinds of account with the same
     * ID would otherwise replace each other's there.
     */
    public function userHandle(Authenticatable&Model $user): string
    {
        $existing = $this->keyring->authenticatorModel()::query()->ownedBy($user)->whereNotNull('public_key')->oldest()->value('public_key');

        return $this->record($existing)->userHandle ?? KeyedHash::make(KeyedHash::USER_HANDLES, $user->getMorphClass().':'.$user->getAuthIdentifier());
    }

    /**
     * A stored credential record, or null when there's none or it can't be
     * read: a row that came from somewhere that kept another format.
     */
    public function record(?string $json): ?CredentialRecord
    {
        try {
            return $json === null ? null : $this->fromJson($json, CredentialRecord::class);
        } catch (Throwable $e) {
            report_if(! $this->isRejection($e), $e);

            return null;
        }
    }

    public function relyingPartyId(): string
    {
        return config('keyring.webauthn.relying_party.id')
            ?? Url::parse(config('app.url') ?? '')?->getAsciiHost()
            ?? 'localhost';
    }

    public function relyingPartyName(): string
    {
        return config('keyring.webauthn.relying_party.name') ?? config('app.name');
    }

    /**
     * Origins allowed to complete ceremonies, normalised to scheme://host[:port].
     * Empty when none of them is a full URL, and then every ceremony is
     * refused.
     *
     * @return list<string>
     */
    public function origins(): array
    {
        $origins = config('keyring.webauthn.origins') ?: [config('app.url')];

        return array_map($this->origin(...), $origins) |> array_filter(...) |> array_values(...);
    }

    /**
     * A URL's origin, or null when it isn't a URL (an APP_URL left unset).
     */
    protected function origin(?string $url): ?string
    {
        $url = Url::parse($url ?? '');

        return $url === null ? null : $url->getScheme().'://'.$url->getAsciiHost().($url->getPort() ? ':'.$url->getPort() : '');
    }

    /**
     * @return array<string, mixed>
     */
    public function toBrowser(object $options): array
    {
        $serializer = $this->serializer();
        assert($serializer instanceof NormalizerInterface);

        /** @var array<string, mixed> $normalized */
        $normalized = $serializer->normalize($options, 'json', [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]);

        return $normalized;
    }

    public function toJson(object $value): string
    {
        return $this->serializer()->serialize($value, 'json');
    }

    /**
     * @template T of object
     *
     * @param  class-string<T>  $class
     * @param  bool  $attested  whether to read attestation other than "none" too
     * @return T
     */
    public function fromJson(string $json, string $class, bool $attested = false): object
    {
        return $this->serializer($attested)->deserialize($json, $class, 'json');
    }

    /**
     * The signature algorithms keys may use, in the app's order of
     * preference. Only these are offered to the browser, and a key that
     * signs with anything else is refused, when it's added and at sign in.
     *
     * RS256 is off unless the app lists it: OWASP ASVS doesn't approve its
     * padding (PKCS #1 v1.5), and the keys that need it are 2048 bit RSA,
     * short of the 128 bits of strength ASVS asks for.
     */
    public function algorithms(): Manager
    {
        $algorithms = array_filter(array_map(fn (mixed $name) => match ($name) {
            'ES256' => ES256::create(),
            'EdDSA' => Ed25519::isSupported() ? Ed25519::create() : null,
            'RS256' => RS256::create($this->rsaKeys()),
            default => throw new LogicException('Keyring only knows the WebAuthn algorithms ES256, EdDSA and RS256. Check keyring.webauthn.algorithms.'),
        }, $this->algorithmNames()));

        throw_if($algorithms === [], LogicException::class, 'Keyring has no algorithm to check WebAuthn signatures with. List at least one this server supports in keyring.webauthn.algorithms: EdDSA on its own needs PHP\'s sodium extension.');

        return Manager::create()->add(...$algorithms);
    }

    /**
     * The algorithms the app lists, as "webauthn.algorithms" names them.
     *
     * @return list<mixed>
     */
    public function algorithmNames(): array
    {
        return array_values(config('keyring.webauthn.algorithms') ?? ['ES256', 'EdDSA']);
    }

    /**
     * The algorithm a key signs with, as "webauthn.algorithms" would name
     * it, or its COSE number when it's none of those. Null when the key
     * can't be read.
     */
    public function algorithmOf(CredentialRecord $record): ?string
    {
        $algorithm = $this->coseKey($record)?->alg();

        return match ($algorithm) {
            null => null,
            ES256::ID => 'ES256',
            Ed25519::ID => 'EdDSA',
            RS256::ID => 'RS256',
            default => 'COSE algorithm '.$algorithm,
        };
    }

    /**
     * What an RS256 key has to be: "minimum_rsa_bits" long, and never under
     * 2048 bits. Given to the library outright, which then refuses a
     * shorter key itself. Left to its default it only raises a warning,
     * and the key passes wherever warnings aren't turned into exceptions.
     */
    protected function rsaKeys(): RsaKeyValidator
    {
        return RsaKeyValidator::create(max(static::SHORTEST_RSA_KEY, (int) config('keyring.webauthn.minimum_rsa_bits')));
    }

    /**
     * Whether signatures from a key could be checked: its algorithm is one
     * the app takes now, and an RSA key is long enough. The library only
     * looks at a key when it verifies with it, at sign in, so without this
     * a key could be added, or imported unremarked, that would never work.
     */
    public function canVerify(CredentialRecord $record): bool
    {
        $key = $this->coseKey($record);

        if ($key === null) {
            return false;
        }

        return $this->algorithms()->has($key->alg())
            && ($key->alg() !== RS256::ID || ($key instanceof RsaKey && $this->rsaKeys()->isValid($key)));
    }

    /**
     * A key's public half as the COSE key it's stored as, or null when it
     * can't be read as one that names its algorithm.
     */
    protected function coseKey(CredentialRecord $record): ?Key
    {
        try {
            $decoded = Decoder::create()->decode(StringStream::create($record->credentialPublicKey));
            $data = $decoded instanceof Normalizable ? $decoded->normalize() : null;
            $key = is_array($data) ? Key::create($data) : null;

            // The algorithm is asked for here, and an RSA key read as one,
            // so a key that can't answer is unreadable now and not later.
            return $key?->alg() === RS256::ID ? RsaKey::create($key->getData()) : $key;
        } catch (Throwable $e) {
            report_if(! $this->isRejection($e), $e);

            return null;
        }
    }

    /**
     * Whether a profile's keys have to show who made them.
     */
    protected function attests(Profile $profile): bool
    {
        // Without attestation an AAGUID is only what the key says about
        // itself, and the list would take anything that claims to be on it.
        throw_if($profile->aaguids !== null && ! $profile->attestation, LogicException::class, "Keyring can't limit the [{$profile->key}] factor to certain AAGUIDs without checking attestation: nothing vouches for the AAGUID a key reports. Add requireAttestation() to it.");

        return $profile->attestation;
    }

    /**
     * Whether the attestation shows the key to be a model the profile takes:
     * one of those it lists, if it lists any, with certificates that chain to
     * a root the app trusts for it.
     */
    protected function vouchedFor(AttestationObject $attestation, Profile $profile): bool
    {
        $aaguid = $attestation->authData->attestedCredentialData?->aaguid;

        return $aaguid !== null
            && ($profile->aaguids === null || in_array($aaguid->toRfc4122(), $profile->aaguids, true))
            && app(Attestation::class)->verifies($attestation->attStmt, $aaguid);
    }

    /**
     * Whether an attested registration says something about the key that its
     * statement doesn't sign. A "packed" statement signs all of the
     * authenticator data. A "fido-u2f" one signs the credential and leaves
     * out the flags: that the user was verified, that the key may sync, that
     * it has. A U2F key sets none of them, so one that arrives set was put
     * there on the way, and is what the key would be trusted for from then
     * on.
     */
    protected function claimsMoreThanSigned(AttestationObject $attestation): bool
    {
        $data = $attestation->authData;

        return $attestation->attStmt->fmt === 'fido-u2f'
            && ($data->isUserVerified() || $data->isBackupEligible() || $data->isBackedUp());
    }

    protected function steps(bool $attested = false): CeremonyStepManagerFactory
    {
        $origins = $this->origins();

        // The library takes an empty list as no list, and then accepts any
        // https origin on the relying party's host, whatever the port.
        throw_if($origins === [], LogicException::class, 'Keyring has no origin to check WebAuthn responses against. Set APP_URL to a full URL such as https://example.com, or list full URLs in keyring.webauthn.origins.');

        $factory = new CeremonyStepManagerFactory;
        $factory->setAlgorithmManager($this->algorithms());
        $factory->setAllowedOrigins($origins);
        $factory->setAttestationStatementSupportManager($this->attestationSupport($attested));

        if ($attested) {
            $trust = app(Attestation::class);
            $factory->enableMetadataStatementSupport($trust, $trust, $trust);
        }

        return $factory;
    }

    protected function attestationSupport(bool $attested = false): AttestationStatementSupportManager
    {
        // Made each time: the formats hold the algorithms the app takes now.
        if ($attested) {
            return AttestationStatementSupportManager::create($this->attestationFormats());
        }

        return $this->attestation ??= tap(AttestationStatementSupportManager::create())->add(NoneAttestationStatementSupport::create());
    }

    /**
     * The formats a key may attest in when a profile wants attestation, each
     * only taken when its certificates chain to a trusted root: "packed" from
     * FIDO2 keys and "fido-u2f" from older ones. Without that, "none" is the
     * only format read at all.
     *
     * @return list<AttestationStatementSupport>
     */
    protected function attestationFormats(): array
    {
        return [
            PackedAttestationStatementSupport::create($this->algorithms()),
            FidoU2FAttestationStatementSupport::create(),
        ];
    }

    protected function serializer(bool $attested = false): SerializerInterface
    {
        if ($attested) {
            return new WebauthnSerializerFactory($this->attestationSupport(true))->create();
        }

        return $this->serializer ??= new WebauthnSerializerFactory($this->attestationSupport())->create();
    }

    /**
     * Expected failures (bad signature, wrong origin, replayed counter) aren't
     * worth reporting. Anything else is a bug, or a setting that needs
     * fixing, and is reported while the ceremony is refused.
     */
    protected function isRejection(Throwable $e): bool
    {
        return $e instanceof WebauthnException
            || $e instanceof ExceptionInterface
            || $e instanceof \InvalidArgumentException
            || $e instanceof \JsonException;
    }
}
