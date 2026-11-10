<?php

namespace Keyring\WebAuthn;

use Cose\Algorithm\Algorithm;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\RSA\RS256;
use Illuminate\Container\Attributes\Singleton;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Keyring\KeyringManager;
use Keyring\Support\Duration;
use Keyring\Support\KeyedHash;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Uri\WhatWg\Url;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
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
            // No attestation: any authenticator is accepted, like Fortify.
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
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
     * Check a registration response. Returns null when it isn't valid.
     */
    public function register(string $credential, string $options): ?CredentialRecord
    {
        try {
            $credential = $this->fromJson($credential, PublicKeyCredential::class);
            $options = $this->fromJson($options, PublicKeyCredentialCreationOptions::class);

            if (! $credential->response instanceof AuthenticatorAttestationResponse) {
                return null;
            }

            return AuthenticatorAttestationResponseValidator::create($this->steps()->creationCeremony())
                ->check($credential->response, $options, $this->relyingPartyId());
        } catch (Throwable $e) {
            report_if(! $this->isRejection($e), $e);

            return null;
        }
    }

    /**
     * Check a login response against a stored credential. Returns the updated
     * record, whether the user was verified and whether the key may sync, or
     * null when it isn't valid.
     *
     * @return array{record: CredentialRecord, userVerified: bool, backupEligible: bool}|null
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
     */
    public function userHandle(Authenticatable&Model $user): string
    {
        $existing = $this->keyring->authenticatorModel()::query()->ownedBy($user)->whereNotNull('public_key')->oldest()->value('public_key');

        return $this->record($existing)->userHandle ?? KeyedHash::make('keyring|'.$user->getAuthIdentifier());
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
            ?? Url::parse(config('app.url'))?->getAsciiHost()
            ?? 'localhost';
    }

    public function relyingPartyName(): string
    {
        return config('keyring.webauthn.relying_party.name') ?? config('app.name');
    }

    /**
     * Origins allowed to complete ceremonies, normalised to scheme://host[:port].
     *
     * @return list<string>
     */
    public function origins(): array
    {
        $origins = config('keyring.webauthn.origins') ?: [config('app.url')];

        return array_map($this->origin(...), $origins) |> array_filter(...) |> array_values(...);
    }

    /**
     * A URL's origin, or null when it isn't a URL.
     */
    protected function origin(string $url): ?string
    {
        $url = Url::parse($url);

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
     * @return T
     */
    public function fromJson(string $json, string $class): object
    {
        return $this->serializer()->deserialize($json, $class, 'json');
    }

    /**
     * The signature algorithms keys may use, in order of preference. Only
     * these are offered to the browser, so every key it creates can be
     * checked.
     */
    public function algorithms(): Manager
    {
        return Manager::create()->add(...array_filter([
            ES256::create(),
            Ed25519::isSupported() ? Ed25519::create() : null,
            RS256::create(), // older Windows Hello
        ]));
    }

    protected function steps(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory;
        $factory->setAlgorithmManager($this->algorithms());
        $factory->setAllowedOrigins($this->origins());
        $factory->setAttestationStatementSupportManager($this->attestationSupport());

        return $factory;
    }

    protected function attestationSupport(): AttestationStatementSupportManager
    {
        return $this->attestation ??= tap(AttestationStatementSupportManager::create())->add(NoneAttestationStatementSupport::create());
    }

    protected function serializer(): SerializerInterface
    {
        return $this->serializer ??= new WebauthnSerializerFactory($this->attestationSupport())->create();
    }

    /**
     * Expected failures (bad signature, wrong origin, replayed counter) aren't
     * worth reporting. Anything else is a bug.
     */
    protected function isRejection(Throwable $e): bool
    {
        return $e instanceof WebauthnException
            || $e instanceof ExceptionInterface
            || $e instanceof \InvalidArgumentException
            || $e instanceof \JsonException;
    }
}
