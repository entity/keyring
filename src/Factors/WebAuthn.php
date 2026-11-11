<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\DiscoverableFactor;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enrollment\Enrollment;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Enums\Category;
use Keyring\Events\CloneSuspected;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\WebAuthn\Ceremonies;
use Keyring\WebAuthn\Profile;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Exception\CounterException;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * Passkeys and security keys: one driver, two profiles.
 *
 *     WebAuthn::passkeys()        // discoverable, user verified, can sign in alone
 *     WebAuthn::securityKeys()    // a second factor, user verification when the key does it
 *
 * Phishing resistant, because the browser binds every response to the origin.
 * Inherence is only counted when the authenticator verified the user this time.
 */
class WebAuthn extends Factor implements DiscoverableFactor, Enrollable, PrimaryFactor
{
    protected const string LOGIN_OPTIONS = 'keyring.webauthn.login';

    final public function __construct(
        protected Profile $profile,
    ) {}

    public static function passkeys(): static
    {
        return new static(Profile::passkeys());
    }

    public static function securityKeys(): static
    {
        return new static(Profile::securityKeys());
    }

    /**
     * Register the same profile under another key, e.g. for a second kind of key.
     */
    #[\NoDiscard]
    public function as(string $key): static
    {
        return clone ($this, ['profile' => $this->profile->as($key)]);
    }

    #[\NoDiscard]
    public function requireUserVerification(bool $required = true): static
    {
        return clone ($this, ['profile' => $this->profile->requireUserVerification($required)]);
    }

    /**
     * Only enroll keys whose attestation chains to a root the app trusts.
     */
    #[\NoDiscard]
    public function requireAttestation(bool $required = true): static
    {
        return clone ($this, ['profile' => $this->profile->requireAttestation($required)]);
    }

    /**
     * Only enroll these models, by AAGUID. It needs requireAttestation() too.
     *
     * @param  list<string>  $aaguids
     */
    #[\NoDiscard]
    public function allowOnly(array $aaguids): static
    {
        return clone ($this, ['profile' => $this->profile->allowOnly($aaguids)]);
    }

    public function key(): string
    {
        return $this->profile->key;
    }

    public function categories(Authenticator $authenticator): array
    {
        return $this->categoriesFor($this->profile->requiresUserVerification() || $authenticator->meta('user_verified'));
    }

    public function phishingResistant(Authenticator $authenticator): bool
    {
        return true;
    }

    /**
     * A passkey that syncs (iCloud Keychain, Google Password Manager...) can
     * leave the device, so it isn't. Unknown counts as synced.
     */
    public function deviceBound(Authenticator $authenticator): bool
    {
        return $authenticator->meta('backup_eligible') === false;
    }

    public function priority(): int
    {
        return $this->profile->priority;
    }

    public function rules(): array
    {
        return ['credential' => ['required']];
    }

    public function identificationRules(): array
    {
        return [];
    }

    public function errorKey(): string
    {
        return 'credential';
    }

    /**
     * Options for a usernameless sign in (including conditional UI autofill).
     */
    public function loginOptions(Request $request): array
    {
        $options = $this->ceremonies()->requestOptions([], AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED);

        $request->session()->put(static::LOGIN_OPTIONS.'.'.$this->key(), $this->ceremonies()->toJson($options));

        return $this->ceremonies()->toBrowser($options);
    }

    public function identify(Request $request): ?Authenticator
    {
        // Only this path may spend a usernameless challenge, and trying it
        // spends it even when no key matches.
        $request->attributes->set(static::LOGIN_OPTIONS, $request->session()->pull(static::LOGIN_OPTIONS.'.'.$this->key()));

        $id = $this->profile->primary ? $this->ceremonies()->credentialId($this->credential($request)) : null;

        if ($id === null) {
            return null;
        }

        $authenticator = Keyring::authenticatorModel()::query()
            ->where('factor', $this->key())
            ->where('credential_id', $id)
            ->confirmed()
            ->first();

        return $authenticator?->authenticatable instanceof Authenticatable ? $authenticator : null;
    }

    public function challenge(Attempt $attempt, Authenticator $authenticator): array
    {
        $options = $this->ceremonies()->requestOptions(
            array_values($attempt->keyring()->of($this->key())->map($this->descriptor(...))->all()),
            $this->profile->userVerification,
        );

        $attempt->put($this->key(), 'options', $this->ceremonies()->toJson($options));

        return ['options' => $this->ceremonies()->toBrowser($options)];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        // This attempt's own challenge, or the one identify() took. Spent here,
        // so a failure can't be retried.
        $options = $attempt->state($this->key(), 'options') ?? $request->attributes->get(static::LOGIN_OPTIONS);
        $attempt->forget($this->key());

        $credential = $this->credential($request);

        // The browser may answer with any of the user's keys, not just the one shown.
        $id = $this->ceremonies()->credentialId($credential);
        $actual = $authenticator->credential_id === $id
            ? $authenticator
            : $attempt->keyring()->of($this->key())->firstWhere('credential_id', $id);

        if (! is_string($options) || $actual === null) {
            return null;
        }

        $result = null;

        try {
            // Against the locked row, so parallel assertions can't both pass
            // one stored count and a slower write can't lower it.
            $this->consume($actual, function (Authenticator $locked) use (&$result, $credential, $options) {
                $record = $this->ceremonies()->record($locked->public_key);

                // Without a record there's nothing to check a signature against.
                $result = $record === null ? null : $this->ceremonies()->assert($credential, $options, $record);

                if ($result === null) {
                    return false;
                }

                // Whether the key may sync, and whether it has been backed up
                // yet, are reported again on every sign in.
                $locked->withMeta('backup_eligible', $result['backupEligible'])->withMeta('backed_up', $result['backedUp'])->forceFill([
                    'public_key' => $this->ceremonies()->toJson($result['record']),
                    'sign_count' => $result['record']->counter,
                ]);

                return true;
            });
        } catch (CounterException) {
            CloneSuspected::dispatch($actual);
        }

        if ($result === null) {
            return null;
        }

        return $this->verified(
            $actual,
            categories: $this->categoriesFor($result['userVerified']),
            deviceBound: ! $result['backupEligible'],
        );
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        $exclude = Keyring::authenticatorModel()::query()
            ->ownedBy($user)
            ->whereNotNull('credential_id')
            ->get()
            ->map($this->descriptor(...))
            ->all();

        $options = $this->ceremonies()->creationOptions($user, $this->profile, array_values($exclude));

        return Enrollment::make($this->key(), [
            'options' => $this->ceremonies()->toBrowser($options),
        ], [
            'options' => $this->ceremonies()->toJson($options),
        ]);
    }

    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        // A registration challenge is single use too, whether or not this works.
        app(EnrollmentStore::class)->forget($this->key());

        $record = $this->ceremonies()->register($this->credential($request), $enrollment->state('options'), $this->profile);

        if ($record === null) {
            // "Check it and try again" would send someone round in circles
            // with a key this factor will never take.
            throw_if($this->profile->attestation, ValidationException::withMessages([
                $this->errorKey() => __('keyring::keyring.key_not_accepted'),
            ]));

            return null;
        }

        $id = Base64UrlSafe::encodeUnpadded($record->publicKeyCredentialId);

        // Already registered (to anyone), or longer than the column allows.
        if (strlen($id) > 512 || Keyring::authenticatorModel()::query()->where('credential_id', $id)->exists()) {
            return null;
        }

        return $this->makeAuthenticator([
            'name' => $this->nameFrom($request, $this->defaultName()),
            'credential_id' => $id,
            'public_key' => $this->ceremonies()->toJson($record),
            'sign_count' => $record->counter,
            'aaguid' => $record->aaguid->toRfc4122(),
            // Only a type that was checked against the app's roots is kept.
            'attestation' => $this->profile->attestation ? $record->attestationType : null,
            'transports' => $record->transports,
            'meta' => [
                'user_verified' => (bool) $record->uvInitialized,
                'backup_eligible' => (bool) $record->backupEligible,
                'backed_up' => (bool) $record->backupStatus,
            ],
        ]);
    }

    public function startsLogin(): bool
    {
        return $this->profile->primary;
    }

    public function answersChallenges(): bool
    {
        return true;
    }

    protected function defaultName(): string
    {
        return $this->profile->primary ? __('Passkey') : __('Security key');
    }

    protected function descriptor(Authenticator $authenticator): PublicKeyCredentialDescriptor
    {
        return $this->ceremonies()->descriptor((string) $authenticator->credential_id, $authenticator->transports ?? []);
    }

    /**
     * The credential from the request, as the JSON the library expects.
     */
    protected function credential(Request $request): string
    {
        $credential = $request->input('credential');

        return is_string($credential) ? $credential : (string) json_encode($credential);
    }

    protected function ceremonies(): Ceremonies
    {
        return app(Ceremonies::class);
    }

    /**
     * A key only counts as inherence when it verified the user (PIN or
     * biometrics), not just their presence.
     *
     * @return list<Category>
     */
    protected function categoriesFor(bool $userVerified): array
    {
        return $userVerified ? [Category::Possession, Category::Inherence] : [Category::Possession];
    }
}
