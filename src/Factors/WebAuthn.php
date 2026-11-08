<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Contracts\DiscoverableFactor;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Category;
use Keyring\Events\CloneSuspected;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\WebAuthn\Ceremonies;
use Keyring\WebAuthn\Profile;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CredentialRecord;
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
    protected const LOGIN_OPTIONS = 'keyring.webauthn.login';

    public function __construct(
        protected Profile $profile,
    ) {}

    public static function passkeys(): self
    {
        return new self(Profile::passkeys());
    }

    public static function securityKeys(): self
    {
        return new self(Profile::securityKeys());
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

    public function key(): string
    {
        return $this->profile->key;
    }

    public function categories(Authenticator $authenticator): array
    {
        return $this->profile->requiresUserVerification() || $authenticator->meta('user_verified')
            ? [Category::Possession, Category::Inherence]
            : [Category::Possession];
    }

    public function phishingResistant(Authenticator $authenticator): bool
    {
        return true;
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

        $request->session()->put(self::LOGIN_OPTIONS.'.'.$this->key(), $this->ceremonies()->toJson($options));

        return $this->ceremonies()->toBrowser($options);
    }

    public function identify(Request $request): ?Authenticator
    {
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
            $attempt->keyring()->of($this->key())->map(fn (Authenticator $each) => $this->descriptor($each))->all(),
            $this->profile->userVerification,
        );

        $attempt->put($this->key(), 'options', $this->ceremonies()->toJson($options));

        return ['options' => $this->ceremonies()->toBrowser($options)];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $options = $attempt->state($this->key(), 'options')
            ?? $request->session()->pull(self::LOGIN_OPTIONS.'.'.$this->key());
        $credential = $this->credential($request);

        // The browser may answer with any of the user's keys, not just the one shown.
        $id = $this->ceremonies()->credentialId($credential);
        $actual = $authenticator->credential_id === $id
            ? $authenticator
            : $attempt->keyring()->of($this->key())->firstWhere('credential_id', $id);

        if (! is_string($options) || $actual === null) {
            return null;
        }

        try {
            $result = $this->ceremonies()->assert(
                $credential,
                $options,
                $this->ceremonies()->fromJson($actual->public_key, CredentialRecord::class),
            );
        } catch (CounterException) {
            CloneSuspected::dispatch($actual);

            $result = null;
        }

        $attempt->forget($this->key());

        if ($result === null) {
            return null;
        }

        $actual->forceFill([
            'public_key' => $this->ceremonies()->toJson($result['record']),
            'sign_count' => $result['record']->counter,
        ])->save();

        return $this->verified(
            $actual,
            categories: $result['userVerified'] ? [Category::Possession, Category::Inherence] : [Category::Possession],
        );
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        $exclude = Keyring::authenticatorModel()::query()
            ->whereMorphedTo('authenticatable', $user)
            ->whereNotNull('credential_id')
            ->get()
            ->map(fn (Authenticator $each) => $this->descriptor($each))
            ->all();

        $options = $this->ceremonies()->creationOptions($user, $this->profile, $exclude);

        return Enrollment::make($this->key(), [
            'options' => $this->ceremonies()->toBrowser($options),
        ], [
            'options' => $this->ceremonies()->toJson($options),
        ]);
    }

    public function enrollmentRules(): array
    {
        return ['credential' => ['required'], 'name' => ['nullable', 'string', 'max:64']];
    }

    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        $record = $this->ceremonies()->register($this->credential($request), $enrollment->state('options'));

        if ($record === null) {
            return null;
        }

        $id = $this->ceremonies()->credentialId($this->credential($request));

        // Already registered (to anyone), or longer than the column allows.
        if ($id === null || strlen($id) > 512 || Keyring::authenticatorModel()::query()->where('credential_id', $id)->exists()) {
            return null;
        }

        return $this->makeAuthenticator([
            'name' => $this->nameFrom($request, $this->defaultName()),
            'credential_id' => $id,
            'public_key' => $this->ceremonies()->toJson($record),
            'sign_count' => $record->counter,
            'aaguid' => $record->aaguid->toRfc4122(),
            'transports' => $record->transports,
            'meta' => [
                'user_verified' => (bool) $record->uvInitialized,
                'backup_eligible' => (bool) $record->backupEligible,
            ],
        ]);
    }

    public function startsLogin(): bool
    {
        return $this->profile->primary;
    }

    public function profile(): Profile
    {
        return $this->profile;
    }

    protected function defaultName(): string
    {
        return $this->profile->primary ? __('Passkey') : __('Security key');
    }

    protected function descriptor(Authenticator $authenticator): PublicKeyCredentialDescriptor
    {
        return $this->ceremonies()->descriptor($authenticator->credential_id, $authenticator->transports ?? []);
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
}
