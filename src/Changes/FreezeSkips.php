<?php

declare(strict_types=1);

namespace Keyring\Changes;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Factor;
use Keyring\Enums\Purpose;
use Keyring\Events\FactorFailed;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Pipeline\Context;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;
use Keyring\Support\Input;
use Keyring\Support\Throttle;
use Keyring\WebAuthn\SpentChallenges;
use Throwable;

/**
 * Making one change while the account is frozen, for an owner who proves
 * a sign-in method the account has had for "established_after", and since
 * before this session signed in. A passkey or security key, or an
 * authenticator app where "skip_with_totp" allows it. Never recovery codes,
 * an emailed code or the password: whoever holds the session may have
 * those.
 *
 * The proof comes in the request that makes the change, as "proof", and
 * only counts for that change. A key signs a challenge issued for that
 * change alone ("remove" an authenticator, or "replace" a factor's), kept
 * in this session with the account it's for. Nothing about it is
 * remembered for the session afterwards, so a copy of the session, however
 * recently it was verified, can't make a change the owner didn't sign.
 */
class FreezeSkips
{
    /** Where a key's challenge waits, one per factor. */
    public const string OPTIONS = 'keyring.freeze_skip';

    /** The changes a proof can be for. */
    public const array ACTIONS = ['remove', 'replace'];

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected Throttle $throttle,
    ) {}

    /**
     * The factors that could prove a change in this session, by key: what
     * a refusal tells the client it can try. Empty when none can.
     *
     * @return list<string>
     */
    public function factors(Authenticatable&Model $user, Request $request): array
    {
        return array_values($this->provers($user, $request)->pluck('factor')->unique()->all());
    }

    /**
     * A challenge for one of the user's keys of this factor to sign, good
     * for this one change. It's kept in the session until it's answered,
     * for as long as a usernameless sign in's would be.
     *
     * @return array<string, mixed>
     *
     * @throws ValidationException
     */
    public function options(Authenticatable&Model $user, Request $request, string $factor, string $action, string $target): array
    {
        $webauthn = $this->keyring->hasFactor($factor) ? $this->keyring->factor($factor) : null;

        abort_unless($webauthn instanceof WebAuthn, 404);

        $keys = $this->provers($user, $request)->where('factor', $factor);

        if ($keys->isEmpty()) {
            throw ValidationException::withMessages(['proof' => __('keyring::keyring.freeze_proof_not_established')]);
        }

        ['browser' => $browser, 'kept' => $kept] = $webauthn->requestOptionsFor($keys);

        $request->session()->put(static::OPTIONS.'.'.$factor, [
            'options' => $kept,
            'change' => $this->change($action, $target),
            'user' => $this->owner($user),
            'expires_at' => now()->getTimestamp() + $this->lifetime(),
        ]);

        return $browser;
    }

    /**
     * Whether the request proves an established sign-in method for this
     * change. False when it has no "proof". One that doesn't hold is an
     * error on "proof": a key's answer to a challenge issued for anything
     * else, or answered before, a wrong code, or a method that's too new.
     *
     * A key's challenge is used up by the first answer, right or wrong, and
     * a code works once, as they do everywhere else. Each try counts
     * against the factor's rate limits, as a step-up's would.
     *
     * @throws ValidationException
     */
    public function proves(Authenticatable&Model $user, Request $request, string $action, string $target): bool
    {
        if (Input::get($request, 'proof') === null) {
            return false;
        }

        Input::validate($request, [
            'proof' => ['array'],
            'proof.factor' => ['required', 'string', 'max:64'],
            'proof.code' => ['sometimes', 'string', 'max:64'],
        ]);

        /** @var array{factor: string, credential?: mixed, code?: string} $proof */
        $proof = Input::get($request, 'proof');

        $keys = $this->provers($user, $request)->where('factor', $proof['factor']);
        $factor = $keys->first()?->factor();

        // A key's challenge is spent whatever happens next.
        $issued = $this->pullOptions($request, $proof['factor']);

        if ($factor === null) {
            throw ValidationException::withMessages(['proof' => __('keyring::keyring.freeze_proof_not_established')]);
        }

        $attempt = $this->attempt($user, $factor, $issued, $this->change($action, $target));

        if ($attempt === null) {
            throw $this->invalid();
        }

        return $this->verify($request, $attempt, $factor, $keys, $proof);
    }

    /**
     * Check the proof against the factor, under its rate limits.
     *
     * @param  Collection<int, Authenticator>  $keys
     * @param  array{factor: string, credential?: mixed, code?: string}  $proof
     *
     * @throws ValidationException
     */
    protected function verify(Request $request, Attempt $attempt, Factor $factor, Collection $keys, array $proof): bool
    {
        $authenticator = $keys->firstOrFail();
        $limits = $this->throttle->aim($factor->limits($request, $attempt), new Context($request, Purpose::Confirm, $factor, $attempt, $authenticator));

        if (($refusing = $this->throttle->hit($limits)) !== null) {
            throw Throttle::exception('proof', $this->throttle->retryAfter($refusing) ?? 0);
        }

        try {
            // The factor reads its answer where it always does.
            $verification = $factor->verify($attempt, $authenticator, Request::create('/', 'POST', array_intersect_key($proof, array_flip(['credential', 'code']))));
        } catch (Throwable $e) {
            $this->throttle->release($limits);

            throw $e;
        }

        // A key's answer only counts from one of these, never a newer key.
        $used = $verification === null ? null : $keys->firstWhere('id', $verification->authenticator);

        if ($used === null) {
            $this->throttle->failed($limits);
            FactorFailed::dispatch($attempt, $authenticator, $factor->key(), $request);

            throw $this->invalid();
        }

        $this->throttle->succeeded($limits);
        $used->markAsUsed();

        return true;
    }

    /**
     * An attempt for the factor to verify against, with the key's challenge
     * when the factor has one. Null when a key's challenge is missing, has
     * expired, or was issued for another account or another change.
     *
     * @param  array<string, mixed>|null  $issued
     */
    protected function attempt(Authenticatable&Model $user, Factor $factor, ?array $issued, string $change): ?Attempt
    {
        if (! $factor instanceof WebAuthn) {
            return Attempt::start(Purpose::Confirm, $user);
        }

        if ($issued === null) {
            return null;
        }

        // Used up here, so an answer to a challenge for another change can't
        // be sent again with the change it was for, from another copy of
        // the session.
        if ($issued['change'] !== $change || $issued['user'] !== $this->owner($user)) {
            app(SpentChallenges::class)->spend($issued['options'], $issued['expires_at']);

            return null;
        }

        $attempt = new Attempt(Str::random(40), Purpose::Confirm, config('keyring.guard'), $user->getAuthIdentifier(), $issued['expires_at']);
        $attempt->put($factor->key(), 'options', $issued['options']);

        return $attempt;
    }

    /**
     * Take the factor's challenge out of the session, if it's still good.
     *
     * @return array{options: string, change: string, user: string, expires_at: int}|null
     */
    protected function pullOptions(Request $request, string $factor): ?array
    {
        $issued = $request->session()->pull(static::OPTIONS.'.'.$factor);

        if (! is_array($issued) || ! is_string($issued['options'] ?? null) || ! is_int($issued['expires_at'] ?? null) || $issued['expires_at'] < now()->getTimestamp()) {
            return null;
        }

        return [
            'options' => $issued['options'],
            'change' => (string) ($issued['change'] ?? ''),
            'user' => (string) ($issued['user'] ?? ''),
            'expires_at' => $issued['expires_at'],
        ];
    }

    /**
     * The authenticators that can prove a change in this session: of a
     * factor that may, added at least "established_after" ago and before
     * this session signed in. None when there's no record of when it did.
     *
     * @return Collection<int, Authenticator>
     */
    protected function provers(Authenticatable&Model $user, Request $request): Collection
    {
        $signedInAt = $this->sessions->current($request)?->authenticatedAt;

        if ($signedInAt === null) {
            return new Collection;
        }

        $before = min($signedInAt, Duration::ago(config('keyring.authenticator_changes.established_after'))->getTimestamp());

        return $this->keyring->for($user)->all()
            ->filter(fn (Authenticator $authenticator) => ! $authenticator->isVirtual()
                && $authenticator->created_at !== null
                && $authenticator->created_at->getTimestamp() < $before
                && $this->mayProve($authenticator->factor()))
            ->values();
    }

    /**
     * Whether the factor can prove a change: one bound to this site, or a
     * code from an app where the app allows it. A six digit code can be
     * phished as it's typed, so that's off unless "skip_with_totp" says.
     */
    protected function mayProve(Factor $factor): bool
    {
        return $factor instanceof WebAuthn
            || ($factor instanceof Totp && (bool) config('keyring.authenticator_changes.skip_with_totp'));
    }

    /**
     * Seconds a challenge can be answered for: as long as a usernameless
     * sign in's, and never shorter than the browser is told to wait.
     */
    protected function lifetime(): int
    {
        return max(
            Duration::seconds(config('keyring.webauthn.login_options_for')),
            (int) ceil(Duration::milliseconds(config('keyring.webauthn.timeout')) / 1000),
        );
    }

    protected function change(string $action, string $target): string
    {
        return $action.':'.$target;
    }

    protected function owner(Authenticatable&Model $user): string
    {
        return $user->getMorphClass().':'.$user->getAuthIdentifier();
    }

    protected function invalid(): ValidationException
    {
        return ValidationException::withMessages(['proof' => __('keyring::keyring.freeze_proof_invalid')]);
    }
}
