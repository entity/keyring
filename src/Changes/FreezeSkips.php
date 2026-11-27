<?php

declare(strict_types=1);

namespace Keyring\Changes;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Factor;
use Keyring\Enums\Purpose;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;
use Keyring\Support\FactorCheck;
use Keyring\Support\Input;

/**
 * Making one change while the account is frozen, for an owner who proves
 * a sign-in method the account has had for "established_after", and since
 * before this session signed in. A passkey or security key, a factor of
 * the app's own that's phishing resistant, or an authenticator app where
 * "skip_with_totp" allows it. Never recovery codes, an emailed code or the
 * password: whoever holds the session may have those.
 *
 * The proof comes in the request that makes the change, as "proof", and
 * only counts for that change. A key answers a challenge issued for that
 * change alone ("remove" an authenticator, "rename" one to a given name,
 * or "replace" a factor's), kept in this session with the account it's
 * for. Nothing about it is remembered for the session afterwards, so a
 * copy of the session, however recently it was verified, can't make a
 * change the owner didn't sign.
 *
 * A challenge is answered once, whichever copy of the session it comes
 * back in, and however many requests bring it at once: its first answer
 * claims it on the server, in the rate limiter's store, for every kind of
 * key, a factor of your own's included.
 */
class FreezeSkips
{
    /** Where a challenge waits, one per factor. */
    public const string OPTIONS = 'keyring.freeze_skip';

    /** The changes a proof can be for. */
    public const array ACTIONS = ['remove', 'replace', 'rename'];

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected FactorCheck $checks,
        protected CacheFactory $cache,
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
     * A challenge for one of the user's established authenticators of this
     * factor to answer, good for this one change: for a key, the options
     * its browser signs. It's kept in the session until it's answered, for
     * as long as a usernameless sign in's would be. A rename is to $name,
     * and only that name.
     *
     * @return array<string, mixed>
     *
     * @throws ValidationException
     */
    public function options(Authenticatable&Model $user, Request $request, string $factor, string $action, string $target, ?string $name = null): array
    {
        abort_unless($this->keyring->hasFactor($factor), 404);

        $keys = $this->provers($user, $request)->where('factor', $factor)->values();
        $proving = $keys->first()?->factor();

        if ($proving === null) {
            throw ValidationException::withMessages(['proof' => __('keyring::keyring.freeze_proof_not_established')]);
        }

        // Its ID is the challenge's, so a factor that remembers what it has
        // answered sees the same one when it comes back.
        $nonce = Str::random(40);
        $attempt = $this->attemptFor($user, $nonce, now()->getTimestamp() + $this->lifetime());

        // A key's browser may answer with any of these, never a newer key.
        if ($proving instanceof WebAuthn) {
            ['browser' => $browser, 'kept' => $kept] = $proving->requestOptionsFor($keys);
            $attempt->put($factor, 'options', $kept);
            $props = ['options' => $browser];
        } else {
            $props = $proving->challenge($attempt, $keys->firstOrFail());
        }

        $request->session()->put(static::OPTIONS.'.'.$factor, [
            'nonce' => $nonce,
            'state' => $attempt->state($factor),
            'change' => $this->change($action, $target, $name),
            'user' => $this->owner($user),
            'expires_at' => $attempt->expiresAt,
        ]);

        return $props;
    }

    /**
     * Whether the request proves an established sign-in method for this
     * change. False when it has no "proof". One that doesn't hold is an
     * error on "proof": an answer to a challenge issued for anything else,
     * or answered before, a wrong code, or a method that's too new.
     *
     * "proof.authenticator" picks which of the user's authenticators of the
     * factor to check, such as one of two authenticator apps. Without it, a
     * code is checked against the first, and a key's answer may come from
     * any of them.
     *
     * A challenge is used up by the first answer, right or wrong, in any
     * copy of the session, and a code works once, as they do everywhere
     * else. Each try counts against the factor's rate limits, as a
     * step-up's would. A rename is proved for $name, the name it gives.
     *
     * @throws ValidationException
     */
    public function proves(Authenticatable&Model $user, Request $request, string $action, string $target, ?string $name = null): bool
    {
        if (Input::get($request, 'proof') === null) {
            return false;
        }

        Input::validate($request, [
            'proof' => ['array'],
            'proof.factor' => ['required', 'string', 'max:64'],
            'proof.authenticator' => ['sometimes', 'string', 'max:255'],
            'proof.code' => ['sometimes', 'string', 'max:64'],
        ]);

        /** @var array{factor: string, authenticator?: string, credential?: mixed, code?: string} $proof */
        $proof = Input::get($request, 'proof');

        $keys = $this->provers($user, $request)->where('factor', $proof['factor']);

        if (isset($proof['authenticator'])) {
            $keys = $keys->where('id', $proof['authenticator']);
        }

        $keys = $keys->values();
        $factor = $keys->first()?->factor();

        // A challenge is spent whatever happens next.
        $issued = $this->pullOptions($request, $proof['factor']);

        if ($factor === null) {
            throw ValidationException::withMessages(['proof' => __('keyring::keyring.freeze_proof_not_established')]);
        }

        $attempt = $this->attempt($user, $factor, $keys->firstOrFail(), $issued, $this->change($action, $target, $name));

        if ($attempt === null) {
            throw $this->invalid();
        }

        $used = $this->checks->check($request, $attempt, $factor, $keys, Arr::except($proof, ['factor', 'authenticator']), 'proof');

        if ($used === null) {
            throw $this->invalid();
        }

        $used->markAsUsed();

        return true;
    }

    /**
     * An attempt for the factor to verify against, with the challenge it
     * was given. Null when an authenticator that answers challenges has
     * none: it's missing, has expired, or was issued for another account or
     * another change. A code from an app needs none.
     *
     * @param  array{nonce: string, state: array<string, mixed>, change: string, user: string, expires_at: int}|null  $issued
     */
    protected function attempt(Authenticatable&Model $user, Factor $factor, Authenticator $authenticator, ?array $issued, string $change): ?Attempt
    {
        if (! $factor->phishingResistant($authenticator)) {
            return Attempt::start(Purpose::Confirm, $user);
        }

        if ($issued === null || $issued['change'] !== $change || $issued['user'] !== $this->owner($user)) {
            return null;
        }

        $attempt = $this->attemptFor($user, $issued['nonce'], $issued['expires_at']);

        foreach ($issued['state'] as $key => $value) {
            $attempt->put($factor->key(), (string) $key, $value);
        }

        return $attempt;
    }

    protected function attemptFor(Authenticatable&Model $user, string $nonce, int $expiresAt): Attempt
    {
        return new Attempt($nonce, Purpose::Confirm, config('keyring.guard'), $user->getAuthIdentifier(), $expiresAt);
    }

    /**
     * Take the factor's challenge out of the session, and claim it, if it's
     * still good. Null when there's none, it has expired, or it was claimed
     * before: answered from another copy of the session, or by another
     * request at the same time. The claim is kept in the rate limiter's
     * store until the challenge would have expired, and add() writes only
     * when nothing is there, so of two requests that bring one challenge,
     * one finds it claimed.
     *
     * @return array{nonce: string, state: array<string, mixed>, change: string, user: string, expires_at: int}|null
     */
    protected function pullOptions(Request $request, string $factor): ?array
    {
        $issued = $request->session()->pull(static::OPTIONS.'.'.$factor);

        if (! is_array($issued) || ! is_string($issued['nonce'] ?? null) || ! is_array($issued['state'] ?? null)
            || ! is_int($issued['expires_at'] ?? null) || $issued['expires_at'] < now()->getTimestamp()) {
            return null;
        }

        $claimed = $this->cache->store(config('cache.limiter'))->add(
            'keyring:freeze-proof:'.sha1($issued['nonce']),
            true,
            max(1, $issued['expires_at'] - now()->getTimestamp()) + 1,
        );

        if (! $claimed) {
            return null;
        }

        return [
            'nonce' => $issued['nonce'],
            'state' => $issued['state'],
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
                && $this->mayProve($authenticator))
            ->values();
    }

    /**
     * Whether the authenticator can prove a change: one whose answers are
     * bound to this site, such as a passkey or security key, or one of a
     * factor of your own that says it's phishing resistant. The challenge
     * kept for this change alone is what binds its answer to it. A code
     * from an authenticator app can be phished as it's typed, so that's off
     * unless "skip_with_totp" says. No other code ever can.
     */
    protected function mayProve(Authenticator $authenticator): bool
    {
        $factor = $authenticator->factor();

        return $factor->phishingResistant($authenticator)
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

    /**
     * The change a challenge is for. A rename is bound to the name it
     * gives, so its proof can't give the key another.
     */
    protected function change(string $action, string $target, ?string $name = null): string
    {
        return $action.':'.$target.($name === null ? '' : ':'.hash('sha256', $name));
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
