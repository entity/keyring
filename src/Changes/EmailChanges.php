<?php

namespace Keyring\Changes;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Keyring\Enums\Category;
use Keyring\Enums\EmailConfirmation;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\EmailChanged;
use Keyring\Events\EmailChangeRequested;
use Keyring\Events\EmailChangeReverted;
use Keyring\KeyringManager;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Notifications\ConfirmEmailChange;
use Keyring\Notifications\EmailAddressInUse;
use Keyring\Notifications\EmailChangeNotice;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;
use Keyring\Support\RowLock;

use function Illuminate\Support\defer;

/**
 * Changing the email address the OWASP way:
 *
 *  1. The user re-verifies (handled by middleware) and asks for a new address.
 *  2. The new address gets a confirmation link. The current address gets a
 *     notice with a "this wasn't me" link, and must confirm too unless this
 *     session proved a second factor.
 *  3. Once confirmed, the change applies, and can still be reverted from the
 *     old address for a while. Meanwhile nobody else can take the old
 *     address. Reverting signs everything out, closes any later changes, and
 *     removes sign-in methods added since the request.
 *
 * Nothing reveals whether the new address belongs to another account.
 */
class EmailChanges
{
    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected SessionAssurance $assurance,
        protected ReservedAddresses $reserved,
    ) {}

    public function request(Authenticatable&Model $user, string $email, Request $request): ?PendingChange
    {
        $email = $this->keyring->normalizeUsername($email);
        $current = (string) $user->getAttribute($this->attribute());

        if ($email === $this->keyring->normalizeUsername($current)) {
            return null;
        }

        if ($this->taken($user, $email)) {
            // After the response, like the emails for a real change, so timing
            // doesn't give away that the address is taken.
            defer(fn () => Notification::route('mail', $email)->notify(app(EmailAddressInUse::class)));

            return null;
        }

        $tokens = ['confirm' => Str::random(48), 'current' => Str::random(48), 'revert' => Str::random(48)];

        $needsCurrent = ! $this->sessionProvedEstablishedSecondFactor($request);

        $change = PendingChange::query()->getConnection()->transaction(function () use ($user, $email, $current, $tokens, $needsCurrent) {
            $this->cancel($user);

            $change = new PendingChange([
                'attribute' => $this->attribute(),
                'value' => $email,
                'previous_value' => $current,
                'confirm_token' => PendingChange::hashToken($tokens['confirm']),
                'current_token' => $needsCurrent ? PendingChange::hashToken($tokens['current']) : null,
                'revert_token' => PendingChange::hashToken($tokens['revert']),
                'expires_at' => Duration::fromNow(config('keyring.email_changes.expire', '24h')),
            ]);
            $change->authenticatable()->associate($user);
            $change->save();

            return $change;
        });

        defer(function () use ($change, $email, $current, $tokens, $needsCurrent) {
            Notification::route('mail', $email)->notify(app(ConfirmEmailChange::class, ['change' => $change, 'token' => $tokens['confirm']]));

            Notification::route('mail', $current)->notify(app(EmailChangeNotice::class, [
                'change' => $change,
                'revertToken' => $tokens['revert'],
                'confirmToken' => $needsCurrent ? $tokens['current'] : null,
            ]));
        });

        EmailChangeRequested::dispatch($user, $change);

        return $change;
    }

    /**
     * Handle a confirmation from either address.
     */
    public function confirm(PendingChange $change, string $token): EmailConfirmation
    {
        $result = RowLock::hold($change, function (?PendingChange $change) use ($token) {
            if ($change === null || ! $change->isPending()) {
                return EmailConfirmation::Invalid;
            }

            if ($change->matches('confirm_token', $token)) {
                $change->confirmed_at ??= now();
            } elseif ($change->matches('current_token', $token)) {
                $change->current_confirmed_at ??= now();
            } else {
                return EmailConfirmation::Invalid;
            }

            $change->save();

            return match (true) {
                ! $change->isReady() => EmailConfirmation::NeedsOtherAddress,
                $this->apply($change) => EmailConfirmation::Applied,
                default => EmailConfirmation::Invalid,
            };
        });

        $change = $change->fresh();

        if ($result === EmailConfirmation::Applied && ($user = $change?->user())) {
            EmailChanged::dispatch($user, $change);
        }

        return $result;
    }

    /**
     * "This wasn't me": put the address back, close every later change, remove
     * sign-in methods added since the change was requested, and sign out
     * everywhere. Returns whether the link was good.
     */
    public function revert(PendingChange $change, string $token): bool
    {
        $reverted = RowLock::hold($change, function (?PendingChange $change) use ($token) {
            if ($change === null || ! $change->canRevert() || ! $change->matches('revert_token', $token)) {
                return false;
            }

            $user = $change->user();

            if ($change->applied_at !== null && $user !== null) {
                $this->keyring->changing(fn () => $user->forceFill([$change->attribute => $change->previous_value])->save());
            }

            $change->forceFill(['reverted_at' => now()])->save();

            if ($user !== null) {
                $this->closeLaterChanges($user, $change);
                $this->removeAuthenticatorsAddedSince($user, $change->created_at);
            }

            return true;
        });

        $change = $change->fresh();

        if ($reverted && ($user = $change?->user())) {
            $this->sessions->revokeAll($user);

            EmailChangeReverted::dispatch($user, $change);
        }

        return $reverted;
    }

    /**
     * Cancel every change still waiting for confirmation, e.g. after the
     * account was recovered with a password reset.
     */
    public function cancel(Authenticatable&Model $user): void
    {
        $this->changesOf($user)->pending()->update(['cancelled_at' => now()]);
    }

    public function pending(Authenticatable&Model $user): ?PendingChange
    {
        return $this->changesOf($user)->pending()->latest()->first();
    }

    /**
     * When the user's email last changed (or was changed back), for recovery
     * risk checks.
     */
    public function lastChangedAt(Authenticatable&Model $user): ?Carbon
    {
        $times = $this->changesOf($user)
            ->whereNotNull('applied_at')
            ->get(['applied_at', 'reverted_at'])
            ->flatMap(fn (PendingChange $change) => [$change->applied_at, $change->reverted_at])
            ->filter();

        return $times->isEmpty() ? null : Carbon::parse($times->max());
    }

    /**
     * Skip the current-address confirmation only when this session proved a
     * second factor that existed before it signed in. Factors added during
     * the session don't count, or a stolen session could add one, verify it,
     * and skip the check.
     */
    protected function sessionProvedEstablishedSecondFactor(Request $request): bool
    {
        $signedInAt = $this->sessions->current($request)?->authenticatedAt;

        if ($signedInAt === null) {
            return false;
        }

        $ids = collect($this->assurance->all())
            ->filter(fn (Verification $verification) => $verification->authenticator !== null
                && in_array(Category::Possession, $verification->categories, true))
            ->map(fn (Verification $verification) => $verification->authenticator);

        return $ids->isNotEmpty() && $this->keyring->authenticatorModel()::query()
            ->whereKey($ids->all())
            ->where('created_at', '<', Carbon::createFromTimestamp($signedInAt))
            ->exists();
    }

    /**
     * Apply inside the confirm transaction, only if the address is still the
     * one the change was requested from.
     */
    protected function apply(PendingChange $change): bool
    {
        $user = $change->user();

        return $user !== null && RowLock::hold($user, function (?Model $user) use ($change) {
            if (
                $user === null
                || $this->keyring->normalizeUsername((string) $user->getAttribute($change->attribute)) !== $this->keyring->normalizeUsername((string) $change->previous_value)
                || $this->taken($user, $change->value)
            ) {
                $change->forceFill(['cancelled_at' => now()])->save();

                return false;
            }

            $this->keyring->changing(fn () => $user->forceFill([
                $change->attribute => $change->value,
                ...(array_key_exists('email_verified_at', $user->getAttributes()) ? ['email_verified_at' => now()] : []),
            ])->save());

            $change->forceFill([
                'applied_at' => now(),
                'revertable_until' => Duration::fromNow(config('keyring.email_changes.revertable_for', '7d')),
            ])->save();

            return true;
        });
    }

    /**
     * Later changes were made by whoever had the account; their links must
     * not be able to move the address away again.
     */
    protected function closeLaterChanges(Authenticatable&Model $user, PendingChange $change): void
    {
        $this->changesOf($user)
            ->where($change->getKeyName(), '>', $change->getKey()) // ULIDs sort by creation
            ->whereNull('reverted_at')
            ->update(['cancelled_at' => now(), 'revertable_until' => now()]);
    }

    /**
     * One by one, so each removal is logged and announced.
     */
    protected function removeAuthenticatorsAddedSince(Authenticatable&Model $user, CarbonInterface $since): void
    {
        $this->keyring->authenticatorModel()::query()
            ->ownedBy($user)
            ->where('created_at', '>=', $since)
            ->get()
            ->each(function (Authenticator $authenticator) use ($user) {
                $authenticator->delete();
                AuthenticatorRemoved::dispatch($user, $authenticator);
            });
    }

    protected function taken(Authenticatable&Model $user, string $email): bool
    {
        return $user->newQuery()->where($this->attribute(), $email)->whereKeyNot($user->getKey())->exists()
            || $this->reserved->has($email, except: $user);
    }

    /**
     * @return Builder<PendingChange>
     */
    protected function changesOf(Authenticatable&Model $user): Builder
    {
        return PendingChange::query()->ownedBy($user)->where('attribute', $this->attribute());
    }

    protected function attribute(): string
    {
        return $this->keyring->username();
    }
}
