<?php

namespace Keyring\Changes;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Expression;
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
 * Changing the email address:
 *
 *  1. The user re-verifies (handled by middleware) and asks for a new address.
 *  2. The new address gets a confirmation link. The current address gets a
 *     notice with a "this wasn't me" link, and must confirm too unless this
 *     session proved a second factor.
 *  3. Once confirmed, the change applies, and can still be reverted from the
 *     old address for a while. Meanwhile nobody else can take the old
 *     address. Reverting signs everything out, closes any later changes, and
 *     removes sign-in methods added since the session that asked signed in.
 *
 * Nothing reveals whether the new address belongs to another account.
 */
class EmailChanges
{
    public function __construct(
        protected KeyringManager $keyring,
        protected ProtectedAttributes $protection,
        protected Sessions $sessions,
        protected SessionAssurance $assurance,
        protected ReservedAddresses $reserved,
    ) {}

    /**
     * A taken address is asked for like any other, so nothing the account can
     * see (the pending change, the notice to its current address) gives away
     * that it's taken. Only the email to the new address differs, and with no
     * confirmation link sent the change can never apply.
     */
    public function request(Authenticatable&Model $user, string $email, Request $request): ?PendingChange
    {
        $email = $this->keyring->normalizeUsername($email);
        $current = (string) $user->getAttribute($this->attribute());

        if ($email === $this->keyring->normalizeUsername($current)) {
            return null;
        }

        $taken = $this->taken($user, $email);
        $tokens = ['confirm' => Str::random(48), 'current' => Str::random(48), 'revert' => Str::random(48)];

        $signedInAt = $this->signedInAt($request);
        $needsCurrent = ! $this->sessionProvedEstablishedSecondFactor($user, $signedInAt);

        $change = $this->keyring->pendingChangeModel()::query()->getConnection()->transaction(function () use ($user, $email, $current, $tokens, $needsCurrent, $signedInAt) {
            $this->cancel($user);

            $model = $this->keyring->pendingChangeModel();
            $change = new $model([
                'attribute' => $this->attribute(),
                'value' => $email,
                'previous_value' => $current,
                'confirm_token' => PendingChange::hashToken($tokens['confirm']),
                'current_token' => $needsCurrent ? PendingChange::hashToken($tokens['current']) : null,
                'revert_token' => PendingChange::hashToken($tokens['revert']),
                'signed_in_at' => $signedInAt,
                'expires_at' => Duration::fromNow(config('keyring.email_changes.confirmable_for', '24h')),
            ]);
            $change->authenticatable()->associate($user);
            $change->save();

            return $change;
        });

        // After the response, so timing doesn't give away which case it was.
        defer(function () use ($change, $email, $current, $tokens, $needsCurrent, $taken) {
            Notification::route('mail', $email)->notify($taken
                ? app(EmailAddressInUse::class)
                : app(ConfirmEmailChange::class, ['change' => $change, 'token' => $tokens['confirm']]));

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
            $this->endOtherSessions($user);

            EmailChanged::dispatch($user, $change);
        }

        return $result;
    }

    /**
     * "This wasn't me": put the address back, close every later change, remove
     * sign-in methods added since the session that asked for the change signed
     * in, and sign out everywhere. The address goes back even when it was a
     * later change that moved it, since the link for an earlier, cancelled
     * one still works. Returns whether the link was good.
     */
    public function revert(PendingChange $change, string $token): bool
    {
        $reverted = RowLock::hold($change, function (?PendingChange $change) use ($token) {
            if ($change === null || ! $change->canRevert() || ! $change->matches('revert_token', $token)) {
                return false;
            }

            $user = $change->user();

            if ($user !== null && $this->movedAddress($user, $change)) {
                $this->protection->changing(fn () => $user->forceFill([$change->attribute => $change->previous_value])->save());
            }

            $change->forceFill(['reverted_at' => now()])->save();

            if ($user !== null) {
                $this->closeLaterChanges($user, $change);
                $this->removeAuthenticatorsAddedSince($user, $change->signed_in_at ?? $change->created_at);
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
     * account was recovered with a password reset. The emailed "this wasn't
     * me" link keeps working until the change would have expired: whoever
     * asked for the change can cancel it too, and that mustn't take the
     * owner's way to undo what they did.
     */
    public function cancel(Authenticatable&Model $user): void
    {
        $this->changesOf($user)->pending()->update([
            'cancelled_at' => now(),
            'revertable_until' => new Expression('expires_at'),
        ]);
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
     * and skip the check. Only this account's own factors count: a switched
     * or impersonated session may hold someone else's verifications.
     */
    protected function sessionProvedEstablishedSecondFactor(Authenticatable&Model $user, ?CarbonInterface $signedInAt): bool
    {
        if ($signedInAt === null) {
            return false;
        }

        $ids = collect($this->assurance->all())
            ->filter(fn (Verification $verification) => $verification->authenticator !== null
                && in_array(Category::Possession, $verification->categories, true))
            ->map(fn (Verification $verification) => $verification->authenticator);

        return $ids->isNotEmpty() && $this->keyring->authenticatorModel()::query()
            ->ownedBy($user)
            ->whereKey($ids->all())
            ->where('created_at', '<', $signedInAt)
            ->exists();
    }

    /**
     * When this session signed in, in the app's timezone like every stored
     * time it's compared with.
     */
    protected function signedInAt(Request $request): ?CarbonInterface
    {
        $signedInAt = $this->sessions->current($request)?->authenticatedAt;

        return $signedInAt === null ? null : now()->setTimestamp($signedInAt);
    }

    /**
     * Whoever else was signed in shouldn't keep the account once the address
     * has moved: other sessions end, unless the app opted out. The browser
     * that confirmed keeps its own, under a new ID, only if it's the account's.
     */
    protected function endOtherSessions(Authenticatable&Model $user): void
    {
        // The current request, not one captured at boot (Octane).
        $request = request();
        $here = $request->hasSession() && $this->signedInAs($user);

        if (config('keyring.email_changes.sign_out_others', true)) {
            $this->sessions->revokeAll($user, except: $here ? $this->sessions->current($request)?->id : null);
        }

        if ($here) {
            $this->sessions->rotate($request);
        }
    }

    protected function signedInAs(Authenticatable&Model $user): bool
    {
        $found = $this->keyring->guard()->user();

        return $found instanceof Model && $found->is($user);
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

            $this->protection->changing(fn () => $user->forceFill([
                $change->attribute => $change->value,
                ...(array_key_exists('email_verified_at', $user->getAttributes()) ? ['email_verified_at' => now()] : []),
            ])->save());

            $change->forceFill([
                'applied_at' => now(),
                'revertable_until' => Duration::fromNow(config('keyring.email_changes.revertable_for', '7d')),
            ])->save();

            $this->sessions->distrustDevices($user);

            return true;
        });
    }

    /**
     * Whether this change, or one asked for after it, moved the address and
     * hasn't been reverted.
     */
    protected function movedAddress(Authenticatable&Model $user, PendingChange $change): bool
    {
        return $this->changesOf($user)
            ->where($change->getKeyName(), '>=', $change->getKey()) // ULIDs sort by creation
            ->whereNotNull('applied_at')
            ->whereNull('reverted_at')
            ->exists();
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
        return $this->keyring->pendingChangeModel()::query()->ownedBy($user)->where('attribute', $this->attribute());
    }

    protected function attribute(): string
    {
        return $this->keyring->username();
    }
}
