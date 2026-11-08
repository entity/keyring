<?php

namespace Keyring\Changes;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Category;
use Keyring\Events\EmailChanged;
use Keyring\Events\EmailChangeRequested;
use Keyring\Events\EmailChangeReverted;
use Keyring\KeyringManager;
use Keyring\Login\Verification;
use Keyring\Models\PendingChange;
use Keyring\Notifications\ConfirmEmailChange;
use Keyring\Notifications\EmailAddressInUse;
use Keyring\Notifications\EmailChangeNotice;
use Keyring\Session\SessionAssurance;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;

/**
 * Changing the email address the OWASP way:
 *
 *  1. The user re-verifies (handled by middleware) and asks for a new address.
 *  2. The new address gets a confirmation link. The current address gets a
 *     notice with a "this wasn't me" link, and must confirm too unless this
 *     session proved a second factor.
 *  3. Once confirmed, the change applies, and can still be reverted from the
 *     old address for a while. Reverting signs everything out, closes any
 *     later changes, and removes sign-in methods added since the request.
 *
 * Nothing reveals whether the new address belongs to another account.
 */
class EmailChanges
{
    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected DeviceManager $devices,
        protected SessionAssurance $assurance,
    ) {}

    public function request(Authenticatable&Model $user, string $email): ?PendingChange
    {
        $email = Str::lower(trim($email));
        $current = (string) $user->getAttribute($this->attribute());

        if ($email === Str::lower($current)) {
            return null;
        }

        if ($this->taken($user, $email)) {
            Notification::route('mail', $email)->notify(new EmailAddressInUse);

            return null;
        }

        $tokens = ['confirm' => Str::random(48), 'current' => Str::random(48), 'revert' => Str::random(48)];

        $needsCurrent = ! $this->sessionProvedEstablishedSecondFactor();

        $change = DB::transaction(function () use ($user, $email, $current, $tokens, $needsCurrent) {
            $this->cancel($user);

            $change = new PendingChange([
                'attribute' => $this->attribute(),
                'value' => $email,
                'previous_value' => $current,
                'confirm_token' => hash('sha256', $tokens['confirm']),
                'current_token' => $needsCurrent ? hash('sha256', $tokens['current']) : null,
                'revert_token' => hash('sha256', $tokens['revert']),
                'expires_at' => now()->addSeconds(Duration::seconds(config('keyring.email_changes.expire', '24h'))),
            ]);
            $change->authenticatable()->associate($user);
            $change->save();

            return $change;
        });

        Notification::route('mail', $email)->notify(new ConfirmEmailChange($change, $tokens['confirm']));
        Notification::route('mail', $current)->notify(
            new EmailChangeNotice($change, $tokens['revert'], $needsCurrent ? $tokens['current'] : null),
        );

        EmailChangeRequested::dispatch($user, $change);

        return $change;
    }

    /**
     * Handle a confirmation from either address. Returns whether the change
     * has now been applied.
     */
    public function confirm(PendingChange $change, string $token): bool
    {
        $hash = hash('sha256', $token);

        $applied = DB::transaction(function () use ($change, $hash) {
            $change = $this->lock($change);

            if ($change === null || ! $change->isPending()) {
                return false;
            }

            match (true) {
                hash_equals($change->confirm_token, $hash) => $change->confirmed_at ??= now(),
                $change->current_token !== null && hash_equals($change->current_token, $hash) => $change->current_confirmed_at ??= now(),
                default => null,
            };

            $change->save();

            return $change->isReady() && $this->apply($change);
        });

        if ($applied && ($user = $change->fresh()?->user())) {
            EmailChanged::dispatch($user, $change->fresh());
        }

        return $applied;
    }

    /**
     * "This wasn't me": put the address back, close every later change, remove
     * sign-in methods added since the change was requested, and sign out
     * everywhere.
     */
    public function revert(PendingChange $change, string $token): bool
    {
        $hash = hash('sha256', $token);

        $reverted = DB::transaction(function () use ($change, $hash) {
            $change = $this->lock($change);

            if ($change === null || ! $change->canRevert() || ! hash_equals($change->revert_token, $hash)) {
                return false;
            }

            $user = $change->user();

            if ($change->applied_at !== null && $user !== null) {
                $this->keyring->changing(fn () => $user->forceFill([$change->attribute => $change->previous_value])->save());
            }

            $change->forceFill(['reverted_at' => now()])->save();

            if ($user !== null) {
                // Later changes were made by whoever had the account; their
                // links must not be able to move the address away again.
                $this->closeLaterChanges($user, $change);

                $this->keyring->authenticatorModel()::query()
                    ->whereMorphedTo('authenticatable', $user)
                    ->where('created_at', '>=', $change->created_at)
                    ->delete();
            }

            return true;
        });

        $user = $change->fresh()?->user();

        if ($reverted && $user !== null) {
            $this->sessions->registry()->revokeAll($user);
            $this->devices->cycleRememberToken($user);

            EmailChangeReverted::dispatch($user, $change->fresh());
        }

        return $reverted;
    }

    /**
     * Cancel every change still waiting for confirmation, e.g. after the
     * account was recovered with a password reset.
     */
    public function cancel(Authenticatable&Model $user): void
    {
        PendingChange::query()
            ->whereMorphedTo('authenticatable', $user)
            ->where('attribute', $this->attribute())
            ->pending()
            ->update(['cancelled_at' => now()]);
    }

    public function pending(Authenticatable&Model $user): ?PendingChange
    {
        return PendingChange::query()
            ->whereMorphedTo('authenticatable', $user)
            ->where('attribute', $this->attribute())
            ->pending()
            ->latest()
            ->first();
    }

    /**
     * When the user's email last changed (or was changed back), for recovery
     * risk checks.
     */
    public function lastChangedAt(Authenticatable&Model $user): ?Carbon
    {
        $times = PendingChange::query()
            ->whereMorphedTo('authenticatable', $user)
            ->where('attribute', $this->attribute())
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
    protected function sessionProvedEstablishedSecondFactor(): bool
    {
        $signedInAt = $this->sessions->current(request())?->authenticatedAt;

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
        $user = $user === null ? null : $user->newQuery()->lockForUpdate()->find($user->getKey());

        if (
            $user === null
            || Str::lower((string) $user->getAttribute($change->attribute)) !== Str::lower((string) $change->previous_value)
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
            'revertable_until' => now()->addSeconds(Duration::seconds(config('keyring.email_changes.revertable_for', '7d'))),
        ])->save();

        return true;
    }

    protected function closeLaterChanges(Authenticatable&Model $user, PendingChange $change): void
    {
        PendingChange::query()
            ->whereMorphedTo('authenticatable', $user)
            ->where('attribute', $change->attribute)
            ->where($change->getKeyName(), '>', $change->getKey()) // ULIDs sort by creation
            ->whereNull('reverted_at')
            ->update(['cancelled_at' => now(), 'revertable_until' => now()]);
    }

    protected function lock(PendingChange $change): ?PendingChange
    {
        return PendingChange::query()->lockForUpdate()->find($change->getKey());
    }

    protected function taken(Authenticatable&Model $user, string $email): bool
    {
        return $user->newQuery()
            ->where($this->attribute(), $email)
            ->whereKeyNot($user->getKey())
            ->exists();
    }

    protected function attribute(): string
    {
        return $this->keyring->username();
    }
}
