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
use Keyring\Login\Requirement;
use Keyring\Models\PendingChange;
use Keyring\Notifications\ConfirmEmailChange;
use Keyring\Notifications\EmailAddressInUse;
use Keyring\Notifications\EmailChangeNotice;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;

/**
 * Changing the email address the OWASP way:
 *
 *  1. The user re-verifies (handled by middleware) and asks for a new address.
 *  2. The new address gets a confirmation link. The current address gets a
 *     notice with a "this wasn't me" link, and must confirm too when the
 *     account has no second factor.
 *  3. Once confirmed, the change applies, and can still be reverted from the
 *     old address for a while, which signs everything out.
 *
 * Nothing reveals whether the new address belongs to another account.
 */
class EmailChanges
{
    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected DeviceManager $devices,
    ) {}

    public function request(Authenticatable&Model $user, string $email): ?PendingChange
    {
        $email = Str::lower(trim($email));
        $attribute = $this->attribute();

        if ($email === Str::lower((string) $user->getAttribute($attribute))) {
            return null;
        }

        if ($this->taken($user, $email)) {
            Notification::route('mail', $email)->notify(new EmailAddressInUse);

            return null;
        }

        $tokens = ['confirm' => Str::random(48), 'current' => Str::random(48), 'revert' => Str::random(48)];
        $needsCurrent = ! $this->keyring->for($user)->canMeet(Requirement::aal2()->including(Category::Possession));

        $change = DB::transaction(function () use ($user, $email, $tokens, $needsCurrent) {
            $this->pending($user)?->forceFill(['cancelled_at' => now()])->save();

            $change = new PendingChange([
                'attribute' => $this->attribute(),
                'value' => $email,
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
        Notification::route('mail', $user->getAttribute($this->attribute()))->notify(
            new EmailChangeNotice($change, $tokens['revert'], $needsCurrent ? $tokens['current'] : null),
        );

        EmailChangeRequested::dispatch($user, $change);

        return $change;
    }

    /**
     * Handle a confirmation link from either address. Returns whether the
     * change has now been applied.
     */
    public function confirm(PendingChange $change, string $token): bool
    {
        if (! $change->isPending()) {
            return false;
        }

        $hash = hash('sha256', $token);

        match (true) {
            hash_equals($change->confirm_token, $hash) => $change->confirmed_at ??= now(),
            $change->current_token !== null && hash_equals($change->current_token, $hash) => $change->current_confirmed_at ??= now(),
            default => null,
        };

        $change->save();

        return $change->isReady() && $this->apply($change);
    }

    /**
     * "This wasn't me": undo the change (or cancel it) and sign out everywhere.
     */
    public function revert(PendingChange $change, string $token): bool
    {
        if (! $change->canRevert() || ! hash_equals($change->revert_token, hash('sha256', $token))) {
            return false;
        }

        $user = $change->user();

        DB::transaction(function () use ($change, $user) {
            if ($change->applied_at !== null && $user !== null) {
                $this->keyring->changing(fn () => $user->forceFill([$change->attribute => $change->previous_value])->save());
            }

            $change->forceFill(['reverted_at' => now()])->save();
        });

        if ($user !== null) {
            $this->sessions->registry()->revokeAll($user);
            $this->devices->cycleRememberToken($user);

            EmailChangeReverted::dispatch($user, $change);
        }

        return true;
    }

    public function cancel(Authenticatable&Model $user): void
    {
        $this->pending($user)?->forceFill(['cancelled_at' => now()])->save();
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
     * When the user's email last changed, for recovery risk checks.
     */
    public function lastChangedAt(Authenticatable&Model $user): ?Carbon
    {
        $at = PendingChange::query()
            ->whereMorphedTo('authenticatable', $user)
            ->where('attribute', $this->attribute())
            ->whereNotNull('applied_at')
            ->whereNull('reverted_at')
            ->max('applied_at');

        return $at === null ? null : Carbon::parse($at);
    }

    protected function apply(PendingChange $change): bool
    {
        $user = $change->user();

        if ($user === null || $this->taken($user, $change->value)) {
            $change->forceFill(['cancelled_at' => now()])->save();

            return false;
        }

        DB::transaction(function () use ($change, $user) {
            $previous = $user->getAttribute($change->attribute);

            $this->keyring->changing(fn () => $user->forceFill([
                $change->attribute => $change->value,
                ...(array_key_exists('email_verified_at', $user->getAttributes()) ? ['email_verified_at' => now()] : []),
            ])->save());

            $change->forceFill([
                'previous_value' => $previous,
                'applied_at' => now(),
                'revertable_until' => now()->addSeconds(Duration::seconds(config('keyring.email_changes.revertable_for', '7d'))),
            ])->save();
        });

        EmailChanged::dispatch($user, $change);

        return true;
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
