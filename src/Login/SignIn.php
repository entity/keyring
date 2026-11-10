<?php

namespace Keyring\Login;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Keyring\Activity\SecurityLog;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Purpose;
use Keyring\Events\Authenticated;
use Keyring\Events\Confirmed;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\Models\SecurityEvent;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;

/**
 * The one place a user becomes signed in (after a login or registration)
 * or confirms it's them (step-up). Everything that should happen at those
 * moments happens here.
 */
class SignIn
{
    public function __construct(
        protected KeyringManager $keyring,
        protected SessionAssurance $assurance,
        protected DeviceManager $devices,
        protected Sessions $sessions,
        protected SecurityLog $log,
    ) {}

    public function complete(Request $request, Attempt $attempt): void
    {
        $user = $attempt->user();

        if (! $this->keyring->belongsToGuard($user) || ! $this->keyring->allowsSignIn($user)) {
            throw ValidationException::withMessages([$this->keyring->username() => __('auth.failed')]);
        }

        $this->keyring->guard()->login($user, $attempt->remember);
        $request->session()->regenerate(true);
        $this->assurance->reset($attempt->verifications);

        $device = $this->devices->signIn(
            $request,
            $user,
            provedSecondFactor: Requirement::aal2()->isMetBy($attempt->verifications),
            trust: $this->earnedTrust($attempt),
        );

        $new = $device?->wasRecentlyCreated === true;

        $this->sessions->start($request, $user, $device, $this->assurance->level(), remembered: $attempt->remember);

        // A password reset or change, or an email change or its undo, signs
        // out the sessions registered by then. This one was still being
        // checked, and is only registered now, so look again: with the new
        // password or address saved, it ends here.
        if ($this->changedMeanwhile($user)) {
            $this->out($request, onlyThisBrowser: true);

            throw ValidationException::withMessages([$this->keyring->username() => __('auth.failed')]);
        }

        Authenticated::dispatch($user, $attempt, $device);

        // "Was this you?" for anything suspicious since they last signed in.
        // A browser the account hasn't used before could be whoever caused
        // them, so they wait for one it has.
        $request->session()->flash('keyring.alerts', $new ? [] : $this->log->pullAlerts($user)->map(fn (SecurityEvent $event) => [
            'type' => $event->type,
            'factor' => $event->factor,
            'at' => $event->created_at->toIso8601String(),
            'ip' => $event->ip,
        ])->all());

        if ($new) {
            NewDeviceSignedIn::dispatch($user, $device);
        }
    }

    /**
     * Whether this login may mark the device trusted: the user asked, and it
     * verified two categories on an account whose email is proven. Otherwise
     * a second factor enrolled later would be skipped on a device that never
     * proved one.
     */
    protected function earnedTrust(Attempt $attempt): bool
    {
        $user = $attempt->user();

        return $attempt->trustDevice
            && Requirement::aal2()->isMetBy($attempt->verifications)
            && (! Features::enabled(Features::emailVerification()) || ! $user instanceof MustVerifyEmail || $user->hasVerifiedEmail());
    }

    /**
     * Whether the password or the email address is no longer the one this
     * request loaded and checked. Read after the session is registered: if
     * they're still the same, a change hasn't saved yet, and its sign-out
     * will find this session.
     */
    protected function changedMeanwhile(Authenticatable&Model $user): bool
    {
        $now = $user->newQuery()->whereKey($user->getKey())->first();
        $email = $this->keyring->email();

        return ! $now instanceof Authenticatable
            || ! hash_equals((string) $user->getAuthPassword(), (string) $now->getAuthPassword())
            || $user->getAttribute($email) !== $now->getAttribute($email);
    }

    public function confirm(Request $request, Attempt $attempt): void
    {
        $request->session()->regenerate(true);
        $this->assurance->confirm($attempt->verifications);
        $this->sessions->elevate($request, $this->assurance->level());

        Confirmed::dispatch($attempt->user(), $attempt);
    }

    /**
     * Sign the current user out of this session. Returns who it was.
     *
     * Signing out on purpose changes the "remember me" token, as Laravel
     * does. A session that ends on its own (a timeout, say) leaves the token
     * alone, or one ending would sign out every remembered browser: its
     * record is revoked, and that is what stops this browser's cookies
     * bringing it back (Sessions::end).
     */
    public function out(Request $request, bool $onlyThisBrowser = false): ?Authenticatable
    {
        $guard = $this->keyring->guard();
        $user = $guard->user();

        $this->sessions->end($request);
        $onlyThisBrowser && $guard instanceof SessionGuard ? $guard->logoutCurrentDevice() : $guard->logout();
        $this->assurance->flush();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return $user;
    }

    /**
     * Sign in a user who just proved something outside the pipeline, like
     * choosing a password at registration.
     *
     * @param  list<Verification>  $verifications
     */
    public function as(Request $request, Authenticatable&Model $user, array $verifications, bool $remember = false): void
    {
        $this->complete($request, Attempt::start(Purpose::Login, $user, $remember, verifications: $verifications));
    }
}
