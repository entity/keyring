<?php

declare(strict_types=1);

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Contracts\Responses\SignedOutResponse;
use Keyring\Devices\DeviceManager;
use Keyring\Devices\UserAgent;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Events\RememberMeReused;
use Keyring\Events\SessionEnded;
use Keyring\Events\SessionResumed;
use Keyring\Events\SessionsRevoked;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\RiskEngine;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Symfony\Component\HttpFoundation\Response;

/**
 * Checks every signed-in request against the session registry, so revoking
 * a session or device takes effect straight away on any session driver.
 * Also enforces idle and absolute timeouts.
 */
class AuthenticateSession
{
    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected SessionAssurance $assurance,
        protected DeviceManager $devices,
        protected RiskEngine $risk,
        protected RiskLocks $locks,
        protected SignIn $signIn,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $guard = $this->keyring->guard();

        if (! $request->hasSession()) {
            return $next($request);
        }

        // An app's own Auth::login() (Socialite, impersonation) is registered
        // on the response that signs in, so every copy of that session's
        // cookie can be revoked, on the cookie driver too. One that ticked
        // "remember me" gets Keyring's cookie next to Laravel's.
        if (! $guard->check()) {
            return tap($next($request), function () use ($request, $guard) {
                if (($user = $guard->user()) !== null && ! $request->session()->has(Sessions::KEY)) {
                    $this->register($request, $user, remembered: $this->sessions->recallerQueued());
                }
            });
        }

        $user = $this->keyring->user();

        // Someone the app has stopped letting sign in (Keyring::allowSignInWhen)
        // isn't left signed in, whatever kept them so: a session, a "remember
        // me" cookie, or a sign in the app started.
        if (! $this->keyring->allowsSignIn($user)) {
            return $this->keepOut($request, $user);
        }

        $session = $this->sessions->current($request);

        if ($session === null) {
            // The session was registered, but its record is gone (revoked and
            // expired, or the store was cleared). Treat it as signed out rather
            // than starting it over with a fresh window.
            if ($request->session()->has(Sessions::KEY)) {
                return $this->signOut($request, 'revoked');
            }

            if ($this->recalled($request)) {
                return $this->resume($request, $user) ?? $next($request);
            }

            $this->register($request, $user);

            return $next($request);
        }

        $now = now()->getTimestamp();

        if (($ended = $this->ended($session, $user, $now)) !== null) {
            // Still open on a record "remember me" has carried on from, so
            // this isn't the browser that did.
            return $ended === 'replaced' ? $this->reused($request, $user, $session) : $this->signOut($request, $ended);
        }

        // Before anything checks the level, so inactivity lapses it first.
        $this->assurance->touch();

        // With sessions.end_on_lapse, a session ends with the level it
        // signed in at, where it would otherwise carry on at a lower one.
        if (($lapse = $this->assurance->lapse()) !== null) {
            return $this->signOut($request, $lapse);
        }

        if ($this->risk->signalsFor(Checkpoint::Request) !== [] && ($response = $this->assessRisk($request, $user, $session)) !== null) {
            return $response;
        }

        if ($now - $session->lastActivityAt >= 60) {
            $this->sessions->registry()->update($session->id, ['lastActivityAt' => $now]);
        }

        return $next($request);
    }

    /**
     * Why this user can't carry on with a record, if they can't. "replaced"
     * is one "remember me" has already carried on from.
     *
     * @return 'revoked'|'expired'|'idle'|'other_user'|'replaced'|null
     */
    protected function ended(RegisteredSession $session, Authenticatable $user, int $now): ?string
    {
        return match (true) {
            $session->revokedAt !== null => 'revoked',
            $session->expiresAt <= $now => 'expired',
            $session->userId !== (string) $user->getAuthIdentifier() => 'other_user',
            $session->replacedBy !== null => 'replaced',
            $this->sessions->idledOut($session, $now) => 'idle',
            default => null,
        };
    }

    /**
     * Sign out someone the app no longer lets sign in. The first request
     * that's refused ends every session the account has, with its "remember
     * me" cookies and trusted devices: one that stayed away while the account
     * was kept out would otherwise work again the moment it's let back.
     * After that there are none left, so the account's other browsers are
     * only signed out themselves as each finds out.
     */
    protected function keepOut(Request $request, Authenticatable $user): Response
    {
        if ($this->sessions->registry()->forUser($user)->isNotEmpty()) {
            SessionsRevoked::dispatch($user, $this->sessions->signOutEverywhere($user));
        }

        return $this->signOut($request, 'not_allowed');
    }

    /**
     * Register a session that started some other way, like an app's own
     * Auth::login().
     */
    protected function register(Request $request, Authenticatable&Model $user, bool $remembered = false): void
    {
        $this->sessions->start($request, $user, $this->devices->find($request, $user), $this->assurance->level(), $remembered);
        $this->assurance->touch();
    }

    /**
     * Whether a "remember me" cookie signed this session in: on this request,
     * or earlier on a route this middleware isn't on (Sessions::markRecalled).
     */
    protected function recalled(Request $request): bool
    {
        return $this->keyring->guard()->viaRemember() || $request->session()->get(Sessions::REMEMBERED) === true;
    }

    /**
     * Let a "remember me" cookie carry on the session it was issued with, and
     * nothing else. Laravel's cookie works for as long as the browser sends
     * it, so on its own a copy kept after a timeout or a risk response would
     * start a new session with a whole new window. The browser's Keyring
     * cookie names the record it goes with, and the record has to still be
     * good. Returns a response when it isn't.
     *
     * The cookie works once: the session moves to a new record with a new
     * cookie, so a copy of the pair brings nothing back, and gives itself
     * away when it's tried (reused).
     */
    protected function resume(Request $request, Authenticatable&Model $user, bool $retry = true): ?Response
    {
        // The cookie signs in with nothing proved, so a risk lock refuses it
        // like any other sign in.
        if ($this->locks->locked($user)) {
            return $this->signOut($request, 'risk');
        }

        $session = $this->sessions->remembered($request);

        // No cookie, or no record left for it: both are kept for as long as
        // the session could last, so it has run out.
        if ($session === null) {
            return $this->signOut($request, 'expired');
        }

        $now = now()->getTimestamp();
        $ended = $this->ended($session, $user, $now);

        // A browser's first requests back arrive together, all with the
        // cookie the first of them uses up. The rest join the session that
        // one resumed, if it's still good.
        if ($joining = $ended === 'replaced' && ($resumed = $this->sessions->overlapped($request, $session)) !== null) {
            $ended = $this->ended($session = $resumed, $user, $now);
        }

        if ($ended === 'replaced') {
            return $this->reused($request, $user, $session);
        }

        if ($ended !== null) {
            // An idle session ends for good, as when its own request shows it.
            if ($ended === 'idle') {
                $this->sessions->registry()->revoke($session->id);
            }

            return $this->signOut($request, $ended);
        }

        // The cookie proves nothing, so it can't carry a session on where a
        // session ends with the level it signed in at.
        if (config('keyring.sessions.end_on_lapse')) {
            $this->sessions->registry()->revoke($session->id);

            return $this->signOut($request, 'expired');
        }

        // Whatever this session held, the cookie proved none of it.
        $this->assurance->flush();

        if ($joining) {
            $this->sessions->join($request, $session);
            $this->assurance->touch();

            return null;
        }

        $current = $this->sessions->resume($request, $user, $session);

        // A request sent alongside this one used the cookie first, or the
        // session was revoked a moment ago. Looking again says which.
        if ($current === null) {
            return $retry ? $this->resume($request, $user, retry: false) : $this->signOut($request, 'revoked');
        }

        // Recorded like a sign in, so a browser the account hasn't used is
        // announced as a new device. Only the request that resumed records
        // one, so the session's device is the one it came from.
        $device = $this->devices->signIn($request, $user);

        if ($device !== null && $device->id !== $current->deviceId) {
            $this->sessions->registry()->update($current->id, ['deviceId' => $device->id]);
        }

        $this->assurance->touch();

        SessionResumed::dispatch($user, $current->with(['deviceId' => $device->id ?? $current->deviceId]));

        if ($device?->wasRecentlyCreated) {
            NewDeviceSignedIn::dispatch($user, $device);
        }

        return null;
    }

    /**
     * A record "remember me" already carried on from has turned up again:
     * as its cookie, too late or from another browser to be a request sent
     * alongside, or as a session still open on it. Two browsers held the
     * same cookies, and nothing says which is the owner's, so the session
     * ends for both: this request is signed out, and the record the other
     * one holds now is revoked.
     *
     * The user's remember token is left alone. Neither browser's cookies
     * lead to a record that works any more, and changing the token would
     * sign out every other browser the user ticked "remember me" in.
     */
    protected function reused(Request $request, Authenticatable $user, RegisteredSession $session): Response
    {
        $current = $this->sessions->latest($session);

        // Already ended some other way: there's nothing left to end.
        if ($current?->isActive(now()->getTimestamp())) {
            $this->sessions->registry()->revoke($current->id);

            RememberMeReused::dispatch($user, $current);
        }

        return $this->signOut($request, 'reused');
    }

    /**
     * Cheap mid-session checks, like the session cookie turning up in a
     * different browser. Returns a response when the session must end.
     */
    protected function assessRisk(Request $request, mixed $user, RegisteredSession $session): ?Response
    {
        $risk = $this->risk->assess(new Assessment(Checkpoint::Request, $request, $user, session: $session));
        $action = $this->risk->enforce($user, $risk, Checkpoint::Request);

        if ($action->reauthenticate || $action->deny || $action->revokeSessions) {
            return $this->signOut($request, 'risk');
        }

        if (! $action->doesSomething()) {
            return null;
        }

        // Remember what we've seen, so the same change isn't acted on twice.
        $seen = ['ip' => $this->keyring->recordedIp($request), 'userAgent' => UserAgent::from($request)];

        // Ask again before anything sensitive. Only this request's copy of
        // the session forgets what it proved, so the session gets a new
        // record: an older cookie, or a request that overlapped this one and
        // saves after it, holds the old one and is signed out.
        if ($action->stepUp) {
            $this->assurance->flush();
            $this->sessions->reregister($request, $seen);
        } else {
            $this->sessions->registry()->update($session->id, $seen);
        }

        return null;
    }

    /**
     * @param  'revoked'|'expired'|'idle'|'other_user'|'reused'|'risk'|'not_allowed'  $reason
     */
    protected function signOut(Request $request, string $reason): Response
    {
        // An account that's kept out or locked loses the session its
        // "remember me" would carry on, too. Otherwise the same cookies
        // would sign it in again the moment it's let back. A cookie that was
        // used a moment ago stands for the session it was used for.
        if (in_array($reason, ['not_allowed', 'risk'], true) && ($remembered = $this->sessions->remembered($request)) !== null) {
            $this->sessions->registry()->revoke(($this->sessions->latest($remembered) ?? $remembered)->id);
        }

        if ($user = $this->signIn->out($request, onlyThisBrowser: true)) {
            SessionEnded::dispatch($user, $reason);
        }

        return $this->keyring->response(SignedOutResponse::class, reason: $reason)->toResponse($request);
    }
}
