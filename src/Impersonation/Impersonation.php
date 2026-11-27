<?php

declare(strict_types=1);

namespace Keyring\Impersonation;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Route;
use Keyring\Enums\ImpersonationEndReason;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\ImpersonationEnded;
use Keyring\Events\ImpersonationStarted;
use Keyring\Exceptions\ImpersonationRefused;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Login\Verification;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Signing in as another user, and coming back. Everything goes through
 * Keyring's own sessions rather than around them:
 *
 * - The impersonated session is a registered session of its own, on a new
 *   session ID, that proved nothing, is never remembered and is on no
 *   device. It names the impersonator and the record of their own session.
 * - The impersonator's session is parked, not ended: its record stays good
 *   (kept from idling out while they're active), and their "remember me"
 *   cookies are left as they are. What it proved is kept aside in the
 *   session, where nothing reads it until they come back. Its levels lapse
 *   on their own clocks as they would in that session: a request after a
 *   level's idle limit lapses it.
 * - Coming back takes that record still being good, the impersonator still
 *   being someone who may sign in, on the password their session had, and
 *   the browser's session still being the impersonation it started. Otherwise the browser is signed out, and
 *   the parked record ends with it. An impersonator who may no longer
 *   impersonate the user ends it too, and goes back. They come back at the
 *   level they had, but nothing counts as fresh: a page of the user's could
 *   have sent them back.
 *
 * The user's own sign-in events don't fire, so nothing that listens for a
 * sign in (new device emails, risk, "last signed in") takes it for one.
 *
 * @phpstan-type Parked array{impersonator: string, type: string, name: ?string, session: string, user: string, user_type: string, remembered: bool, started_at: int, expires_at: int, parked: array<string, mixed>}
 */
class Impersonation
{
    use ChoosesFormat;

    /** Where the browser's session keeps what it needs to go back. */
    public const string KEY = 'keyring.impersonation';

    /** What the impersonator's session proved, kept aside until they come back. */
    protected const array PROVED = [SessionAssurance::KEY, SessionAssurance::ACTIVE, SessionAssurance::LAPSED, SessionAssurance::SIGNED_IN];

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
    ) {}

    /**
     * Sign the browser in as $user, on behalf of whoever is signed in now.
     *
     * The user's record is saved before the browser changes hands, so a
     * registry that fails leaves the impersonator where they were.
     *
     * @throws ImpersonationRefused
     */
    public function start(Request $request, Authenticatable&Model $user): void
    {
        $impersonator = $this->keyring->user();
        $now = now()->getTimestamp();

        $refusal = match (true) {
            $this->active($request) => 'impersonating',
            $impersonator->is($user) => 'self',
            ! $this->keyring->allowsImpersonation($impersonator, $user) => 'not_allowed',
            default => null,
        };

        if ($refusal !== null) {
            throw new ImpersonationRefused($refusal);
        }

        // Coming back takes a record to come back to.
        $own = $this->sessions->current($request);

        if ($own === null || ! $own->isActive($now) || ! $own->belongsTo($impersonator)) {
            throw new ImpersonationRefused('unregistered');
        }

        $until = $now + Duration::seconds(config('keyring.impersonation.lifetime') ?? '1h');
        $session = $request->session();

        $parked = [
            'impersonator' => (string) $impersonator->getAuthIdentifier(),
            'type' => RegisteredSession::typeOf($impersonator),
            'name' => $this->nameOf($impersonator),
            'session' => $own->id,
            'user' => (string) $user->getAuthIdentifier(),
            'user_type' => RegisteredSession::typeOf($user),
            'remembered' => $session->get(Sessions::REMEMBERED) === true,
            'started_at' => $now,
            'expires_at' => $until,
            'parked' => $this->pick($session),
        ];

        $record = $this->sessions->startImpersonation($request, $user, $impersonator, $own, $until);

        $this->switchTo($request, $user);
        $session->put(self::KEY, $parked);
        $request->attributes->set(self::KEY, $parked);
        $this->sessions->rebind($request, $record, remembered: false);

        ImpersonationStarted::dispatch($impersonator, $user);
    }

    /**
     * Stop impersonating: back to the impersonator's own session, or signed
     * out when that has ended. Returns the impersonator when they're back.
     *
     * @throws LogicException when nobody is being impersonated
     */
    public function stop(Request $request): (Authenticatable&Model)|null
    {
        throw_unless($this->active($request), LogicException::class, 'Nobody is being impersonated in this session.');

        return $this->end($request, ImpersonationEndReason::Stopped)->returns() ? $this->keyring->user() : null;
    }

    /**
     * End the impersonation for a reason, and say what it ended for. The
     * impersonated session ends whatever happens. For a reason that goes
     * back, the browser goes back to the impersonator's session, on a new
     * session ID, as long as that session and the impersonator are still
     * good. It goes back at the level that session had, with nothing
     * counting as fresh. Otherwise, or for a reason that doesn't, the
     * browser is signed out and the impersonator's session ends too.
     *
     * Only the impersonation this browser started goes back: the guard
     * still signed in as the user it parked the impersonator's session for,
     * and the session still on the impersonated record that parked it, or
     * on no record at all. Anything else (the user gone, someone else
     * signed in on the session) signs out, as Lost: what's parked isn't
     * this session's to go back to. With nothing parked, the impersonated
     * record still names the impersonator and their session, which ends.
     *
     * The reason it ended for is the one given, unless it couldn't go back:
     * then ImpersonatorSessionEnded or Lost. It went back when the reason
     * returns().
     */
    public function end(Request $request, ImpersonationEndReason $reason): ImpersonationEndReason
    {
        $parked = $this->parked($request);
        $current = $this->sessions->current($request);
        $user = $this->keyring->guard()->user();
        $target = $this->userFrom($parked, $current);
        $impersonated = $current?->isImpersonated() === true ? $current : null;
        $impersonator = match (true) {
            $parked !== null => $this->impersonatorFrom($parked),
            default => $impersonated === null ? null : $this->load((string) $impersonated->impersonatorId, $impersonated->impersonatorType),
        };
        $own = $parked['session'] ?? $impersonated?->impersonatorSession;

        $ours = $parked !== null && $user !== null
            && (string) $user->getAuthIdentifier() === $parked['user'] && RegisteredSession::typeOf($user) === $parked['user_type']
            && ($current === null || ($current->impersonatorSession === $parked['session'] && $current->belongsTo($user)));
        $back = $ours && $reason->returns() ? $this->returnable($parked, $impersonator) : null;

        if ($back === null && $reason->returns()) {
            $reason = $ours ? ImpersonationEndReason::ImpersonatorSessionEnded : ImpersonationEndReason::Lost;
        }

        $this->sessions->because(SessionEndReason::ImpersonationEnded, function () use ($current, $own, $back) {
            if ($current !== null) {
                $this->sessions->registry()->revoke($current->id);
            }

            // Nobody is going back to it, so it ends with the browser.
            if ($back === null && $own !== null) {
                $this->sessions->registry()->revoke($own);
            }
        });

        $this->forget($request);

        if ($back === null) {
            app(SignIn::class)->out($request, onlyThisBrowser: true);
        } else {
            $this->switchTo($request, $back[0]);
            $this->restore($request, $this->catchUp($parked['parked'])[0]);
            $this->sessions->rebind($request, $back[1], $parked['remembered']);

            // A copy of the session from while impersonating would lead
            // back here again with what was parked: a cookie session's, in
            // the browser where regenerating can't destroy it, or a request
            // that overlapped this one and saves the old session after it.
            // The record moves, as on a step-up, so the copy's parked record
            // has ended. The browser's "remember me" moves with it.
            $this->sessions->reregister($request);
        }

        if ($impersonator !== null || $target !== null) {
            ImpersonationEnded::dispatch($impersonator, $target, $reason, $back !== null);
        }

        return $reason;
    }

    /**
     * The browser is being signed out while it impersonates: Keyring's own
     * sign-out, or the app's Auth::logout(). Or someone is signing in on a
     * session that still holds an impersonation (SignIn, and a sign in the
     * app started), which mustn't be left for the next request to go back
     * with. The impersonator's parked session ends with it, as nobody can
     * come back to it now.
     *
     * A session the app emptied before signing out, with invalidate() or
     * flush() ahead of Auth::logout(), is ended by what the request noted
     * (parked()), as Sessions::end() does for its own record.
     */
    public function signedOut(Request $request): void
    {
        if (($parked = $this->parked($request, orNoted: true)) === null) {
            return;
        }

        $this->forget($request);

        $this->sessions->because(SessionEndReason::ImpersonationEnded, fn () => $this->sessions->registry()->revoke($parked['session']));

        $impersonator = $this->impersonatorFrom($parked);
        $user = $this->userFrom($parked, null);

        if ($impersonator !== null || $user !== null) {
            ImpersonationEnded::dispatch($impersonator, $user, ImpersonationEndReason::SignedOut, false);
        }
    }

    /**
     * Why the impersonation this request is part of has to end now, if it
     * does. Asked by the session middleware on every request, in place of
     * its own checks. Who may impersonate whom is asked again each time, so
     * an impersonator who loses the right, or a user the app protects
     * since, ends it on the next request.
     */
    public function ending(Request $request, ?RegisteredSession $session, Authenticatable&Model $user): ?ImpersonationEndReason
    {
        $parked = $this->parked($request);
        $now = now()->getTimestamp();

        if ($parked === null || $session === null || $session->impersonatorSession !== $parked['session'] || ! $session->belongsTo($user)
            || $session->replacedBy !== null || ($session->revokedAt !== null && ! $this->sessions->timedOut($session))
            || ! $this->keyring->allowsSignIn($user)) {
            return ImpersonationEndReason::Ended;
        }

        $impersonator = $this->impersonatorFrom($parked);

        return match (true) {
            $impersonator !== null && ! $this->keyring->allowsImpersonation($impersonator, $user) => ImpersonationEndReason::Ended,
            $now >= $parked['expires_at'] || ! $session->isActive($now) || $this->sessions->idledOut($session, $now) => ImpersonationEndReason::Expired,
            $this->returnable($parked, $impersonator) === null => ImpersonationEndReason::ImpersonatorSessionEnded,
            default => null,
        };
    }

    /**
     * Note activity on the impersonated session and on the impersonator's,
     * so the one they'll come back to doesn't idle out while they're busy,
     * nor what it proved: the impersonator is using the browser all along.
     * The records at most once a minute, as for any session. What it proved
     * on every request, as their own session would note it, lapsing a level
     * whose idle limit passed since the last one.
     */
    public function touch(Request $request, RegisteredSession $session, int $now): void
    {
        if ($now - $session->lastActivityAt >= 60) {
            $this->sessions->registry()->update($session->id, ['lastActivityAt' => $now]);
            $this->sessions->registry()->update((string) $session->impersonatorSession, ['lastActivityAt' => $now]);
        }

        if (($parked = $this->parked($request)) !== null) {
            $parked['parked'] = $this->catchUp($parked['parked'])[0];

            $request->session()->put(self::KEY, $parked);
            $request->attributes->set(self::KEY, $parked);
        }
    }

    /**
     * Whether this request's session is impersonating someone, or was until
     * now and the session middleware hasn't caught up yet.
     */
    public function active(Request $request): bool
    {
        return $this->parked($request) !== null;
    }

    /**
     * Who is impersonating, while someone is. Null when nobody is, or when
     * they've since been deleted.
     */
    public function impersonator(Request $request): (Authenticatable&Model)|null
    {
        $parked = $this->parked($request);

        return $parked === null ? null : $this->impersonatorFrom($parked);
    }

    /**
     * The impersonation for a page to show, as in a banner with a way to
     * stop. Null when nobody is being impersonated. Read from the session,
     * so asking costs no query.
     *
     * @return array{impersonator: array{id: string, name: ?string}, startedAt: string, expiresAt: string, stopUrl: ?string}|null
     */
    public function toArray(Request $request): ?array
    {
        $parked = $this->parked($request);
        $time = fn (int $timestamp) => now()->setTimestamp($timestamp)->toIso8601String();

        return $parked === null ? null : [
            'impersonator' => ['id' => $parked['impersonator'], 'name' => $parked['name']],
            'startedAt' => $time($parked['started_at']),
            'expiresAt' => $time($parked['expires_at']),
            'stopUrl' => Route::has('keyring.impersonation.destroy') ? route('keyring.impersonation.destroy') : null,
        ];
    }

    /**
     * Who is in an impersonated session, as the user's sessions list names
     * them. Null for one nobody else is in, or whose impersonator is gone.
     */
    public function describe(RegisteredSession $session): ?string
    {
        $impersonator = $session->isImpersonated() ? $this->keyring->provider()->retrieveById($session->impersonatorId) : null;

        return $impersonator instanceof Model && RegisteredSession::typeOf($impersonator) === $session->impersonatorType ? $this->nameOf($impersonator) : null;
    }

    /**
     * Where starting goes: impersonation.redirect_to, or "home".
     */
    public function redirectTo(): string
    {
        return url()->to(config('keyring.impersonation.redirect_to') ?? config('keyring.home'));
    }

    /**
     * Where coming back goes: impersonation.return_to, or "home".
     */
    public function returnTo(): string
    {
        return url()->to(config('keyring.impersonation.return_to') ?? config('keyring.home'));
    }

    /**
     * The answer to anything Keyring refuses while impersonating: a 403,
     * with the "impersonating" status for JSON clients.
     */
    public function refuse(Request $request): Response
    {
        $message = $this->keyring->statusMessage('impersonating');

        return $this->wantsJson($request)
            ? new JsonResponse(['status' => 'impersonating', 'message' => $message], 403)
            : abort(403, (string) $message);
    }

    /**
     * Hand the browser to another user, on a new session ID, with nothing
     * of what the session held for the last one: what it proved, the
     * pending sign ins and confirms, Laravel's password confirmation, and
     * the password hash Laravel's auth.session middleware compares. Their
     * own Login event doesn't fire: nobody signed in.
     */
    protected function switchTo(Request $request, Authenticatable&Model $user): void
    {
        $guard = $this->keyring->guard();

        assert($guard instanceof SessionGuard);

        $session = $request->session();

        $session->regenerate(true);
        $session->forget(['keyring', 'auth.password_confirmed_at', $this->passwordHashKey()]);
        $session->put($guard->getName(), $user->getAuthIdentifier());

        $guard->setUser($user);
    }

    /**
     * The impersonator and their session, when the browser can go back to
     * it: the record is still good and theirs, they may still sign in, with
     * no password change they're held for, their password is the one the
     * session parked, and, under sessions.end_on_lapse, the level it signed
     * in at hasn't lapsed.
     *
     * @param  Parked  $parked
     * @return array{0: Authenticatable&Model, 1: RegisteredSession}|null
     */
    protected function returnable(array $parked, (Authenticatable&Model)|null $impersonator): ?array
    {
        $own = $impersonator === null ? null : $this->sessions->registry()->find($parked['session']);
        $now = now()->getTimestamp();

        if ($impersonator === null || $own === null || ! $own->isActive($now) || $this->sessions->idledOut($own, $now)
            || ! $own->belongsTo($impersonator) || ! $this->keyring->allowsSignIn($impersonator) || $this->keyring->requiresPasswordChange($impersonator)
            || $this->passwordChanged($parked['parked'], $impersonator) || $this->catchUp($parked['parked'])[1] !== null) {
            return null;
        }

        return [$impersonator, $own];
    }

    /**
     * Whether the impersonator's password changed since their session
     * parked its hash, compared as Laravel's auth.session middleware
     * compares it: the guard's keyed hash, or the raw hash an older session
     * kept. Decided here rather than left to that middleware, whose step
     * after the response stores the current hash over the one put back, so
     * a stop it wraps would come back signed in. Nothing to compare for an
     * impersonator without a password, which it skips too.
     *
     * @param  array<string, mixed>  $parked
     */
    protected function passwordChanged(array $parked, Authenticatable $impersonator): bool
    {
        $stored = $parked[$this->passwordHashKey()] ?? null;
        $password = $impersonator->getAuthPassword();
        $guard = $this->keyring->guard();

        assert($guard instanceof SessionGuard);

        return is_string($stored) && filled($password)
            && ! hash_equals($guard->hashPasswordForCookie($password), $stored) && ! hash_equals($password, $stored);
    }

    /**
     * What the impersonator's session parked, noted for a request now, by
     * the rules their own session goes by (SessionAssurance): a level whose
     * idle limit passed since the last request has lapsed. With why the
     * level it signed in at no longer holds, under sessions.end_on_lapse,
     * which ends it as it would end their own session.
     *
     * @param  array<string, mixed>  $parked
     * @return array{0: array<string, mixed>, 1: 'idle'|'expired'|null}
     */
    protected function catchUp(array $parked): array
    {
        $session = new Store('keyring-parked', new ArraySessionHandler(0));

        foreach ($parked as $key => $value) {
            $session->put($key, $value);
        }

        $assurance = new SessionAssurance($session, $this->sessions, $this->keyring);
        $assurance->touch();

        return [$this->pick($session), $assurance->lapse()];
    }

    /**
     * Put back what the impersonator's session had parked. What it proved
     * counts toward its level as before, but none of it as fresh: a page of
     * the user's, a stored script say, could have stopped the impersonation
     * and would otherwise act straight after as an impersonator who had
     * just proved everything. keyring.fresh and step-ups ask again.
     *
     * @param  array<string, mixed>  $parked
     */
    protected function restore(Request $request, array $parked): void
    {
        foreach ($parked as $key => $value) {
            if ($key === SessionAssurance::KEY && is_array($value)) {
                $value = array_map(fn (mixed $verification) => is_array($verification) ? [...$verification, 'authenticated_at' => Verification::UNKNOWN] : $verification, $value);
            }

            $request->session()->put($key, $value);
        }
    }

    /**
     * @param  Parked  $parked
     */
    protected function impersonatorFrom(array $parked): (Authenticatable&Model)|null
    {
        return $this->load($parked['impersonator'], $parked['type']);
    }

    /**
     * The user being impersonated, as the parked state names them, or the
     * impersonated record when the session has lost that. Not the guard's
     * user: the app may have signed someone else in meanwhile.
     *
     * @param  Parked|null  $parked
     */
    protected function userFrom(?array $parked, ?RegisteredSession $session): (Authenticatable&Model)|null
    {
        return match (true) {
            $parked !== null => $this->load($parked['user'], $parked['user_type']),
            $session !== null => $this->load($session->userId, $session->userType),
            default => null,
        };
    }

    /**
     * The account with this ID, as long as it's the type named: two user
     * models can have the same IDs.
     */
    protected function load(string $id, ?string $type): (Authenticatable&Model)|null
    {
        $found = $this->keyring->provider()->retrieveById($id);

        return $found instanceof Model && RegisteredSession::typeOf($found) === $type ? $found : null;
    }

    /**
     * A user's name for people to read: their "name", else their username.
     */
    protected function nameOf(Authenticatable&Model $user): ?string
    {
        $name = $user->getAttribute('name') ?? $user->getAttribute($this->keyring->username());

        return is_scalar($name) ? (string) $name : null;
    }

    /**
     * What the session parked, if it's impersonating. Noted on the request
     * too, so signedOut() can still end it if the app empties the session
     * before signing out: $orNoted reads that when the session has none.
     *
     * @return Parked|null
     */
    protected function parked(Request $request, bool $orNoted = false): ?array
    {
        $parked = $request->hasSession() ? $request->session()->get(self::KEY) : null;

        if (is_array($parked)) {
            $request->attributes->set(self::KEY, $parked);
        } elseif ($orNoted) {
            $parked = $request->attributes->get(self::KEY);
        }

        // @phpstan-ignore return.type (only start() and touch() write it, and always whole)
        return is_array($parked) ? $parked : null;
    }

    /**
     * Forget the impersonation, from the session and the request. From
     * request() too, when given a copy of it, like a form request: the
     * Logout listener reads the note from there, and would end it again.
     */
    protected function forget(Request $request): void
    {
        $request->session()->forget(self::KEY);
        $request->attributes->remove(self::KEY);
        request()->attributes->remove(self::KEY);
    }

    /**
     * What a session holds of what the impersonator's keeps aside.
     *
     * @return array<string, mixed>
     */
    protected function pick(Session $session): array
    {
        return array_filter(array_combine($this->parkedKeys(), array_map($session->get(...), $this->parkedKeys())), fn (mixed $value) => $value !== null);
    }

    /**
     * What the impersonator's session keeps aside: what it proved, and the
     * password hash Laravel's auth.session middleware compares, so a
     * password changed elsewhere meanwhile ends the impersonation and signs
     * them out rather than going back (passwordChanged()).
     *
     * @return list<string>
     */
    protected function parkedKeys(): array
    {
        return [...self::PROVED, $this->passwordHashKey()];
    }

    protected function passwordHashKey(): string
    {
        return 'password_hash_'.config('keyring.guard');
    }
}
