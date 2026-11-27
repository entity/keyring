<?php

declare(strict_types=1);

namespace Keyring\Impersonation;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Keyring\Enums\ImpersonationEndReason;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\ImpersonationEnded;
use Keyring\Events\ImpersonationStarted;
use Keyring\Exceptions\ImpersonationRefused;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
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
 *   session, where nothing reads it until they come back.
 * - Coming back takes that record still being good, and the impersonator
 *   still being someone who may sign in. Otherwise the browser is signed
 *   out, and the parked record ends with it.
 *
 * The user's own sign-in events don't fire, so nothing that listens for a
 * sign in (new device emails, risk, "last signed in") takes it for one.
 *
 * @phpstan-type Parked array{impersonator: string, type: string, name: ?string, session: string, remembered: bool, started_at: int, expires_at: int, parked: array<string, mixed>}
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
            'remembered' => $session->get(Sessions::REMEMBERED) === true,
            'started_at' => $now,
            'expires_at' => $until,
            'parked' => array_filter(array_combine(self::PROVED, array_map($session->get(...), self::PROVED)), fn (mixed $value) => $value !== null),
        ];

        $record = $this->sessions->startImpersonation($request, $user, $impersonator, $own, $until);

        $this->switchTo($request, $user);
        $session->put(self::KEY, $parked);
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

        return $this->end($request, ImpersonationEndReason::Stopped);
    }

    /**
     * End the impersonation for a reason. The impersonated session ends
     * whatever happens. For a reason that goes back, the browser goes back
     * to the impersonator's session with what it had proved, on a new
     * session ID, as long as that session and the impersonator are still
     * good. Otherwise, or for one that doesn't, the browser is signed out
     * and the impersonator's session ends too. Returns the impersonator
     * when they're back.
     */
    public function end(Request $request, ImpersonationEndReason $reason): (Authenticatable&Model)|null
    {
        $parked = $this->parked($request);
        $user = $this->keyring->guard()->user();
        $back = $reason->returns() ? $this->returnable($parked) : null;

        if ($back === null && $reason->returns()) {
            $reason = ImpersonationEndReason::ImpersonatorSessionEnded;
        }

        $impersonator = $back[0] ?? ($parked === null ? null : $this->impersonatorFrom($parked));

        $this->sessions->because(SessionEndReason::ImpersonationEnded, function () use ($request, $parked, $back) {
            if (($current = $this->sessions->current($request)) !== null) {
                $this->sessions->registry()->revoke($current->id);
            }

            // Nobody is going back to it, so it ends with the browser.
            if ($back === null && $parked !== null) {
                $this->sessions->registry()->revoke($parked['session']);
            }
        });

        $request->session()->forget(self::KEY);

        if ($back === null) {
            app(SignIn::class)->out($request, onlyThisBrowser: true);
        } else {
            [$impersonator, $own] = $back;

            assert($parked !== null);

            $this->switchTo($request, $impersonator);

            foreach ($parked['parked'] as $key => $value) {
                $request->session()->put($key, $value);
            }

            $this->sessions->rebind($request, $own, $parked['remembered']);
        }

        if ($user !== null) {
            ImpersonationEnded::dispatch($impersonator, $user, $reason, $back !== null);
        }

        return $back[0] ?? null;
    }

    /**
     * The browser is being signed out while it impersonates: Keyring's own
     * sign-out, or the app's Auth::logout(). The impersonator's parked
     * session ends with it, as nobody can come back to it now.
     */
    public function signedOut(Request $request, ?Authenticatable $user): void
    {
        if (($parked = $this->parked($request)) === null) {
            return;
        }

        $request->session()->forget(self::KEY);

        $this->sessions->because(SessionEndReason::ImpersonationEnded, fn () => $this->sessions->registry()->revoke($parked['session']));

        if ($user !== null) {
            ImpersonationEnded::dispatch($this->impersonatorFrom($parked), $user, ImpersonationEndReason::SignedOut, false);
        }
    }

    /**
     * Why the impersonation this request is part of has to end now, if it
     * does. Asked by the session middleware on every request, in place of
     * its own checks.
     */
    public function ending(Request $request, ?RegisteredSession $session, Authenticatable&Model $user): ?ImpersonationEndReason
    {
        $parked = $this->parked($request);
        $now = now()->getTimestamp();

        return match (true) {
            $parked === null || $session === null || $session->impersonatorSession !== $parked['session'] || ! $session->belongsTo($user)
                || $session->replacedBy !== null || ($session->revokedAt !== null && ! $this->sessions->timedOut($session))
                || ! $this->keyring->allowsSignIn($user) => ImpersonationEndReason::Ended,
            $now >= $parked['expires_at'] || ! $session->isActive($now) || $this->sessions->idledOut($session, $now) => ImpersonationEndReason::Expired,
            $this->returnable($parked) === null => ImpersonationEndReason::ImpersonatorSessionEnded,
            default => null,
        };
    }

    /**
     * Note activity on the impersonated session and on the impersonator's,
     * so the one they'll come back to doesn't idle out while they're busy.
     * At most once a minute, as for any session.
     */
    public function touch(RegisteredSession $session, int $now): void
    {
        if ($now - $session->lastActivityAt < 60) {
            return;
        }

        $this->sessions->registry()->update($session->id, ['lastActivityAt' => $now]);
        $this->sessions->registry()->update((string) $session->impersonatorSession, ['lastActivityAt' => $now]);
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
        $session->forget(['keyring', 'auth.password_confirmed_at', 'password_hash_'.config('keyring.guard')]);
        $session->put($guard->getName(), $user->getAuthIdentifier());

        $guard->setUser($user);
    }

    /**
     * The impersonator and their session, when the browser can go back to
     * it: the record is still good and theirs, and they may still sign in.
     *
     * @param  Parked|null  $parked
     * @return array{0: Authenticatable&Model, 1: RegisteredSession}|null
     */
    protected function returnable(?array $parked): ?array
    {
        $impersonator = $parked === null ? null : $this->impersonatorFrom($parked);
        $own = $parked === null ? null : $this->sessions->registry()->find($parked['session']);
        $now = now()->getTimestamp();

        if ($impersonator === null || $own === null || ! $own->isActive($now) || $this->sessions->idledOut($own, $now)
            || ! $own->belongsTo($impersonator) || ! $this->keyring->allowsSignIn($impersonator)) {
            return null;
        }

        return [$impersonator, $own];
    }

    /**
     * @param  Parked  $parked
     */
    protected function impersonatorFrom(array $parked): (Authenticatable&Model)|null
    {
        $found = $this->keyring->provider()->retrieveById($parked['impersonator']);

        return $found instanceof Model && RegisteredSession::typeOf($found) === $parked['type'] ? $found : null;
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
     * @return Parked|null
     */
    protected function parked(Request $request): ?array
    {
        $parked = $request->hasSession() ? $request->session()->get(self::KEY) : null;

        // @phpstan-ignore return.type (only start() writes it, and always whole)
        return is_array($parked) ? $parked : null;
    }
}
