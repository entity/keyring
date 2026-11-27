<?php

declare(strict_types=1);

/*
 * One side of a race: boots the app the way the tests do, against the same
 * database, says it's ready, then runs one operation and prints what happened
 * as JSON. Usage: php worker.php <operation> <arguments...>
 */

use Illuminate\Auth\AuthenticationException;
use Illuminate\Cache\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Sleep;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Changes\EmailChanges;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Sessions\CacheSessionRegistry;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;
use Keyring\Support\Throttle;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\TestCase;

require __DIR__.'/../../vendor/autoload.php';

new class('worker') extends TestCase {}->createApplication();
useRaceFactors();

[, $operation, $id, $value] = $argv + [3 => null];

echo "ready\n";

try {
    $result = match ($operation) {
        'remove-authenticator' => Keyring::authenticatorModel()::find($value) !== null
            && app(AuthenticatorChanges::class)->remove(User::findOrFail($id), $value) instanceof Authenticator,
        'use-recovery-code' => (function () use ($id, $value) {
            $authenticator = Authenticator::findOrFail($id);
            $attempt = Attempt::start(Purpose::Login, $authenticator->user());

            return Keyring::factor('recovery')->verify($attempt, $authenticator, Request::create('/', 'POST', ['code' => $value])) !== null;
        })(),
        'use-passkey', 'answer-challenge' => (function () use ($operation, $id, $value) {
            // Answered challenges are remembered in the rate limiter's
            // store. Kept in the database, every side of a race sees it.
            if ($operation === 'answer-challenge') {
                config(['cache.limiter' => 'database']);
            }

            $authenticator = Authenticator::findOrFail($id);
            ['options' => $options, 'credential' => $credential] = json_decode($value, true);
            $attempt = Attempt::start(Purpose::Login, $authenticator->user());
            $attempt->put('passkey', 'options', $options);

            return Keyring::factor('passkey')->verify($attempt, $authenticator, Request::create('/', 'POST', ['credential' => $credential])) !== null;
        })(),
        'guess-password' => (function () use ($id) {
            $throttle = app(Throttle::class);
            $limits = Keyring::factor('password')->limits(Request::create('/login', 'POST', ['email' => User::findOrFail($id)->email]), null);

            // As the pipeline does around a wrong password: counted going
            // in, unless a limit refuses it, and failed coming out.
            if ($throttle->hit($limits) !== null) {
                return 'refused';
            }

            $throttle->failed($limits);

            return 'checked';
        })(),
        'resume-session' => (function () use ($id) {
            $request = Request::create('/');
            $request->setLaravelSession(app('session.store'));

            // Read while the row is held, as a request that found the cookie unused.
            $session = app(SessionRegistry::class)->find($id);

            return app(Sessions::class)->resume($request, User::findOrFail($session->userId), $session)?->id;
        })(),
        'start-session' => (function () use ($id, $value) {
            config(['keyring.sessions.max' => (int) $value]);

            $request = Request::create('/');
            $request->setLaravelSession(app('session.store'));

            return app(Sessions::class)->start($request, User::findOrFail($id), null, Assurance::AAL1)->id;
        })(),
        'add-authenticator' => (function () use ($id, $value) {
            // A request its middleware let through as this session, saving
            // a sign-in method it has just confirmed.
            $request = Request::create('/user/authenticators/totp/confirm', 'POST');
            $request->setLaravelSession(app('session.store'));
            $request->session()->put(Sessions::KEY, $value);

            $user = User::findOrFail($id);

            app(AuthenticatorChanges::class)->add($user, Keyring::factor('totp'), Authenticator::factory()->totp()->for($user, 'authenticatable')->make(), $request, passwordConfirmed: true);

            return 'added';
        })(),
        'sign-out' => app(Sessions::class)->signOutEverywhere(User::findOrFail($id)),
        'end-latest' => (function () use ($id) {
            // Read while the row is held, as a request that found the cookie used.
            $session = app(SessionRegistry::class)->find($id);

            return app(Sessions::class)->endLatest(User::findOrFail($session->userId), $session)?->id;
        })(),
        'sign-out-everyone' => app(SessionRegistry::class)->revokeEveryone(),
        'revoke' => app(SessionRegistry::class)->revoke($id)?->id,
        'revoke-all' => app(SessionRegistry::class)->revokeAll(User::findOrFail($id))->map(fn (RegisteredSession $session) => $session->id)->sort()->values()->all(),
        'start-session-announcing' => (function () use ($id, $value) {
            config(['keyring.sessions.max' => (int) $value]);
            $announced = [];
            Event::listen(function (RegisteredSessionEnded $event) use (&$announced) {
                $announced[] = $event->handle;
            });

            $request = Request::create('/');
            $request->setLaravelSession(app('session.store'));
            app(Sessions::class)->start($request, User::findOrFail($id), null, Assurance::AAL1);

            return $announced;
        })(),
        'sweep' => (function () {
            $announced = [];
            Event::listen(function (RegisteredSessionEnded $event) use (&$announced) {
                $announced[] = $event->handle;
            });

            Artisan::call('keyring:sweep');

            return $announced;
        })(),
        'cache-replace-paused' => (function () use ($id) {
            // Moves a session on the cache driver, and stops between adding
            // the key that says it moved and checking nothing revoked it,
            // where a revocation used to slip in unannounced.
            $cache = new class(Cache::store('database')->getStore()) extends Repository
            {
                public function add($key, $value, $ttl = null)
                {
                    $added = parent::add($key, $value, $ttl);

                    if (str_ends_with((string) $key, ':replaced')) {
                        Cache::store('database')->put('race:paused', true, 60);
                        Sleep::sleep(2);
                    }

                    return $added;
                }
            };
            $registry = new CacheSessionRegistry($cache);
            $session = $registry->find($id);

            return $registry->replace($id, $session->with(['id' => 'successor', 'origin' => $session->origin()]));
        })(),
        'announce-revoke-all' => (function () use ($id) {
            $announced = [];
            Event::listen(function (RegisteredSessionEnded $event) use (&$announced) {
                $announced[] = $event->handle;
            });

            app(SessionRegistry::class)->revokeAll(User::findOrFail($id));

            return $announced;
        })(),
        'confirm-email-change' => app(EmailChanges::class)->confirm(PendingChange::findOrFail($id), $value)->name,
        'revert-email-change' => app(EmailChanges::class)->revert(PendingChange::findOrFail($id), $value),
        'change-password' => (function () use ($id, $value) {
            // A request its middleware let through as this session, with its
            // current password checked against the user it loaded.
            $request = Request::create('/user/password', 'PUT');
            $request->setLaravelSession(app('session.store'));
            $request->session()->put(Sessions::KEY, $value);

            $user = User::findOrFail($id);

            app(PasswordChanges::class)->change($user, fn () => $user->forceFill(['password' => 'a passphrase sent a moment later'])->save(), currentSession: $value, request: $request);

            return 'changed';
        })(),
        'request-email-change' => (function () use ($id, $value) {
            // A request its middleware let through as this session.
            $request = Request::create('/user/email', 'POST');
            $request->setLaravelSession(app('session.store'));
            $request->session()->put(Sessions::KEY, $value);

            return app(EmailChanges::class)->request(User::findOrFail($id), 'new@example.com', $request)?->id !== null;
        })(),
    };
} catch (ValidationException) {
    $result = 'refused';
} catch (AuthenticationException) {
    $result = 'signed out';
}

echo json_encode(['result' => $result]), "\n";
