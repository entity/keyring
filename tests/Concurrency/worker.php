<?php

declare(strict_types=1);

/*
 * One side of a race: boots the app the way the tests do, against the same
 * database, says it's ready, then runs one operation and prints what happened
 * as JSON. Usage: php worker.php <operation> <arguments...>
 */

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Changes\EmailChanges;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
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

            app(AuthenticatorChanges::class)->add($user, Keyring::factor('totp'), Authenticator::factory()->totp()->for($user, 'authenticatable')->make(), $request);

            return 'added';
        })(),
        'sign-out' => app(Sessions::class)->signOutEverywhere(User::findOrFail($id)),
        'end-latest' => (function () use ($id) {
            // Read while the row is held, as a request that found the cookie used.
            $session = app(SessionRegistry::class)->find($id);

            return app(Sessions::class)->endLatest(User::findOrFail($session->userId), $session)?->id;
        })(),
        'sign-out-everyone' => app(SessionRegistry::class)->revokeEveryone(),
        'revoke-all' => app(SessionRegistry::class)->revokeAll(User::findOrFail($id))->map(fn (RegisteredSession $session) => $session->id)->sort()->values()->all(),
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
