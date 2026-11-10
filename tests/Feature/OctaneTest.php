<?php

use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Keyring\Contracts\Responses\LogoutResponse;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;

// Octane boots the app once per worker and handles each request in a copy of
// it. Keyring's manager is built at boot, when the app's provider registers
// its factors, and lives as long as the worker does.
beforeEach(function () {
    $this->user = taylor();
    $this->booted = app();

    // Octane resolves the session while booting unless the app took it out
    // of the "warm" list in config/octane.php. Without it, each request's
    // copy of the app makes a session of its own.
    $this->booted->forgetInstance('session');
    $this->booted->forgetInstance('session.store');

    expect(app(KeyringManager::class))->toBe(Keyring::getFacadeRoot());
});

afterEach(function () {
    Container::setInstance($this->booted);
    Facade::clearResolvedInstances();
    Facade::setFacadeApplication($this->booted);
});

/**
 * Handle a request the way an Octane worker does: in a copy of the booted
 * app, made the current one, with the request handed to both.
 *
 * @param  array<string, mixed>  $input
 * @return array{Application, Request}
 */
function octaneRequest(Application $booted, array $input): array
{
    $sandbox = clone $booted;
    $sandbox->instance('app', $sandbox);
    $sandbox->instance(Container::class, $sandbox);
    Container::setInstance($sandbox);
    Facade::clearResolvedInstances();
    Facade::setFacadeApplication($sandbox);

    if ($sandbox->resolved('auth')) {
        $sandbox->make('auth')->setApplication($sandbox)->forgetGuards();
    }

    // The session the session middleware starts for this request.
    $session = $sandbox->make('session.store');
    $session->start();

    $request = Request::create('/login', 'POST', $input);
    $request->setLaravelSession($session);

    $booted->instance('request', $request);
    $sandbox->instance('request', $request);

    return [$sandbox, $request];
}

it('keeps a sign in waiting for its second factor in the session of the request that started it', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    [$sandbox, $request] = octaneRequest($this->booted, ['email' => 'taylor@example.com', 'password' => 'password']);

    expect(Keyring::attempt($request)->getStatusCode())->toBe(302)
        ->and($request->session()->has(AttemptStore::key(Purpose::Login)))->toBeTrue()
        ->and($sandbox->make(AttemptStore::class)->current(Purpose::Login)?->userId)->toBe($this->user->id);
});

it('records what a sign in proved in the session of the request that made it', function () {
    [$sandbox, $request] = octaneRequest($this->booted, ['email' => 'taylor@example.com', 'password' => 'password']);

    Keyring::attempt($request);

    expect(Keyring::guard()->id())->toBe($this->user->id)
        ->and($request->session()->has(SessionAssurance::KEY))->toBeTrue()
        ->and($sandbox->make(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
});

it('leaves nothing of one request\'s sign in for the next request to find', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    [, $request] = octaneRequest($this->booted, ['email' => 'taylor@example.com', 'password' => 'password']);
    Keyring::attempt($request);

    // Someone else, on the same worker, straight afterwards. Octane empties
    // the session it kept before each request; Keyring shouldn't need it to.
    [$sandbox, $next] = octaneRequest($this->booted, []);

    expect($next->session()->getId())->not->toBe($request->session()->getId())
        ->and($next->session()->all())->not->toHaveKey(AttemptStore::key(Purpose::Login))
        ->and($sandbox->make(AttemptStore::class)->current(Purpose::Login))->toBeNull()
        ->and($this->booted->make(AttemptStore::class)->current(Purpose::Login))->toBeNull();
});

it('builds what a request needs in the app handling it', function () {
    Keyring::respondWith(LogoutResponse::class, fn (Application $app) => new class($app) implements LogoutResponse
    {
        public function __construct(public Application $app) {}

        public function toResponse($request)
        {
            return response()->noContent();
        }
    });

    [$sandbox] = octaneRequest($this->booted, []);

    expect(Keyring::response(LogoutResponse::class)->app)->toBe($sandbox);
});
