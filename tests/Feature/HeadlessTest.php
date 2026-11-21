<?php

declare(strict_types=1);

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Notifications\ConfirmEmailChange;
use Keyring\Notifications\NewDevice;
use Keyring\Tests\Fixtures\User;

// A frontend Laravel doesn't serve, such as a Nuxt app on another subdomain,
// asks for Keyring's pages with JSON and gets each one's name and props,
// and every answer that sends the browser to one of them names it, so the
// frontend can map it to a page of its own.

it('answers a json request for a page with its name and props', function () {
    $this->getJson('/login')
        ->assertOk()
        ->assertExactJson([
            'page' => 'login',
            'props' => ['canResetPassword' => true, 'canRegister' => true, 'status' => null],
        ])
        // The same headers as every other Keyring response.
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeader('Referrer-Policy', 'same-origin')
        ->assertHeader('X-Frame-Options', 'DENY');
});

it('sends a page without props as an object', function () {
    expect($this->getJson('/register')->assertOk()->getContent())->toBe('{"page":"register","props":{}}');
});

it('notes no json request as the page to go back to, as laravel notes no xhr', function () {
    $this->get('/forgot-password');
    $this->withHeader('X-Requested-With', 'XMLHttpRequest')->getJson('/login')->assertOk();

    expect(session()->previousUrl())->toBe(url('/forgot-password'));
});

it('still answers inertia with its component', function () {
    $this->inertia()->getJson('/login')->assertOk()->assertJsonPath('component', 'auth/login');
});

it('leaves a page the app answers itself to the app, for json too', function () {
    Keyring::page('login', fn (array $props) => response()->json(['mine' => array_keys($props)]));

    $this->getJson('/login')->assertOk()->assertExactJson(['mine' => ['canResetPassword', 'canRegister', 'status']]);
});

describe('signing in', function () {
    beforeEach(function () {
        $this->user = taylor();
        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    });

    it('names the challenge page, which comes back as json with what it posts', function () {
        $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertStatus(202)
            ->assertExactJson(['status' => 'challenge', 'page' => 'challenge', 'redirect' => route('keyring.login.challenge')]);

        $this->getJson(route('keyring.login.challenge'))
            ->assertOk()
            ->assertJsonPath('page', 'challenge')
            ->assertJsonPath('props.purpose', 'login')
            ->assertJsonPath('props.factor', 'totp')
            ->assertJsonPath('props.authenticator.id', $this->totp->id);

        $this->postJson(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)])
            ->assertOk()
            ->assertJsonPath('status', 'authenticated');

        $this->assertAuthenticatedAs($this->user);
    });

    it('sends the frontend on to a home of its own', function () {
        config(['keyring.home' => 'https://app.example.com/dashboard']);
        $this->totp->delete();

        $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertOk()
            ->assertJsonPath('redirect', 'https://app.example.com/dashboard');
    });

    it('answers a sign in that ran out as an error with the page to start again on, not a redirect', function () {
        $this->postJson(route('keyring.login.verify', 'totp'), ['code' => '123456'])
            ->assertUnprocessable()
            ->assertExactJson([
                'message' => __('keyring::keyring.expired'),
                'errors' => ['email' => [__('keyring::keyring.expired')]],
                'page' => 'login',
                'redirect' => route('login'),
            ]);

        $this->getJson(route('keyring.login.challenge'))->assertUnprocessable()->assertJsonPath('page', 'login');
    });

    it('still redirects a page visit with the error', function () {
        $this->post(route('keyring.login.verify', 'totp'), ['code' => '123456'])
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.expired')]);
    });
});

describe('step-up', function () {
    beforeEach(function () {
        $this->user = taylor();
    });

    it('names the confirm page, which comes back as json', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subDay())
            ->postJson(route('keyring.authenticators.store', 'totp'))
            ->assertStatus(423)
            ->assertJsonPath('page', 'confirm')
            ->assertJsonPath('redirect', route('keyring.confirm.challenge'));

        $this->getJson(route('keyring.confirm.challenge'))
            ->assertOk()
            ->assertJsonPath('page', 'confirm')
            ->assertJsonPath('props.purpose', 'confirm')
            ->assertJsonPath('props.factor', 'password');
    });

    it('answers a confirmation with nothing to confirm as an error on the confirm page', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
            ->postJson(route('keyring.confirm.verify', 'password'), ['password' => 'password'])
            ->assertUnprocessable()
            ->assertJsonPath('errors.password.0', __('keyring::keyring.expired'))
            ->assertJsonPath('page', 'confirm')
            ->assertJsonPath('redirect', route('keyring.confirm.challenge'));
    });
});

it('names the page a status sends the browser on to, and none for anywhere else', function (string $redirect, ?string $page) {
    request()->headers->set('Accept', 'application/json');

    $body = json_decode((string) Keyring::response(StatusResponse::class, status: 'device-revoked', redirect: $redirect === '' ? null : url($redirect))->toResponse(request())->getContent(), true);

    expect($body['page'] ?? null)->toBe($page);
})->with([
    'login' => ['/login', 'login'],
    'register' => ['/register', 'register'],
    'forgot password' => ['/forgot-password', 'forgot-password'],
    'verify email' => ['/email/verify', 'verify-email'],
    'challenge' => ['/login/challenge', 'challenge'],
    'confirm' => ['/confirm', 'confirm'],
    'home' => ['/dashboard', null],
    'back' => ['', null],
]);

it('names no page for a route that is turned off', function () {
    withFeatures([]);
    request()->headers->set('Accept', 'application/json');

    $body = json_decode((string) Keyring::response(StatusResponse::class, status: 'registered', redirect: url('/register'))->toResponse(request())->getContent(), true);

    expect($body)->not->toHaveKey('page');
});

describe('emailed links opened by the frontend', function () {
    beforeEach(function () {
        Notification::fake();
        Keyring::linkRootUsing(fn () => 'https://app.example.com');
    });

    it('starts a reset link at the frontend, which reads the page from the same path and posts the token back', function () {
        $user = taylor();
        $link = new ResetPassword(Password::broker()->createToken($user))->toMail($user)->actionUrl;

        expect($link)->toStartWith('https://app.example.com/reset-password/');

        $path = (string) parse_url($link, PHP_URL_PATH);
        $query = (string) parse_url($link, PHP_URL_QUERY);
        $token = basename($path);

        $props = $this->getJson($path.'?'.$query)
            ->assertOk()
            ->assertJsonPath('page', 'reset-password')
            // Its URL carries the token, so it's never cached or passed on.
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->assertHeader('Cache-Control', 'no-store, private')
            ->json('props');

        expect($props)->toBe(['token' => $token, 'email' => 'taylor@example.com']);

        $this->postJson(route('password.update'), [...$props, 'password' => 'a-new-password-1234', 'password_confirmation' => 'a-new-password-1234'])
            ->assertOk()
            ->assertExactJson([
                'status' => 'password-reset',
                'message' => __('keyring::status.password-reset'),
                'page' => 'login',
                'redirect' => route('login'),
            ]);
    });

    it('keeps a path the frontend\'s root has, ahead of keyring\'s own', function () {
        Keyring::linkRootUsing(fn () => 'https://app.example.com/account/');
        $user = taylor();

        expect(new ResetPassword('a-token')->toMail($user)->actionUrl)->toStartWith('https://app.example.com/account/reset-password/a-token?');
    });

    it('starts a verification link at the frontend, whose signature is good for the same path here', function () {
        revealTakenAddresses();
        Route::middleware(['web', 'auth'])->get('/dashboard', fn () => 'dashboard');
        $user = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password']);

        $this->actingAs($user)->postJson('/email/verification-notification')->assertOk()->assertJsonPath('status', 'verification-link-sent');

        Notification::assertSentTo($user, VerifyEmail::class, fn (VerifyEmail $notice) => (bool) ($this->link = $notice->toMail($user)->actionUrl));

        expect($this->link)->toStartWith('https://app.example.com/email/verify/');

        $path = (string) parse_url($this->link, PHP_URL_PATH);

        $props = $this->getJson($path.'?'.parse_url($this->link, PHP_URL_QUERY))
            ->assertOk()
            ->assertJsonPath('page', 'email-verification')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->json('props');

        expect($props)->toMatchArray(['email' => 'abigail@example.com', 'url' => $path]);

        $this->postJson($props['url'], ['expires' => $props['expires'], 'signature' => $props['signature']])
            ->assertOk()
            ->assertExactJson([
                'status' => 'email-verified',
                'message' => __('keyring::status.email-verified'),
                'justNow' => true,
                'redirect' => url('/dashboard?verified=1'),
            ]);

        expect($user->fresh()->hasVerifiedEmail())->toBeTrue();

        $this->getJson('/email/verify')->assertOk()->assertJsonPath('status', 'email-verified')->assertJsonPath('justNow', false);
        $this->getJson($path.'?'.parse_url($this->link, PHP_URL_QUERY))->assertOk()->assertJsonPath('justNow', false);
    });

    it('asks a signed-out frontend to sign in from a verification link, which then verifies the address', function () {
        $this->postJson('/register', ['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'correct horse battery staple', 'password_confirmation' => 'correct horse battery staple'])
            ->assertOk()
            ->assertJsonPath('page', 'login');

        $user = User::sole();
        Notification::assertSentTo($user, VerifyEmail::class, fn (VerifyEmail $notice) => (bool) ($this->link = $notice->toMail($user)->actionUrl));

        $this->getJson(parse_url($this->link, PHP_URL_PATH).'?'.parse_url($this->link, PHP_URL_QUERY))->assertUnauthorized();

        $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'correct horse battery staple'])
            ->assertOk()
            ->assertJsonPath('status', 'authenticated');

        expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
    });

    it('starts a "this wasn\'t me" link at the frontend, and names the page its button leads to', function () {
        sendNotifications(['new_device']);
        $user = taylor();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post('/logout');

        Notification::assertSentTo($user, NewDevice::class, fn (NewDevice $notice) => (bool) ($this->link = $notice->url));

        expect($this->link)->toStartWith('https://app.example.com/devices/');

        $path = (string) parse_url($this->link, PHP_URL_PATH);

        $props = $this->getJson($path.'?'.parse_url($this->link, PHP_URL_QUERY))
            ->assertOk()
            ->assertJsonPath('page', 'device-report')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->json('props');

        $this->postJson($props['url'], ['expires' => $props['expires'], 'signature' => $props['signature']])
            ->assertOk()
            ->assertJsonPath('status', 'device-reported')
            ->assertJsonPath('page', 'login');
    });

    it('starts an email change link at the frontend, and the page posts its token to a path without it', function () {
        sendNotifications(['confirm_email_change', 'email_change_notice']);
        $user = taylor();

        $this->actingAs($user)->withAssurance(Assurance::AAL1)->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

        Notification::assertSentTo(new AnonymousNotifiable, ConfirmEmailChange::class, fn (ConfirmEmailChange $notice) => (bool) ($this->link = $notice->url));

        expect($this->link)->toStartWith('https://app.example.com/email-changes/');

        $props = $this->getJson((string) parse_url($this->link, PHP_URL_PATH))
            ->assertOk()
            ->assertJsonPath('page', 'email-change')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->json('props');

        expect($props['url'])->not->toContain($props['token']);
    });
});

describe('with pages turned off', function () {
    beforeEach(function () {
        config(['keyring.pages' => false]);
    });

    it('answers anything but json with a 404, with the usual headers', function () {
        $this->get('/login')->assertNotFound()->assertHeader('Cache-Control', 'no-store, private');
        $this->inertia()->get('/login')->assertNotFound();
        $this->flushHeaders();
        $this->get('/reset-password/a-token?email=taylor@example.com')->assertNotFound()->assertHeader('Referrer-Policy', 'no-referrer');

        $this->getJson('/login')->assertOk()->assertJsonPath('page', 'login');
    });

    it('still renders a page the app answers itself', function () {
        Keyring::page('login', fn () => 'my login');

        $this->get('/login')->assertOk()->assertSee('my login');
    });

    it('still answers what the forms post', function () {
        taylor();

        $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertOk()->assertJsonPath('status', 'authenticated');
    });
});

it('tells the installer\'s reader where the pages go', function () {
    $this->sandbox = sys_get_temp_dir().'/keyring-headless-'.uniqid();
    $files = new Filesystem;
    $files->ensureDirectoryExists($this->sandbox.'/bootstrap');
    $files->ensureDirectoryExists($this->sandbox.'/config');
    $files->put($this->sandbox.'/bootstrap/providers.php', "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n];\n");
    $this->app->useAppPath($this->sandbox.'/app');
    $this->app->useBootstrapPath($this->sandbox.'/bootstrap');
    $this->app->useConfigPath($this->sandbox.'/config');
    $this->app->useDatabasePath($this->sandbox.'/database');

    try {
        $this->artisan('keyring:install', ['--no-interaction' => true])
            ->expectsOutputToContain('"Headless Frontends" docs')
            ->assertSuccessful();

        config(['keyring.pages' => false]);

        $this->artisan('keyring:install', ['--no-interaction' => true])
            ->expectsOutputToContain('Build Keyring\'s pages in your frontend')
            ->assertSuccessful();
    } finally {
        $files->deleteDirectory($this->sandbox);
    }
});
