<?php

namespace Keyring\Tests\Feature;

use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Http\Middleware\AuthenticateSession;
use Keyring\Pipeline\Steps;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Testing\KeyringConformance;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\TestCase;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Keyring runs its own conformance suite against a full setup.
 */
class ConformanceTest extends TestCase
{
    use KeyringConformance;

    /** What Sanctum's statefulApi() puts on the api group. */
    private const string STATEFUL = 'Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful';

    /** @var list<class-string> */
    private array $acknowledged = [];

    /** @var list<string> */
    private array $unchecked = [];

    protected function setUp(): void
    {
        parent::setUp();

        Notification::fake();
        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys(), Totp::class, EmailCode::asSecondFactor(), RecoveryCodes::class]);
    }

    protected function keyringUser(): User
    {
        return User::create(['name' => 'Taylor', 'email' => 'taylor-'.uniqid().'@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    }

    /**
     * @return list<class-string>
     */
    protected function keyringAcknowledgedDangerousSteps(): array
    {
        return $this->acknowledged;
    }

    /**
     * @return list<string>
     */
    protected function keyringAcknowledgedUncheckedRoutes(): array
    {
        return $this->unchecked;
    }

    /**
     * @param  list<string>|string  $middleware
     */
    #[DataProvider('signedInRoutesWithoutTheSessionMiddleware')]
    public function test_the_suite_fails_when_a_signed_in_route_skips_the_session_checks(array|string $middleware, ?string $excluding = null): void
    {
        Route::middleware($middleware)->withoutMiddleware((array) $excluding)->get('/reports/unchecked', fn () => 'reports');

        try {
            $this->test_keyring_checks_the_session_on_every_signed_in_route();
        } catch (AssertionFailedError $failure) {
            $this->assertStringContainsString('without keyring.session', $failure->getMessage());
            $this->assertStringContainsString('reports/unchecked', $failure->getMessage());
            $this->assertStringNotContainsString('user/sessions', $failure->getMessage());

            return;
        }

        $this->fail('A signed-in route without the session middleware went unnoticed.');
    }

    /**
     * @return array<string, list<mixed>>
     */
    public static function signedInRoutesWithoutTheSessionMiddleware(): array
    {
        return [
            'auth for the guard by name' => ['auth:web'],
            'auth for the default guard' => ['auth'],
            'auth for several guards' => ['auth:admin,web'],
            'auth through sanctum for a single-page app' => [[self::STATEFUL, 'auth:sanctum']],
            'a group of its own' => [['api', 'auth:web']],
            'the web group with the middleware taken off' => [['web', 'auth'], AuthenticateSession::class],
        ];
    }

    /**
     * @param  list<string>|string  $middleware
     */
    #[DataProvider('routesTheSessionCheckLeavesAlone')]
    public function test_the_suite_accepts_routes_that_check_the_session_or_do_not_sign_in_to_keyrings_guard(array|string $middleware, string $sanctumGuard = 'web'): void
    {
        config(['sanctum.guard' => [$sanctumGuard]]);
        Route::middleware($middleware)->get('/reports/checked', fn () => 'reports');

        $this->test_keyring_checks_the_session_on_every_signed_in_route();
    }

    /**
     * @return array<string, list<mixed>>
     */
    public static function routesTheSessionCheckLeavesAlone(): array
    {
        return [
            'the web group' => [['web', 'auth']],
            'the alias added to another group' => [['api', 'auth:web', 'keyring.session']],
            'another guard' => ['auth:admin'],
            'sanctum for a single-page app, with the alias added' => [[self::STATEFUL, 'auth:sanctum', 'keyring.session']],
            'sanctum for a single-page app over another guard' => [[self::STATEFUL, 'auth:sanctum'], 'admin'],
            'sanctum tokens, which have no session' => [['api', 'auth:sanctum']],
            'no auth at all' => ['api'],
        ];
    }

    public function test_the_suite_accepts_a_signed_in_route_left_unchecked_on_purpose(): void
    {
        Route::middleware('auth:web')->get('/reports/unchecked', fn () => 'reports');
        $this->unchecked = ['reports/unchecked'];

        $this->test_keyring_checks_the_session_on_every_signed_in_route();
    }

    public function test_the_suite_fails_when_the_app_takes_the_session_middleware_out_and_does_not_add_it_back(): void
    {
        // What "sessions.middleware" => false leaves the web group with.
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('user/sessions');

        $this->test_keyring_checks_the_session_on_every_signed_in_route();
    }

    public function test_the_suite_fails_when_a_mandatory_step_was_taken_out(): void
    {
        Keyring::pipeline(fn (Steps $steps) => $steps->dangerouslyRemove(EnsureNotThrottled::class));

        $this->expectException(AssertionFailedError::class);

        $this->test_keyring_keeps_its_mandatory_pipeline_steps();
    }

    public function test_the_suite_accepts_a_mandatory_step_taken_out_on_purpose(): void
    {
        Keyring::pipeline(fn (Steps $steps) => $steps->dangerouslyRemove(EnsureNotThrottled::class));
        $this->acknowledged = [EnsureNotThrottled::class];

        $this->test_keyring_keeps_its_mandatory_pipeline_steps();
    }
}
