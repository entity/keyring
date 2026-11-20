<?php

declare(strict_types=1);

namespace Keyring\Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as PlainAuthenticatable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\SessionRegistry;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Features;
use Keyring\Http\Middleware\AuthenticateSession;
use Keyring\Pipeline\Steps;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Sessions\DatabaseSessionRegistry;
use Keyring\Sessions\RegisteredSession;
use Keyring\Testing\KeyringConformance;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\TestCase;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\SkippedTest;

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

    /** Keyring's own tests run on Laravel's default hasher. */
    private bool $acknowledgesBcrypt = true;

    /** A user model that was never given the HasKeyring trait. */
    private bool $userWithoutKeyring = false;

    protected function setUp(): void
    {
        parent::setUp();

        Notification::fake();
        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys(), Totp::class, EmailCode::asExtraStep(), RecoveryCodes::class]);
    }

    protected function keyringUser(): Authenticatable&Model
    {
        if ($this->userWithoutKeyring) {
            $user = new #[Unguarded] #[Table(name: 'users')] class extends PlainAuthenticatable {};

            return $user->newQuery()->create(['name' => 'Taylor', 'email' => 'taylor-'.uniqid().'@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        }

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

    protected function keyringAcknowledgesBcryptLimit(): bool
    {
        return $this->acknowledgesBcrypt;
    }

    public function test_the_suite_fails_while_bcrypt_limits_passwords_to_72_bytes(): void
    {
        $this->acknowledgesBcrypt = false;

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Set HASH_DRIVER=argon2id');

        $this->test_keyring_takes_passwords_of_64_characters();
    }

    public function test_the_suite_passes_with_a_hasher_that_reads_a_whole_password(): void
    {
        $this->acknowledgesBcrypt = false;
        config(['hashing.driver' => 'argon2id']);

        $this->test_keyring_takes_passwords_of_64_characters();
    }

    public function test_the_suite_fails_when_the_longest_password_allowed_is_under_64_characters(): void
    {
        config(['keyring.passwords.max' => 63]);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('keyring.passwords.max');

        $this->test_keyring_takes_passwords_of_64_characters();
    }

    /**
     * @param  array<string, mixed>  $config
     */
    #[DataProvider('brokersWithoutAThrottle')]
    public function test_the_suite_fails_when_reset_links_are_not_limited_per_account(array $config, string $names): void
    {
        if (! Features::enabled(Features::resetPasswords())) {
            $this->markTestSkipped('Password resets are off.');
        }

        config($config);

        try {
            $this->test_keyring_limits_how_often_an_account_is_sent_a_reset_link();
        } catch (AssertionFailedError $failure) {
            $this->assertStringContainsString($names, $failure->getMessage());

            return;
        }

        $this->fail('A broker without a throttle went unnoticed.');
    }

    /**
     * @return array<string, list<mixed>>
     */
    public static function brokersWithoutAThrottle(): array
    {
        $staff = ['provider' => 'users', 'table' => 'password_reset_tokens', 'expire' => 60];

        return [
            'no throttle' => [['auth.passwords.users.throttle' => null], 'auth.passwords.users.throttle'],
            'a throttle of nothing' => [['auth.passwords.users.throttle' => 0], 'auth.passwords.users.throttle'],
            'the setting left out' => [['auth.passwords.users' => ['provider' => 'users', 'table' => 'password_reset_tokens', 'expire' => 60]], 'auth.passwords.users.throttle'],
            'the broker keyring was told to use' => [['auth.passwords.staff' => $staff, 'keyring.passwords.broker' => 'staff'], 'auth.passwords.staff.throttle'],
        ];
    }

    public function test_the_suite_fails_when_a_password_hash_takes_longer_than_the_timebox(): void
    {
        // Shorter than any hash at the cost production would run.
        config(['keyring.timebox' => '1ms']);

        try {
            $this->test_keyring_holds_a_refusal_for_longer_than_a_password_hash_takes();
        } catch (AssertionFailedError $failure) {
            $this->assertStringContainsString('keyring.timebox is 1ms', $failure->getMessage());

            return;
        }

        $this->fail('A timebox shorter than a password hash went unnoticed.');
    }

    public function test_the_suite_times_a_hash_at_the_cost_production_runs_not_the_test_suites(): void
    {
        // What phpunit.xml gives the tests, and a new app's own setting.
        config(['hashing.bcrypt.rounds' => 4]);
        $this->assertSame(['rounds' => 12], $this->keyringProductionHashOptions());

        config(['hashing.bcrypt.rounds' => 14]);
        $this->assertSame(['rounds' => 14], $this->keyringProductionHashOptions());

        config(['hashing.driver' => 'argon2id']);
        $this->assertSame([], $this->keyringProductionHashOptions());
    }

    public function test_the_suite_reads_the_throttle_of_the_broker_keyring_uses(): void
    {
        // The default broker has none, and it isn't the one that sends Keyring's links.
        config([
            'auth.passwords.users.throttle' => 0,
            'auth.passwords.staff' => ['provider' => 'users', 'table' => 'password_reset_tokens', 'expire' => 60, 'throttle' => 30],
            'keyring.passwords.broker' => 'staff',
        ]);

        $this->test_keyring_limits_how_often_an_account_is_sent_a_reset_link();
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

    public function test_the_suite_fails_when_the_user_model_does_not_guard_its_email_and_password(): void
    {
        if (Keyring::protectedAttributes() === []) {
            $this->markTestSkipped('Nothing is protected.');
        }

        $this->userWithoutKeyring = true;

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('attribute changed outside a Keyring flow');

        $this->test_keyring_protects_email_and_password();
    }

    #[DataProvider('checksForWhatIsTurnedOff')]
    public function test_the_suite_skips_a_check_for_what_the_app_has_turned_off_and_says_how_to_turn_it_on(string $check, string $reason): void
    {
        config(['keyring.features' => [], 'keyring.protected' => []]);

        try {
            $this->{$check}();
        } catch (SkippedTest $skipped) {
            $this->assertStringContainsString($reason, $skipped->getMessage());

            return;
        }

        $this->fail("The [{$check}] check ran with what it checks turned off.");
    }

    /**
     * @return array<string, list<string>>
     */
    public static function checksForWhatIsTurnedOff(): array
    {
        return [
            'reset links' => ['test_keyring_limits_how_often_an_account_is_sent_a_reset_link', 'turn on Features::resetPasswords()'],
            'registration' => ['test_keyring_registers_a_taken_address_like_a_free_one', 'Registration is off'],
            'protected attributes' => ['test_keyring_protects_email_and_password', 'Features::updatePasswords() protects the password'],
            'fresh verification' => ['test_keyring_requires_a_fresh_verification_to_change_sign_in_methods', 'turn on Features::manageAuthenticators()'],
            'enrolling' => ['test_keyring_lets_every_enrollable_factor_begin_enrolling', 'turn on Features::manageAuthenticators()'],
        ];
    }

    #[DataProvider('registriesThatDoNotReturnWhatTheyRevoke')]
    public function test_the_suite_fails_when_the_registry_does_not_return_what_it_revoked(string $broken, string $message): void
    {
        app()->instance(SessionRegistry::class, new class(app('db')->connection(), $broken) extends DatabaseSessionRegistry
        {
            /** @var Collection<int, RegisteredSession> */
            private Collection $last;

            public function __construct(ConnectionInterface $connection, private readonly string $broken)
            {
                parent::__construct($connection);
            }

            public function revoke(string $id): ?RegisteredSession
            {
                $revoked = parent::revoke($id);

                return match ($this->broken) {
                    'nothing from revoke' => null,
                    'revoke as it was read' => $revoked?->with(['revokedAt' => null]),
                    'revoke every time' => $revoked ?? $this->find($id),
                    default => $revoked,
                };
            }

            public function revokeAll(Authenticatable $user, ?string $except = null): Collection
            {
                $revoked = parent::revokeAll($user, $except);

                return $this->last = match ($this->broken) {
                    'nothing from revokeAll' => new Collection,
                    'revokeAll as they were read' => $revoked->map(fn (RegisteredSession $session) => $session->with(['revokedAt' => null])),
                    'revokeAll every time' => $revoked->isEmpty() ? $this->last : $revoked,
                    default => $revoked,
                };
            }
        });

        try {
            $this->test_keyring_registry_returns_the_sessions_it_revokes();
        } catch (AssertionFailedError $failure) {
            $this->assertStringContainsString($message, $failure->getMessage());

            return;
        }

        $this->fail('A registry that doesn\'t return what it revoked went unnoticed.');
    }

    /**
     * @return array<string, list<string>>
     */
    public static function registriesThatDoNotReturnWhatTheyRevoke(): array
    {
        return [
            'nothing from revoke' => ['nothing from revoke', 'revoke() should return the record it revoked'],
            'the record from revoke as it was' => ['revoke as it was read', 'revoke() should return the record as it now stands'],
            'the record from revoke every time' => ['revoke every time', 'revoke() should return null for a record that was revoked already'],
            'nothing from revokeAll' => ['nothing from revokeAll', 'revokeAll() should return every record it revoked'],
            'the records from revokeAll as they were' => ['revokeAll as they were read', 'revokeAll() should return each record as it now stands'],
            'the records from revokeAll every time' => ['revokeAll every time', 'revokeAll() should return nothing when it revoked nothing'],
        ];
    }

    /**
     * An app that uses the suite and overrides nothing has acknowledged
     * nothing: every removed step, unchecked route and bcrypt hash fails.
     */
    public function test_the_suite_acknowledges_nothing_an_app_has_not_listed(): void
    {
        $suite = new class('defaults') extends TestCase
        {
            use KeyringConformance;

            protected function keyringUser(): User
            {
                return User::create(['name' => 'Taylor', 'email' => 'taylor-'.uniqid().'@example.com', 'password' => 'password', 'email_verified_at' => now()]);
            }
        };

        Keyring::pipeline(fn (Steps $steps) => $steps->dangerouslyRemove(EnsureNotThrottled::class));
        Route::middleware('auth:web')->get('/reports/unchecked', fn () => 'reports');

        foreach ([
            'test_keyring_keeps_its_mandatory_pipeline_steps' => 'Mandatory pipeline steps were removed or replaced',
            'test_keyring_checks_the_session_on_every_signed_in_route' => 'reports/unchecked',
            'test_keyring_takes_passwords_of_64_characters' => 'hashed with bcrypt',
        ] as $check => $message) {
            try {
                $suite->{$check}();
            } catch (AssertionFailedError $failure) {
                $this->assertStringContainsString($message, $failure->getMessage());

                continue;
            }

            $this->fail("The [{$check}] check let through what the app never acknowledged.");
        }
    }
}
