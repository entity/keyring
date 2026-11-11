<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Lockout as LaravelLockout;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\RateLimiter;
use Keyring\Enums\Severity;
use Keyring\Events\Lockout;
use Keyring\Events\RateLimited;
use Keyring\Models\SecurityEvent;
use Keyring\Support\TooManyAttempts;

beforeEach(function () {
    $this->user = taylor();
});

it('logs a lock once when it starts, not for every request it refuses', function () {
    $refused = ['keyring' => 0, 'laravel' => 0];
    Event::listen(function (Lockout $event) use (&$refused) {
        $refused['keyring']++;
    });
    Event::listen(function (LaravelLockout $event) use (&$refused) {
        $refused['laravel']++;
    });

    foreach (range(1, 12) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    }

    // The events still fire for each refused request, as documented.
    expect(array_count_values(loggedTypes()))->toBe(['factor_failed' => 5, 'locked_out' => 1])
        ->and($refused)->toBe(['keyring' => 7, 'laravel' => 7])
        ->and(logEntry('locked_out'))->factor->toBe('password')->severity->toBe(Severity::Warning)
        ->and(logEntry('locked_out')->meta['retry_after'])->toBeGreaterThan(0);
});

it('logs the next lock once the first is over', function () {
    foreach (range(1, 8) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    }

    $this->travel(61)->seconds();

    foreach (range(1, 8) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    }

    expect(SecurityEvent::query()->where('type', 'locked_out')->count())->toBe(2);
});

it('logs a lock for each address it turns away', function () {
    foreach (range(1, 8) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    }

    foreach (range(1, 3) as $attempt) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    }

    expect(SecurityEvent::query()->where('type', 'locked_out')->oldest('id')->pluck('ip')->all())->toBe(['127.0.0.1', '203.0.113.9']);
});

it('keeps only so many failures for names nobody has from one address', function () {
    config(['keyring.limits.per_ip' => 1000, 'keyring.security_log.refusals' => 3]);

    foreach (range(1, 10) as $attempt) {
        $this->post('/login', ['email' => "nobody{$attempt}@example.com", 'password' => 'wrong']);
    }

    expect(loggedTypes())->toBe(['factor_failed', 'factor_failed', 'factor_failed', 'refusals_limited'])
        ->and(logEntry('refusals_limited'))->meta->toBe(['type' => 'factor_failed'])->ip->toBe('127.0.0.1')->severity->toBe(Severity::Warning);

    // Another address has its own count, and this one's starts again later.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->post('/login', ['email' => 'nobody@example.com', 'password' => 'wrong']);
    $this->travel(61)->minutes();
    $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'wrong']);

    expect(SecurityEvent::query()->where('type', 'factor_failed')->count())->toBe(5);
});

it('still logs every failure for an account, which its own limits already bound', function () {
    config(['keyring.limits.per_account' => 50, 'keyring.security_log.refusals' => 3]);

    foreach (range(1, 10) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    }

    expect(array_count_values(loggedTypes()))->toBe(['factor_failed' => 10]);
});

it('keeps every refusal when the app sets no limit', function () {
    config(['keyring.limits.per_ip' => 1000, 'keyring.security_log.refusals' => null]);

    foreach (range(1, 30) as $attempt) {
        $this->post('/login', ['email' => "nobody{$attempt}@example.com", 'password' => 'wrong']);
    }

    expect(array_count_values(loggedTypes()))->toBe(['factor_failed' => 30]);
});

it('limits the app\'s log the same way when the table is off', function () {
    config(['logging.default' => 'memory', 'keyring.limits.per_ip' => 1000, 'keyring.security_log.refusals' => 2]);
    $log = logTo();
    withFeatures([]);

    foreach (range(1, 12) as $attempt) {
        $this->post('/login', ['email' => "nobody{$attempt}@example.com", 'password' => 'wrong']);
    }

    expect(array_column(written($log), 1))->toBe(['factor_failed', 'factor_failed', 'refusals_limited']);
});

// OWASP ASVS 5.0.0, 16.3.3: a control that refuses is logged. The form
// limiter is one, on the routes the sign-in limits don't cover.
describe('the form limiter', function () {
    it('logs once when it starts refusing, and answers as it always did', function () {
        $refused = 0;
        Event::listen(function (RateLimited $event) use (&$refused) {
            $refused++;
        });

        // The limiter counts a request before anything looks at it, so an
        // empty form fills it as well as a real one.
        $statuses = array_map(fn () => $this->postJson('/forgot-password')->getStatusCode(), range(1, 9));
        $last = $this->postJson('/forgot-password', ['email' => 'nobody@example.com']);

        expect($statuses)->toBe([422, 422, 422, 422, 422, 422, 429, 429, 429])
            ->and($refused)->toBe(4)
            ->and(logEntry('rate_limited'))
            ->severity->toBe(Severity::Warning)
            ->authenticatable_id->toBeNull()
            ->ip->toBe('127.0.0.1')
            ->and(logEntry('rate_limited')->meta)->toMatchArray(['limiter' => 'keyring', 'route' => 'password.email'])
            ->and(logEntry('rate_limited')->meta['retry_after'])->toBeGreaterThan(0)->toBeLessThanOrEqual(60);

        // Laravel's own answer, as before.
        $last->assertStatus(429)->assertHeader('Retry-After')->assertHeader('X-RateLimit-Limit', '6')->assertJsonPath('message', 'Too Many Attempts.');
    });

    it('logs it against the account when someone is signed in', function () {
        Notification::fake();
        // Where an account can be signed in before its address is verified.
        revealTakenAddresses();
        $this->user->forceFill(['email_verified_at' => null])->save();
        $this->actingAs($this->user);

        foreach (range(1, 8) as $request) {
            $this->post(route('verification.send'));
        }

        expect(logEntry('rate_limited'))->authenticatable_id->toBe($this->user->id)
            ->and(logEntry('rate_limited')->meta)->toMatchArray(['limiter' => 'keyring', 'route' => 'verification.send']);
    });

    it('logs the limit on passkey options too', function () {
        foreach (range(1, 63) as $request) {
            $this->getJson(route('keyring.login.options', 'passkey'));
        }

        expect(logEntry('rate_limited')->meta)->toMatchArray(['limiter' => 'keyring-login-options', 'route' => 'keyring.login.options']);
    });

    it('logs again once the wait is over, and for each address it turns away', function () {
        $fill = fn (string $ip = '127.0.0.1') => array_map(fn () => $this->withServerVariables(['REMOTE_ADDR' => $ip])->post('/forgot-password'), range(1, 8));

        $fill();
        $fill('203.0.113.9');
        $this->travel(61)->seconds();
        $fill();

        expect(SecurityEvent::query()->where('type', 'rate_limited')->oldest('id')->pluck('ip')->all())->toBe(['127.0.0.1', '203.0.113.9', '127.0.0.1']);
    });

    it('cannot be used to fill the log', function () {
        config(['keyring.security_log.refusals' => 2]);

        // A minute apart, so each round is a refusal the log hasn't noted.
        foreach (range(1, 5) as $round) {
            array_map(fn () => $this->post('/forgot-password'), range(1, 7));
            $this->travel(61)->seconds();
        }

        expect(loggedTypes())->toBe(['rate_limited', 'rate_limited', 'refusals_limited']);
    });

    it('logs for a limiter of the app\'s own that answers the same way, and not for one that doesn\'t', function (bool $logs) {
        RateLimiter::for('keyring', fn (Request $request) => $logs
            ? Limit::perMinute(2)->by($request->ip())->response(new TooManyAttempts('keyring'))
            : Limit::perMinute(2)->by($request->ip()));

        $statuses = array_map(fn () => $this->post('/forgot-password')->getStatusCode(), range(1, 3));

        expect($statuses)->toBe([302, 302, 429])
            ->and(SecurityEvent::query()->where('type', 'rate_limited')->count())->toBe($logs ? 1 : 0);
    })->with([true, false]);
});
