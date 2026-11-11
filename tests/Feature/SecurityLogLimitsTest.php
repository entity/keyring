<?php

use Illuminate\Auth\Events\Lockout as LaravelLockout;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Keyring\Enums\Severity;
use Keyring\Events\Lockout;
use Keyring\Models\SecurityEvent;

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

    expect(SecurityEvent::query()->where('type', 'locked_out')->pluck('ip')->all())->toBe(['127.0.0.1', '203.0.113.9']);
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
