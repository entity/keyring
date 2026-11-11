<?php

use App\Notifications\Keyring\NewDevice;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\RateLimiter as Limiter;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Keyring\Support\Throttle;

// Octane's "octane" cache store is a Swoole table, and a key there holds 63
// bytes. A longer one is refused with a warning, which Laravel throws. The
// rate limiter adds ":timer" to every key it's given.
beforeEach(function () {
    $table = new class extends ArrayStore
    {
        public function put($key, $value, $seconds)
        {
            if (strlen($key) > 63) {
                throw new ErrorException("Swoole\\Table::set(): key[{$key}] is too long");
            }

            return parent::put($key, $value, $seconds);
        }
    };

    Cache::extend('table', fn () => Cache::repository($table));
    config(['cache.stores.table' => ['driver' => 'table'], 'cache.limiter' => 'table']);

    app()->forgetInstance(Limiter::class);
    RateLimiter::clearResolvedInstance(Limiter::class);

    $this->user = taylor();
});

it('counts a security notice under a key a Swoole table can hold', function () {
    Notification::fake();
    sendNotifications();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

    Notification::assertSentToTimes($this->user, NewDevice::class, 1);

    // The longest kind there is, to an address rather than an account.
    foreach (range(1, 5) as $notice) {
        expect(app(Throttle::class)->notifying('email_change_reverted', 'mail:someone@example.com'))->toBeNull();
    }

    expect(app(Throttle::class)->notifying('email_change_reverted', 'mail:someone@example.com'))->toBeGreaterThan(0)
        ->and(app(Throttle::class)->notifying('email_change_reverted', 'mail:another@example.com'))->toBeNull();
});

it('counts the codes sent to an account with a UUID under a key a Swoole table can hold', function () {
    $throttle = app(Throttle::class);

    foreach (range(1, 3) as $code) {
        $throttle->sending('email-code', '0193a5e2-7c1b-7d3a-9f0e-2b6c4d8e1f00');
    }

    // Another account's count, and another factor's, are their own.
    $throttle->sending('email-code', '0193a5e2-7c1b-7d3a-9f0e-2b6c4d8e1f01');
    $throttle->sending('sms-code', '0193a5e2-7c1b-7d3a-9f0e-2b6c4d8e1f00');

    expect(fn () => $throttle->sending('email-code', '0193a5e2-7c1b-7d3a-9f0e-2b6c4d8e1f00'))->toThrow(ValidationException::class);
});

it('locks an account out and clears its limits under keys a Swoole table can hold', function () {
    config(['keyring.limits.per_account' => 2]);

    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'nope'])->assertStatus(422);
    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'nope'])->assertStatus(422);
    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertStatus(429);

    app(Throttle::class)->clearAccount($this->user);
    app(Throttle::class)->forgetBrowsers($this->user);

    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertOk();
});
