<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Str;
use Keyring\Activity\SecurityLog;
use Keyring\Enums\Severity;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Models\Authenticator;
use Keyring\Models\SecurityEvent;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\LogRecord;

beforeEach(function () {
    $this->user = taylor();
});

/**
 * A second request: each one starts with nothing in Laravel's Context.
 */
function nextRequest(): void
{
    Context::flush();
}

it('records sign ins, failures, lockouts and sign outs with the package\'s own config', function () {
    $defaults = require __DIR__.'/../../config/keyring.php';
    config(['keyring' => $defaults]);
    withFeatures($defaults['features']);

    foreach (range(1, 6) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    }

    $this->travel(2)->minutes();
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    $this->post('/logout');

    expect(array_count_values(loggedTypes()))->toBe(['factor_failed' => 5, 'locked_out' => 1, 'signed_in' => 1, 'signed_out' => 1])
        ->and(logEntry('signed_in')->meta)->toBe(['factors' => ['password']]);
});

it('writes to the app\'s log when the table is turned off, so something always records it', function () {
    config(['logging.default' => 'memory']);
    $log = logTo();
    withFeatures([]);

    $this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    $this->post('/logout');

    $lines = written($log);

    expect(SecurityEvent::count())->toBe(0)
        ->and(array_map(fn (array $line) => [$line[0], $line[1]], $lines))->toBe([
            ['warning', 'factor_failed'], ['info', 'signed_in'], ['info', 'signed_out'],
        ])
        ->and($lines[0][2])->toMatchArray(['user' => $this->user->getMorphClass().':'.$this->user->id, 'factor' => 'password', 'ip' => '127.0.0.1', 'user_agent' => FIREFOX])
        ->and($lines[0][2]['request_id'])->toBeString()
        ->and($lines[1][2]['meta'])->toBe(['factors' => ['password']]);
});

it('writes to the channel the app names', function () {
    $default = logTo('default-channel');
    $security = logTo('security');
    config(['logging.default' => 'default-channel', 'keyring.security_log.channel' => 'security']);
    withFeatures([]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    expect(array_column(written($security), 1))->toBe(['signed_in'])
        ->and(written($default))->toBe([]);
});

it('writes an entry the table would not take to the app\'s log instead', function () {
    Exceptions::fake();
    config(['logging.default' => 'memory']);
    $log = logTo();
    Keyring::useSecurityEventModel(MissingSecurityEvent::class);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertSessionHasErrors('email');

    expect(array_column(written($log), 1))->toBe(['factor_failed']);
    Exceptions::assertReportedCount(1);
});

it('logs a bypass to the app\'s log with the table off, and refuses it when that fails too', function () {
    config(['logging.default' => 'memory']);
    $log = logTo();
    withFeatures([]);

    Keyring::withoutProtection(fn () => null, reason: 'support ticket 42');

    expect(written($log))->toBe([['warning', 'protection_bypassed', ['ip' => '127.0.0.1', 'user_agent' => 'Symfony', 'request_id' => Context::getHidden(SecurityLog::REQUEST_ID), 'meta' => ['reason' => 'support ticket 42']]]]);

    config(['logging.default' => 'broken', 'logging.channels.broken' => ['driver' => 'monolog', 'handler' => BrokenLogHandler::class]]);
    $ran = false;

    expect(fn () => Keyring::withoutProtection(function () use (&$ran) {
        $ran = true;
    }))->toThrow(RuntimeException::class, 'The log is down.')
        ->and($ran)->toBeFalse();
});

it('never keeps what was typed, in the table or the app\'s log', function (array $features) {
    config(['logging.default' => 'memory']);
    $log = logTo();
    withFeatures($features);
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a-wrong-passphrase']);
    $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'a-wrong-passphrase']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => '135790']);
    $this->post(route('password.update'), ['token' => 'a-made-up-reset-token', 'email' => 'taylor@example.com', 'password' => 'another-long-passphrase']);

    $kept = SecurityEvent::all()->toJson().json_encode(array_map(fn (LogRecord $record) => $record->toArray(), $log->getRecords()));

    expect($kept)->toContain('factor_failed')
        ->not->toContain('a-wrong-passphrase')
        ->not->toContain('another-long-passphrase')
        ->not->toContain('135790')
        ->not->toContain('a-made-up-reset-token')
        ->not->toContain('nobody@example.com')
        ->not->toContain(session()->getId())
        ->not->toContain(csrf_token());
})->with([
    'in the table' => [[Features::securityLog(), Features::resetPasswords()]],
    'in the app\'s log' => [[Features::resetPasswords()]],
]);

it('gives the entries one request wrote the same request ID, and the next request another', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);

    nextRequest();
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);

    $ids = SecurityEvent::query()->oldest('id')->get()->mapToGroups(fn (SecurityEvent $event) => [$event->request_id => $event->type]);

    expect($ids->map->all()->values()->all())->toBe([['factor_failed', 'second_factor_failed'], ['factor_failed']])
        ->and($ids->keys()->every(fn (string $id) => Str::isUuid($id)))->toBeTrue();
});

it('uses the ID the app already gave the request, rather than a second one', function () {
    Context::add('trace_id', 'the-apps-own-id');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);

    expect(logEntry('factor_failed')->request_id)->toBe('the-apps-own-id')
        ->and(Context::get('trace_id'))->toBe('the-apps-own-id');
});

it('reads the ID from wherever the app keeps it, hidden or not', function () {
    config(['keyring.security_log.context_key' => 'request_id']);
    Context::add('trace_id', 'not-this-one');
    Context::addHidden('request_id', 'kept-out-of-the-logs');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);

    expect(logEntry('factor_failed')->request_id)->toBe('kept-out-of-the-logs');
});

it('keeps an ID of its own out of the app\'s log lines', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);

    expect(Context::all())->toBe([])
        ->and(Context::getHidden(SecurityLog::REQUEST_ID))->toBe(logEntry('factor_failed')->request_id);
});

it('keeps an ID that is too long for the column short, and leaves it out when the app wants none', function () {
    Context::add('trace_id', str_repeat('a', 200));
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);

    config(['keyring.security_log.context_key' => null]);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    expect(logEntry('factor_failed')->request_id)->toBe(str_repeat('a', 64))
        ->and(logEntry('signed_in')->request_id)->toBeNull();
});

it('classifies each entry by severity', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    app(SecurityLog::class)->record('exported_data', $this->user);
    app(SecurityLog::class)->record('exported_everything', $this->user, severity: Severity::Critical);

    expect(SecurityEvent::query()->oldest('id')->get()->mapWithKeys(fn (SecurityEvent $event) => [$event->type => $event->severity])->all())->toBe([
        'factor_failed' => Severity::Warning,
        'signed_in' => Severity::Info,
        'new_device' => Severity::Notice,
        'exported_data' => Severity::Info,
        'exported_everything' => Severity::Critical,
    ]);
});

// Every query fails, as if the table were gone, without DDL that MySQL would commit.
#[Table('keyring_events_missing')]
class MissingSecurityEvent extends SecurityEvent {}

class BrokenLogHandler extends AbstractProcessingHandler
{
    protected function write(LogRecord $record): void
    {
        throw new RuntimeException('The log is down.');
    }
}
