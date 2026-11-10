<?php

use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Enrollment\Enrollment;
use Keyring\Models\Device;
use Keyring\Pipeline\ConsecutiveLimit;
use Keyring\Support\Throttle;
use Keyring\Tests\Fixtures\User;

function device(User $user, array $attributes = []): Device
{
    return tap(Device::make(['token_hash' => Device::hashToken(Str::random()), 'first_seen_at' => now(), 'last_seen_at' => now(), ...$attributes])->authenticatable()->associate($user))->save();
}

it('sends as many codes as the app allows, as often as it allows', function () {
    config(['keyring.limits.codes' => 1, 'keyring.limits.codes_per' => '1m']);

    Throttle::sending('sms', 1);
    expect(fn () => Throttle::sending('sms', 1))->toThrow(ValidationException::class);

    $this->travel(61)->seconds();
    Throttle::sending('sms', 1);
});

it('gives users as long to finish adding a sign-in method as the app says', function () {
    config(['keyring.enrollments.keep_for' => '1h']);

    expect(Enrollment::make('totp')->expiresAt)->toBe(now()->addHour()->getTimestamp());
});

it('forgets failures in a row after as long as the app says', function () {
    config(['keyring.limits.remember_failures_for' => '1d']);

    expect(ConsecutiveLimit::of(100, 'totp', '1')->decaySeconds)->toBe(86400);
});

it('prunes devices on the app\'s schedule', function () {
    config(['keyring.devices.keep_unseen_for' => '10d']);
    $user = taylor();
    device($user, ['last_seen_at' => now()->subDays(5)]);
    $stale = device($user, ['last_seen_at' => now()->subDays(11)]);

    expect((new Device)->prunable()->pluck('id')->all())->toBe([$stale->id]);
});

it('signs "this wasn\'t me" links for as long as the app says', function () {
    config(['keyring.devices.report_link_for' => '2d']);
    $device = device(taylor());

    parse_str((string) parse_url($device->revokeUrl(), PHP_URL_QUERY), $query);

    expect((int) $query['expires'])->toBe(now()->addDays(2)->getTimestamp());
});
