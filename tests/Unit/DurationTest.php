<?php

declare(strict_types=1);

use Keyring\Support\Duration;

it('reads seconds, minutes, hours and days as seconds', function () {
    expect(Duration::seconds(90))->toBe(90)
        ->and(Duration::seconds('90'))->toBe(90)
        ->and(Duration::seconds('30s'))->toBe(30)
        ->and(Duration::seconds('15m'))->toBe(900)
        ->and(Duration::seconds('12h'))->toBe(43200)
        ->and(Duration::seconds('7d'))->toBe(604800);
});

it('reads milliseconds and longer units as milliseconds', function () {
    expect(Duration::milliseconds('250ms'))->toBe(250)
        ->and(Duration::milliseconds('60s'))->toBe(60_000)
        ->and(Duration::milliseconds('2m'))->toBe(120_000);
});

it('refuses a millisecond duration without a unit', function (string|int $duration) {
    Duration::milliseconds($duration);
})->with([250_000, '250000', ' 60 '])->throws(InvalidArgumentException::class, 'needs a unit');

it('refuses a duration it can\'t read', function () {
    Duration::seconds('soon');
})->throws(InvalidArgumentException::class);
