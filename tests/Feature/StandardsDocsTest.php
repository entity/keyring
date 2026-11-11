<?php

declare(strict_types=1);

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
use Keyring\Console\InstallCommand;
use Keyring\Support\Duration;

// docs/owasp-asvs.md says what a default install gives an app and where
// every requirement stands. These keep what it says about the defaults true
// of the code, and the page complete.
beforeEach(function () {
    $this->page = file_get_contents(__DIR__.'/../../docs/owasp-asvs.md');
    $this->defaults = require __DIR__.'/../../config/keyring.php';

    // What keyring:install writes with its default answers.
    $this->provider = (fn () => $this->provider(new Filesystem, [], true, false))->call(new InstallCommand);
});

it('lists the features a default install turns on', function () {
    preg_match('/^- (\w+) features: (.+),$/m', $this->page, $line);

    $listed = Str::matchAll('/`([a-z-]+)`/', $line[2])->all();

    expect($listed)->toBe($this->defaults['features'])->toHaveCount(5)
        ->and($line[1])->toBe('five');
});

it('counts the security emails and risk signals a default install registers', function () {
    $notices = Str::matchAll("/^ +'([a-z_]+)' => Notifications/m", $this->provider)
        ->reject(fn (string $type) => in_array($type, ['verification_code', 'confirm_email_change', 'email_change_notice', 'email_address_in_use', 'already_registered'], true))
        ->values();
    $signals = Str::matchAll('/^ +Signals\\\\(\w+)::class,$/m', $this->provider);

    preg_match('/^- (\w+) \[security emails\]\([^)]+\): (.+),$/m', $this->page, $emails);
    preg_match('/^- (\w+) \[risk signals\]\([^)]+\): (.+),$/m', $this->page, $risk);

    expect($notices->all())->toBe(['password_changed', 'authenticator_added', 'authenticator_removed', 'recovery_code_used', 'recovery_codes_generated', 'email_changed', 'account_locked', 'suspicious_activity'])
        ->and($emails[1])->toBe('eight')
        // One phrase for each, in the order the provider lists them.
        ->and(preg_split('/, (?:and )?/', $emails[2]))->toHaveCount($notices->count())
        ->and($signals->all())->toBe(['SessionFingerprintChanged', 'RepeatedFactorFailures', 'SuccessAfterFailures'])
        ->and($risk[1])->toBe('three')
        ->and(preg_split('/, (?:and )?/', $risk[2]))->toHaveCount($signals->count());
});

it('gives the session limits the config ships with', function () {
    $sessions = $this->defaults['sessions'];

    expect($this->page)->toContain('a two hour inactivity limit (14 days for a browser that ticked "remember me"), a 30 day limit overall and a limit of 100 sessions per account')
        ->and(Duration::seconds($sessions['idle']))->toBe(2 * 3600)
        ->and(Duration::seconds($sessions['remember_idle']))->toBe(14 * 86400)
        ->and(Duration::seconds($sessions['absolute']))->toBe(30 * 86400)
        ->and($sessions['max'])->toBe(100)
        ->and($sessions['levels'])->toBe(['aal2' => ['idle' => '1h', 'absolute' => '24h'], 'aal3' => ['idle' => '15m', 'absolute' => '12h']])
        ->and($sessions['end_on_lapse'])->toBeFalse()
        ->and($this->defaults['limits']['consecutive'])->toBe(100)
        ->and($this->defaults['passwords']['min_without_mfa'])->toBe(15)
        ->and($this->defaults['passwords']['min_with_mfa'])->toBe(8)
        ->and($this->defaults['support_contact'])->toBeNull();
});

it('has a row for every requirement of ASVS 5.0.0 chapters V6 and V7, each with a status the page defines', function () {
    $requirements = [
        '6.1' => 3, '6.2' => 12, '6.3' => 8, '6.4' => 6, '6.5' => 8, '6.6' => 4, '6.7' => 2, '6.8' => 4,
        '7.1' => 3, '7.2' => 4, '7.3' => 2, '7.4' => 5, '7.5' => 3, '7.6' => 2,
    ];

    preg_match_all('/^\| \*\*([^*]+)\*\* \| /m', Str::between($this->page, "## Introduction\n", "\n## What a Default Install"), $legend);
    preg_match_all('/^\| ((?:6|7)\.\d+\.\d+) [^|]+\| (\d) \| ([^|]+) \|/m', $this->page, $rows, PREG_SET_ORDER);

    $expected = collect($requirements)->flatMap(fn (int $count, string $section) => array_map(fn (int $n) => "{$section}.{$n}", range(1, $count)));
    $statuses = collect($rows)->mapWithKeys(fn (array $row) => [$row[1] => trim($row[3])]);

    expect($expected)->toHaveCount(66)
        ->and($statuses->keys()->all())->toBe($expected->all())
        ->and($statuses->unique()->diff($legend[1])->values()->all())->toBe([]);
});

it('uses only those statuses in its other tables', function () {
    preg_match_all('/^\| \*\*([^*]+)\*\* \| /m', Str::between($this->page, "## Introduction\n", "\n## What a Default Install"), $legend);

    $tables = Str::between($this->page, "### The Other Chapters\n", "\n## What Is Left to Your App");
    preg_match_all('/^\|(?: [^|]+\|){1,2} (Met by default|Met|Needs setup|Partly|Deviates|Yours|N\/A|[A-Z][a-z]+(?: [a-z]+)*) \| [^|]+\|$/m', $tables, $rows);

    expect(count($rows[1]))->toBeGreaterThan(80)
        ->and(array_values(array_diff(array_unique($rows[1]), $legend[1])))->toBe([]);
});
