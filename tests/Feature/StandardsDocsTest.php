<?php

declare(strict_types=1);

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
use Keyring\Changes\ProtectedAttributes;
use Keyring\Console\InstallCommand;
use Keyring\Factors\FactorRegistry;
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\Support\Duration;

// docs/owasp-asvs.md says what a default install gives an app and where
// every requirement stands. These keep what it says about the defaults true
// of the code, and the page complete.
beforeEach(function () {
    $this->page = file_get_contents(__DIR__.'/../../docs/owasp-asvs.md');
    $this->defaults = require __DIR__.'/../../config/keyring.php';

    // What keyring:install sets up with its default answers: the password
    // alone, and the features the config ships with.
    $this->features = $this->defaults['features'];
    $this->provider = (fn () => $this->provider(new Filesystem, [], false, test()->features))->call(new InstallCommand);
});

it('lists the features a default install turns on', function () {
    preg_match('/^- (\w+) features: (.+),$/m', $this->page, $line);

    $listed = Str::matchAll('/`([a-z-]+)`/', $line[2])->all();

    expect($listed)->toBe($this->features)->toHaveCount(5)
        ->and($line[1])->toBe('five');
});

it('says a default install has the password alone, with the rest there to turn on, which is what the installer writes', function () {
    preg_match_all('/^ +(\/\/ )?Factors\\\\(\w+)::/m', $this->provider, $lines, PREG_SET_ORDER);

    expect($this->page)->toContain('- the password as the only sign-in method,')
        ->toContain("It doesn't cover Level 2.")
        ->toContain('| 6.3.3 Multi-factor authentication is required; a hardware factor at Level 3 | 2 | Needs setup | A default install has no second factor to require.')
        ->and(array_column(array_filter($lines, fn (array $line) => $line[1] === ''), 2))->toBe(['Password'])
        ->and(array_column(array_filter($lines, fn (array $line) => $line[1] !== ''), 2))->toBe(['Totp', 'RecoveryCodes', 'WebAuthn', 'WebAuthn', 'EmailCode'])
        ->and($this->provider)->toContain("        // \$this->app->make(\Illuminate\Contracts\Http\Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');");
});

it('counts the security emails Keyring sends and the risk signals a default install registers', function () {
    // What Keyring sends before an app changes anything.
    $keyring = new KeyringManager(new FactorRegistry, app(ProtectedAttributes::class));
    $notices = collect(KeyringManager::NOTIFICATIONS)
        ->reject(fn (string $type) => in_array($type, ['verification_code', 'confirm_email_change', 'email_change_notice', 'email_address_in_use', 'already_registered'], true))
        ->filter(fn (string $type) => $keyring->hasNotification($type))
        ->values();
    $signals = Str::matchAll('/^ +Signals\\\\(\w+)::class,$/m', $this->provider);

    preg_match('/^- (\w+) \[security emails\]\([^)]+\): (.+),$/m', $this->page, $emails);
    preg_match('/^- (\w+) \[risk signals\]\([^)]+\): (.+),$/m', $this->page, $risk);

    expect($notices->all())->toBe(['new_device', 'password_changed', 'authenticator_added', 'authenticator_removed', 'second_factor_failed', 'recovery_code_used', 'recovery_codes_generated', 'suspicious_activity', 'account_locked', 'email_changed', 'email_change_reverted'])
        ->and($emails[1])->toBe('eleven')
        // One phrase for each, in the order Keyring lists them.
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
