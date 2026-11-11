<?php

declare(strict_types=1);

use Illuminate\Support\Str;
use Keyring\Enums\Severity;

it('lists every entry type in the docs with the severity it is logged at', function () {
    preg_match_all('/^\| (`[^|]+) \| (info|notice|warning|critical) \|/m', file_get_contents(__DIR__.'/../../docs/security-log-and-emails.md'), $rows, PREG_SET_ORDER);

    $documented = collect($rows)->flatMap(fn (array $row) => array_fill_keys(Str::matchAll('/`([a-z_]+)`/', $row[1])->all(), $row[2]));

    $recorded = Str::matchAll("/record(?:OrFail|Refusal)?\\(\\s*'([a-z_]+)'[,)]/", file_get_contents(__DIR__.'/../../src/Activity/RecordSecurityEvents.php').file_get_contents(__DIR__.'/../../src/Activity/SecurityLog.php'))
        ->merge(['device_reported', 'device_revoked', 'risk_denied', 'risk_reauthenticate', 'risk_locked', 'risk_step_up', 'risk_revoked_sessions', 'risk_notified'])
        ->unique();

    expect($recorded->diff($documented->keys())->values()->all())->toBe([])
        ->and($documented->keys()->diff($recorded)->values()->all())->toBe([])
        ->and($documented->filter(fn (string $severity, string $type) => Severity::of($type)->value !== $severity)->all())->toBe([]);
});
