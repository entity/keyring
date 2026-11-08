<?php

/*
 * One side of a race: boots the app the way the tests do, against the same
 * database, says it's ready, then runs one operation and prints what happened
 * as JSON. Usage: php worker.php <operation> <arguments...>
 */

use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Changes\EmailChanges;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\TestCase;

require __DIR__.'/../../vendor/autoload.php';

new class('worker') extends TestCase {}->createApplication();
useRaceFactors();

[, $operation, $id, $value] = $argv + [3 => null];

echo "ready\n";

try {
    $result = match ($operation) {
        'remove-authenticator' => Keyring::authenticatorModel()::find($value) !== null
            && app(AuthenticatorChanges::class)->remove(User::findOrFail($id), $value) instanceof Authenticator,
        'use-recovery-code' => (function () use ($id, $value) {
            $authenticator = Authenticator::findOrFail($id);
            $attempt = Attempt::start(Purpose::Login, $authenticator->user());

            return Keyring::factor('recovery')->verify($attempt, $authenticator, Request::create('/', 'POST', ['code' => $value])) !== null;
        })(),
        'confirm-email-change' => app(EmailChanges::class)->confirm(PendingChange::findOrFail($id), $value)->name,
        'revert-email-change' => app(EmailChanges::class)->revert(PendingChange::findOrFail($id), $value),
    };
} catch (ValidationException) {
    $result = 'refused';
}

echo json_encode(['result' => $result]), "\n";
