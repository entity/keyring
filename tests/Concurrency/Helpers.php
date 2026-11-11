<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\WithoutIncrementing;
use Illuminate\Database\Eloquent\Attributes\WithoutTimestamps;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Process\FakeInvokedProcess;
use Illuminate\Process\InvokedProcess;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Sleep;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;

/**
 * The same factors in the test and in every worker, so both sides agree on
 * what each user can sign in with.
 */
function useRaceFactors(): void
{
    Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class]);
}

/**
 * A registered session's row, to hold its lock: the registry has no model
 * of its own.
 */
function sessionRow(string $id): Model
{
    return new #[Table(name: 'keyring_sessions', keyType: 'string')]
    #[WithoutIncrementing]
    #[WithoutTimestamps]
    class extends Model {}->newQuery()->findOrFail($id);
}

/**
 * How many results were exactly this value.
 *
 * @param  list<mixed>  $results
 */
function outcomes(array $results, mixed $value): int
{
    return count(array_filter($results, fn (mixed $result) => $result === $value));
}

/**
 * Race the operations against each other, deterministically: hold the row
 * lock the code under test should take, start every operation in its own
 * process, check each one is waiting for the lock rather than running ahead,
 * then let go and collect what each did.
 *
 * @param  list<list<string|int>>  $operations  worker.php arguments
 * @param  (Closure(): void)|null  $meanwhile  work to finish, holding the lock, before letting go
 * @param  int|null  $waiting  how many of them should get as far as the lock, when the rest are turned away before it
 * @return list<mixed>
 */
function contend(Model $locked, array $operations, ?Closure $meanwhile = null, ?int $waiting = null): array
{
    $connection = $locked->getConnection();
    $connection->beginTransaction();
    $locked->newQuery()->lockForUpdate()->find($locked->getKey());

    $env = ['DB_CONNECTION' => $connection->getName(), 'DB_DATABASE' => $connection->getDatabaseName()];

    $workers = array_map(
        fn (array $arguments) => Process::env($env)->timeout(30)->start([PHP_BINARY, __DIR__.'/worker.php', ...array_map(strval(...), $arguments)]),
        $operations,
    );

    foreach ($workers as $worker) {
        $deadline = microtime(true) + 15;

        while (! str_contains($worker->output(), 'ready') && $worker->running() && microtime(true) < $deadline) {
            Sleep::usleep(50_000);
        }
    }

    // Long enough for an operation that ignores the lock to finish.
    Sleep::usleep(500_000);

    // Let go whatever happens: a failed expectation that kept the lock would
    // leave every later test waiting for the tables it holds.
    try {
        $running = fn () => count(array_filter($workers, fn (InvokedProcess|FakeInvokedProcess $worker) => $worker->running()));

        // Those turned away before the lock get time to finish. The rest can't.
        for ($deadline = microtime(true) + 15; $waiting !== null && $running() > $waiting && microtime(true) < $deadline;) {
            Sleep::usleep(50_000);
        }

        expect($running())->toBe($waiting ?? count($workers), 'An operation ran without waiting for the lock, or one that should have been turned away is waiting for it: '.implode('', array_map(
            fn (InvokedProcess|FakeInvokedProcess $worker) => $worker->output().$worker->errorOutput(),
            $workers,
        )));

        if ($meanwhile !== null) {
            $meanwhile();
        }
    } catch (Throwable $e) {
        $connection->rollBack();
        array_map(fn (InvokedProcess|FakeInvokedProcess $worker) => $worker->running() && $worker->signal(SIGKILL), $workers);

        throw $e;
    }

    $connection->commit();

    return array_map(function (InvokedProcess|FakeInvokedProcess $worker) {
        $result = $worker->wait();

        expect($result->successful())->toBeTrue($result->output().$result->errorOutput());

        return json_decode(str($result->output())->afterLast('ready')->trim()->value(), true)['result'];
    }, $workers);
}
