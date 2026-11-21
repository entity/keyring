<?php

declare(strict_types=1);

namespace Keyring\Support;

use Closure;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;

/**
 * Runs statements that name session records, and fails without naming
 * them. Laravel puts a query's bindings in its exception's message, and a
 * record's ID, or a cache key made from it, is what the "remember me"
 * cookie holds: reported, it would sit in your logs and error tracker.
 * What's thrown instead is the same kind of exception, for the same SQL,
 * with the database's own error and code, and no bindings.
 */
final class WithoutBindings
{
    /**
     * @template TResult
     *
     * @param  Closure(): TResult  $statements
     * @return TResult
     */
    public static function run(Closure $statements): mixed
    {
        try {
            return $statements();
        } catch (QueryException $e) {
            throw self::masked($e);
        } catch (DeadlockException $e) {
            $previous = $e->getPrevious();
            $masked = $previous instanceof QueryException ? self::masked($previous) : null;

            throw new DeadlockException($masked?->getMessage() ?? 'A deadlock was found in the session registry.', (int) $e->getCode(), $masked);
        }
    }

    public static function masked(QueryException $e): QueryException
    {
        $previous = $e->getPrevious() ?? $e;

        return new QueryException($e->connectionName, $e->getSql(), [], $previous, readWriteType: $e->readWriteType, maskBindings: true);
    }
}
