<?php

namespace Keyring\Support;

use Closure;
use Illuminate\Database\Eloquent\Model;

/**
 * Serialises work on one row: two requests spending the same code, or
 * removing a user's last two sign-in methods, run one after the other.
 */
final class RowLock
{
    /**
     * Run the callback in a transaction on the model's own connection, with a
     * fresh copy of its row locked for update (null if the row is gone).
     *
     * @template TModel of Model
     * @template TResult
     *
     * @param  TModel  $model
     * @param  Closure(TModel|null): TResult  $callback
     * @return TResult
     */
    public static function hold(Model $model, Closure $callback): mixed
    {
        return $model->getConnection()->transaction(
            fn () => $callback($model->newQuery()->lockForUpdate()->whereKey($model->getKey())->first()),
        );
    }
}
