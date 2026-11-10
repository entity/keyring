<?php

namespace Keyring\Changes;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Keyring\Events\ProtectionBypassed;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Features;

/**
 * The user attributes (the password and email, once Keyring handles
 * changing them) that may only change through Keyring's flows, and the flows
 * allowed to change them right now.
 */
class ProtectedAttributes
{
    /**
     * The Keyring flows running now, innermost last: each lists the
     * attributes it may change, or null for all of them.
     *
     * @var list<list<string>|null>
     */
    protected array $flows = [];

    /**
     * The password once Keyring handles changing it, the email once Keyring
     * handles changing that, plus any the app lists.
     *
     * @return list<string>
     */
    public function all(): array
    {
        return array_values(array_unique([
            ...Features::enabled(Features::updatePasswords()) ? ['password'] : [],
            ...Features::enabled(Features::emailChanges()) ? ['email'] : [],
            ...config('keyring.protected'),
        ]));
    }

    /**
     * Run a flow that's allowed to change protected attributes: all of them,
     * or only those listed (an app's password action may change the password
     * and nothing else).
     *
     * @template T
     *
     * @param  Closure(): T  $callback
     * @param  list<string>|null  $only
     * @return T
     */
    public function changing(Closure $callback, ?array $only = null): mixed
    {
        $this->flows[] = $only;

        try {
            return $callback();
        } finally {
            array_pop($this->flows);
        }
    }

    /**
     * Change protected attributes outside a Keyring flow, for trusted admin
     * tooling. Every use is announced with a ProtectionBypassed event.
     *
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function bypass(Closure $callback, ?string $reason = null): mixed
    {
        ProtectionBypassed::dispatch($reason);

        return $this->changing($callback);
    }

    /**
     * Refuse changes to protected attributes made outside a Keyring flow.
     */
    public function guard(Model $model): void
    {
        $allowed = $this->flows === [] ? [] : array_last($this->flows);

        if ($allowed === null) {
            return;
        }

        $changed = array_values(array_diff(array_filter($this->all(), $model->isDirty(...)), $allowed));

        if ($changed !== []) {
            throw ProtectedAttributeException::for($model, $changed);
        }
    }
}
