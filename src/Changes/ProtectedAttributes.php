<?php

namespace Keyring\Changes;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Keyring\Events\ProtectionBypassed;
use Keyring\Exceptions\ProtectedAttributeException;

/**
 * The user attributes (email and password by default) that may only change
 * through Keyring's flows, and the flows allowed to change them right now.
 */
class ProtectedAttributes
{
    /** How many Keyring flows are currently allowed to change protected attributes. */
    protected int $changing = 0;

    /**
     * @return list<string>
     */
    public function all(): array
    {
        return config('keyring.protected', ['email', 'password']);
    }

    /**
     * Run a flow that's allowed to change protected attributes.
     *
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function changing(Closure $callback): mixed
    {
        $this->changing++;

        try {
            return $callback();
        } finally {
            $this->changing--;
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
        if ($this->changing > 0) {
            return;
        }

        $changed = array_values(array_filter($this->all(), $model->isDirty(...)));

        if ($changed !== []) {
            throw ProtectedAttributeException::for($model, $changed);
        }
    }
}
