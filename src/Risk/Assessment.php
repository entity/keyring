<?php

namespace Keyring\Risk;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;
use Keyring\Login\Attempt;
use Keyring\Sessions\RegisteredSession;

/**
 * What signals get to look at.
 */
final class Assessment
{
    /** @var array<string, mixed>|null|false */
    private array|null|false $location = false;

    public function __construct(
        public readonly Checkpoint $checkpoint,
        public readonly Request $request,
        public readonly Authenticatable&Model $user,
        public readonly ?Attempt $attempt = null,
        public readonly ?RegisteredSession $session = null,
    ) {}

    /**
     * Where the request seems to come from, if a locator is configured.
     *
     * @return array<string, mixed>|null
     */
    public function location(): ?array
    {
        if ($this->location === false) {
            $this->location = app(LocatesIps::class)->locate($this->request);
        }

        return $this->location;
    }
}
