<?php

declare(strict_types=1);

namespace Keyring\Risk;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Devices\Location;
use Keyring\Login\Attempt;
use Keyring\Sessions\RegisteredSession;

/**
 * What signals get to look at.
 */
final readonly class Assessment
{
    public function __construct(
        public Checkpoint $checkpoint,
        public Request $request,
        public Authenticatable&Model $user,
        public ?Attempt $attempt = null,
        public ?RegisteredSession $session = null,
    ) {}

    /**
     * Where the request seems to come from, if a locator is configured.
     *
     * @return array<string, mixed>|null
     */
    public function location(): ?array
    {
        return Location::of($this->request);
    }
}
