<?php

declare(strict_types=1);

namespace Keyring\Pipeline\Steps;

use Closure;
use Keyring\Devices\DeviceManager;
use Keyring\Pipeline\Context;

/**
 * Notes which device the attempt comes from (or that it's a new one), so the
 * policy and risk signals can use it.
 */
class ResolveDevice
{
    public function __construct(
        protected DeviceManager $devices,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $attempt = $context->attempt();

        if (! $attempt->deviceResolved) {
            $attempt->resolveDevice($this->devices->find($context->request, $attempt->user())?->id);
        }

        if ($context->request->boolean('trust')) {
            $attempt->trustDevice = true;
        }

        return $next($context);
    }
}
