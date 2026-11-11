<?php

declare(strict_types=1);

namespace Keyring\Support;

use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Keyring\Events\RateLimited;

/**
 * What a rate limiter on Keyring's form routes answers once it's full:
 * Laravel's own 429, after saying that it refused (RateLimited), which is
 * how the refusal reaches the security log. Laravel has no event for it.
 *
 * A limiter of your own keeps that by answering the same way:
 *
 *     Limit::perMinute(10)->by(...)->response(new TooManyAttempts('keyring'))
 */
final readonly class TooManyAttempts
{
    public function __construct(
        public string $limiter,
    ) {}

    /**
     * @param  array<string, mixed>  $headers
     */
    public function __invoke(Request $request, array $headers): never
    {
        RateLimited::dispatch(
            $request->user(config('keyring.guard')),
            $this->limiter,
            $request->route()?->getName(),
            (int) ($headers['Retry-After'] ?? 0),
        );

        throw new ThrottleRequestsException('Too Many Attempts.', null, $headers);
    }
}
