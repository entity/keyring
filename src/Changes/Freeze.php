<?php

declare(strict_types=1);

namespace Keyring\Changes;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Keyring\Enums\FreezeReason;

/**
 * Why an account's established sign-in methods and its recovery codes
 * can't be removed or replaced just now, and until when.
 */
final readonly class Freeze
{
    public function __construct(
        public FreezeReason $reason,
        public CarbonImmutable $until,
    ) {}

    /**
     * What the user is told, with how long is left.
     */
    public function message(): string
    {
        // Rounded up, so it never says the wait is shorter than it is.
        $left = $this->until->diffForHumans(now(), [
            'syntax' => CarbonInterface::DIFF_ABSOLUTE,
            'parts' => 1,
            'options' => CarbonInterface::CEIL,
        ]);

        return match ($this->reason) {
            FreezeReason::NewAuthenticator => __('keyring::keyring.frozen_new_authenticator', ['time' => $left]),
            FreezeReason::RecentChange => __('keyring::keyring.frozen_recent_change', ['time' => $left]),
        };
    }

    /**
     * @return array{reason: string, until: string}
     */
    public function toArray(): array
    {
        return ['reason' => $this->reason->value, 'until' => $this->until->toIso8601String()];
    }
}
