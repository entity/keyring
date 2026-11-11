<?php

declare(strict_types=1);

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent when another factor is needed. Built with the pipeline's `context`.
 */
interface ChallengeResponse extends Responsable
{
    /**
     * The constructor arguments Keyring passes, by name.
     *
     * @var list<string>
     */
    public const array BUILT_WITH = ['context'];
}
