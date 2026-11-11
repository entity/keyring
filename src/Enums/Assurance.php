<?php

declare(strict_types=1);

namespace Keyring\Enums;

use Closure;
use InvalidArgumentException;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;

/**
 * Authenticator assurance levels, loosely following NIST SP 800-63B.
 */
enum Assurance: int
{
    case None = 0;

    /** At least one factor. */
    case AAL1 = 1;

    /** At least two factors from different categories. */
    case AAL2 = 2;

    /** Two categories, including a phishing-resistant possession factor. */
    case AAL3 = 3;

    /**
     * The highest level a set of verifications reaches. Defined by the same
     * requirements step-up uses, so the two can never disagree.
     *
     * @param  list<Verification>  $verifications
     */
    public static function of(array $verifications): self
    {
        return self::highest(fn () => $verifications);
    }

    /**
     * The highest level reached when each level counts verifications of its
     * own: a session lets each level's lapse on a different clock.
     *
     * @param  Closure(self): list<Verification>  $countingToward
     */
    public static function highest(Closure $countingToward): self
    {
        return array_find(
            [self::AAL3, self::AAL2, self::AAL1],
            fn (self $level) => Requirement::for($level)->isMetBy($countingToward($level)),
        ) ?? self::None;
    }

    /**
     * The level named in middleware parameters, e.g. keyring:aal2.
     */
    public static function fromName(string $name): self
    {
        return array_find(self::cases(), fn (self $case) => strcasecmp($case->name, $name) === 0)
            ?? throw new InvalidArgumentException("Unknown assurance level [{$name}].");
    }

    public function atLeast(self $level): bool
    {
        return $this->value >= $level->value;
    }
}
