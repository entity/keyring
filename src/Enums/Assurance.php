<?php

namespace Keyring\Enums;

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
     * Work out the level a set of verifications reaches.
     *
     * @param  iterable<Verification>  $verifications
     */
    public static function of(iterable $verifications): self
    {
        $categories = [];
        $phishingResistantPossession = false;

        foreach ($verifications as $verification) {
            foreach ($verification->categories as $category) {
                $categories[$category->value] = true;
            }

            if ($verification->phishingResistant && in_array(Category::Possession, $verification->categories, true)) {
                $phishingResistantPossession = true;
            }
        }

        return match (true) {
            count($categories) >= 2 && $phishingResistantPossession => self::AAL3,
            count($categories) >= 2 => self::AAL2,
            count($categories) === 1 => self::AAL1,
            default => self::None,
        };
    }

    public static function fromName(string $name): self
    {
        return constant(self::class.'::'.strtoupper($name));
    }

    public function atLeast(self $level): bool
    {
        return $this->value >= $level->value;
    }
}
