<?php

namespace Keyring\Login;

use Keyring\Enums\Assurance;
use Keyring\Enums\Category;

/**
 * What a user must prove before an attempt is complete.
 *
 * "Factors" counts distinct categories, so a password plus a PIN is still one
 * factor (OWASP: two factors of the same type are not MFA).
 */
final readonly class Requirement
{
    /**
     * @param  list<Category>  $categories
     */
    public function __construct(
        public int $factors = 1,
        public array $categories = [],
        public bool $requiresPhishingResistance = false,
        public bool $onlyIfEnrolled = false,
        public bool $noDowngrade = false,
    ) {}

    public static function aal1(): self
    {
        return new self(factors: 1);
    }

    public static function aal2(): self
    {
        return new self(factors: 2);
    }

    public static function aal3(): self
    {
        return new self(factors: 2, categories: [Category::Possession], requiresPhishingResistance: true);
    }

    public static function factors(int $count): self
    {
        return new self(factors: max(1, $count));
    }

    public static function for(Assurance $assurance): self
    {
        return match ($assurance) {
            Assurance::None, Assurance::AAL1 => self::aal1(),
            Assurance::AAL2 => self::aal2(),
            Assurance::AAL3 => self::aal3(),
        };
    }

    /**
     * Require these categories to be among the verified ones.
     */
    #[\NoDiscard]
    public function including(Category ...$categories): static
    {
        return clone ($this, [
            'categories' => array_values(array_unique([...$this->categories, ...$categories], SORT_REGULAR)),
        ]);
    }

    /**
     * Require at least one phishing-resistant verification (WebAuthn).
     */
    #[\NoDiscard]
    public function phishingResistant(): static
    {
        return clone ($this, ['requiresPhishingResistance' => true]);
    }

    /**
     * Only apply this requirement when the user has enrolled enough factors to
     * meet it. Otherwise one factor is enough. This is Fortify's behaviour.
     */
    /**
     * Users who have a phishing-resistant factor (a passkey or security key)
     * must use one. "Try another way" won't offer weaker fallbacks (OWASP).
     */
    #[\NoDiscard]
    public function noDowngrade(): static
    {
        return clone ($this, ['noDowngrade' => true]);
    }

    #[\NoDiscard]
    public function ifEnrolled(): static
    {
        return clone ($this, ['onlyIfEnrolled' => true]);
    }

    /**
     * @param  iterable<Verification>  $verifications
     */
    public function isMetBy(iterable $verifications): bool
    {
        $verified = $this->categoriesIn($verifications);

        if (count($verified) < $this->factors) {
            return false;
        }

        foreach ($this->categories as $category) {
            if (! in_array($category, $verified, true)) {
                return false;
            }
        }

        if ($this->requiresPhishingResistance) {
            foreach ($verifications as $verification) {
                if ($verification->phishingResistant) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    /**
     * Whether a further verification with these properties would bring the
     * given verifications closer to meeting the requirement.
     *
     * @param  iterable<Verification>  $verifications
     * @param  list<Category>  $categories
     */
    public function wouldProgress(iterable $verifications, array $categories, bool $phishingResistant): bool
    {
        $verified = $this->categoriesIn($verifications);
        $new = array_filter($categories, fn (Category $category) => ! in_array($category, $verified, true));

        if ($this->requiresPhishingResistance && ! $this->hasPhishingResistant($verifications)) {
            return $phishingResistant;
        }

        if ($new === []) {
            return false;
        }

        foreach ($this->categories as $required) {
            if (! in_array($required, $verified, true) && in_array($required, $new, true)) {
                return true;
            }
        }

        // Only offer it if the requirement can still be met afterwards: the
        // categories still missing must fit in the slots that remain.
        $after = array_unique([...$verified, ...$new], SORT_REGULAR);
        $missing = array_filter($this->categories, fn (Category $category) => ! in_array($category, $after, true));

        return count($verified) < $this->factors
            && count($missing) <= max(0, $this->factors - count($after));
    }

    /**
     * The stricter of two requirements.
     */
    #[\NoDiscard]
    public function atLeast(self $other): static
    {
        return clone ($this, [
            'factors' => max($this->factors, $other->factors),
            'categories' => array_values(array_unique([...$this->categories, ...$other->categories], SORT_REGULAR)),
            'requiresPhishingResistance' => $this->requiresPhishingResistance || $other->requiresPhishingResistance,
        ]);
    }

    public function assurance(): Assurance
    {
        return match (true) {
            $this->factors >= 2 && $this->requiresPhishingResistance => Assurance::AAL3,
            $this->factors >= 2 => Assurance::AAL2,
            default => Assurance::AAL1,
        };
    }

    /**
     * @return array{factors: int, categories: list<string>, phishing_resistant: bool, if_enrolled: bool, no_downgrade: bool}
     */
    public function toArray(): array
    {
        return [
            'factors' => $this->factors,
            'categories' => array_map(fn (Category $category) => $category->value, $this->categories),
            'phishing_resistant' => $this->requiresPhishingResistance,
            'if_enrolled' => $this->onlyIfEnrolled,
            'no_downgrade' => $this->noDowngrade,
        ];
    }

    /**
     * @param  array{factors: int, categories: list<string>, phishing_resistant: bool, if_enrolled: bool, no_downgrade?: bool}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            factors: $data['factors'],
            categories: array_map(Category::from(...), $data['categories']),
            requiresPhishingResistance: $data['phishing_resistant'],
            onlyIfEnrolled: $data['if_enrolled'],
            noDowngrade: $data['no_downgrade'] ?? false,
        );
    }

    /**
     * @param  iterable<Verification>  $verifications
     * @return list<Category>
     */
    private function categoriesIn(iterable $verifications): array
    {
        $categories = [];

        foreach ($verifications as $verification) {
            foreach ($verification->categories as $category) {
                $categories[$category->value] = $category;
            }
        }

        return array_values($categories);
    }

    /**
     * @param  iterable<Verification>  $verifications
     */
    private function hasPhishingResistant(iterable $verifications): bool
    {
        foreach ($verifications as $verification) {
            if ($verification->phishingResistant) {
                return true;
            }
        }

        return false;
    }
}
