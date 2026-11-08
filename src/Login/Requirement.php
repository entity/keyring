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
     * @param  list<string>  $downgradeExceptions  factors noDowngrade() still accepts instead of a key
     * @param  list<string>  $phishingResistanceExceptions  factors accepted in place of a phishing-resistant one
     */
    public function __construct(
        public int $factors = 1,
        public array $categories = [],
        public bool $requiresPhishingResistance = false,
        public bool $onlyIfEnrolled = false,
        public bool $noDowngrade = false,
        public array $downgradeExceptions = [],
        public array $phishingResistanceExceptions = [],
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
     * Users who have a phishing-resistant factor (a passkey or security key)
     * must use one. "Try another way" won't offer weaker fallbacks (OWASP),
     * except recovery codes: single use, and the way back in when the key is
     * lost. Pass `except: []` to refuse those too.
     *
     * @param  list<string>  $except
     */
    #[\NoDiscard]
    public function noDowngrade(array $except = ['recovery']): static
    {
        return clone ($this, ['noDowngrade' => true, 'downgradeExceptions' => $except]);
    }

    /**
     * Apply noDowngrade() for a user who has a phishing-resistant factor.
     *
     * @internal
     */
    #[\NoDiscard]
    public function withoutDowngrades(): static
    {
        return clone ($this, [
            'requiresPhishingResistance' => true,
            'phishingResistanceExceptions' => $this->downgradeExceptions,
        ]);
    }

    /**
     * Only apply this requirement when the user has enrolled enough factors to
     * meet it. Otherwise one factor is enough. This is Fortify's behaviour.
     */
    #[\NoDiscard]
    public function ifEnrolled(): static
    {
        return clone ($this, ['onlyIfEnrolled' => true]);
    }

    /**
     * @param  list<Verification>  $verifications
     */
    public function isMetBy(array $verifications): bool
    {
        $verified = $this->categoriesIn($verifications);

        return count($verified) >= $this->factors
            && array_all($this->categories, fn (Category $category) => in_array($category, $verified, true))
            && (! $this->requiresPhishingResistance || $this->hasPhishingResistant($verifications));
    }

    /**
     * Whether a further verification with these properties would bring the
     * given verifications closer to meeting the requirement.
     *
     * @param  list<Verification>  $verifications
     * @param  list<Category>  $categories
     */
    public function wouldProgress(array $verifications, array $categories, bool $phishingResistant, ?string $factor = null): bool
    {
        $verified = $this->categoriesIn($verifications);
        $new = array_filter($categories, fn (Category $category) => ! in_array($category, $verified, true));

        if ($this->requiresPhishingResistance && ! $this->hasPhishingResistant($verifications)) {
            return $phishingResistant || in_array($factor, $this->phishingResistanceExceptions, true);
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
            'phishingResistanceExceptions' => match (true) {
                $this->requiresPhishingResistance && $other->requiresPhishingResistance => array_values(array_intersect($this->phishingResistanceExceptions, $other->phishingResistanceExceptions)),
                $this->requiresPhishingResistance => $this->phishingResistanceExceptions,
                default => $other->phishingResistanceExceptions,
            },
        ]);
    }

    /**
     * @return array{factors: int, categories: list<string>, phishing_resistant: bool, if_enrolled: bool, no_downgrade: bool, downgrade_exceptions: list<string>, phishing_resistance_exceptions: list<string>}
     */
    public function toArray(): array
    {
        return [
            'factors' => $this->factors,
            'categories' => array_map(fn (Category $category) => $category->value, $this->categories),
            'phishing_resistant' => $this->requiresPhishingResistance,
            'if_enrolled' => $this->onlyIfEnrolled,
            'no_downgrade' => $this->noDowngrade,
            'downgrade_exceptions' => $this->downgradeExceptions,
            'phishing_resistance_exceptions' => $this->phishingResistanceExceptions,
        ];
    }

    /**
     * @param  array{factors: int, categories: list<string>, phishing_resistant: bool, if_enrolled: bool, no_downgrade?: bool, downgrade_exceptions?: list<string>, phishing_resistance_exceptions?: list<string>}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            factors: $data['factors'],
            categories: array_map(Category::from(...), $data['categories']),
            requiresPhishingResistance: $data['phishing_resistant'],
            onlyIfEnrolled: $data['if_enrolled'],
            noDowngrade: $data['no_downgrade'] ?? false,
            downgradeExceptions: $data['downgrade_exceptions'] ?? [],
            phishingResistanceExceptions: $data['phishing_resistance_exceptions'] ?? [],
        );
    }

    /**
     * @param  list<Verification>  $verifications
     * @return list<Category>
     */
    private function categoriesIn(array $verifications): array
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
     * @param  list<Verification>  $verifications
     */
    private function hasPhishingResistant(array $verifications): bool
    {
        return array_any($verifications, fn (Verification $verification) => $verification->phishingResistant
            || in_array($verification->factor, $this->phishingResistanceExceptions, true));
    }
}
