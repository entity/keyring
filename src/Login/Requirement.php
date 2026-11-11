<?php

declare(strict_types=1);

namespace Keyring\Login;

use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Factors\RecoveryCodes;

/**
 * What a user must prove before an attempt is complete.
 *
 * "Factors" counts distinct categories, so a password plus a PIN is still one
 * factor: two of the same kind aren't multi-factor.
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
        public bool $requiresDeviceBound = false,
        public bool $onlyIfEnrolled = false,
        public bool $noDowngrade = false,
        public array $downgradeExceptions = [],
        public array $phishingResistanceExceptions = [],
        public bool $acceptsRecoveryCodes = true,
    ) {}

    public static function aal1(): self
    {
        return new self(factors: 1);
    }

    public static function aal2(): self
    {
        return new self(factors: 2);
    }

    /**
     * AAL3: two factors, one of them a phishing-resistant key that can't
     * leave its device. A synced passkey reaches AAL2, not AAL3.
     */
    public static function aal3(): self
    {
        return self::aal2()->including(Category::Possession)->deviceBound();
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
     * Require a phishing-resistant key that can't leave its device: a
     * security key or a passkey that doesn't sync.
     */
    #[\NoDiscard]
    public function deviceBound(): static
    {
        return clone ($this, ['requiresPhishingResistance' => true, 'requiresDeviceBound' => true]);
    }

    /**
     * Users who have a phishing-resistant factor (a passkey or security key)
     * must use one. "Try another way" won't offer weaker fallbacks, except
     * recovery codes: single use, and the way back in when the key is lost.
     * Pass `except: []` to refuse those too.
     *
     * @param  list<string>  $except
     */
    #[\NoDiscard]
    public function noDowngrade(array $except = [RecoveryCodes::KEY]): static
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
     * Refuse recovery codes, for a confirm that doesn't know what the user
     * was doing: a code spent on it might not get them there.
     *
     * @internal
     */
    #[\NoDiscard]
    public function withoutRecoveryCodes(): static
    {
        return clone ($this, ['acceptsRecoveryCodes' => false]);
    }

    /**
     * Apply this requirement as far as the user's authenticators can meet it.
     * A user with nothing beyond one factor signs in with that, which is
     * Fortify's behaviour.
     */
    #[\NoDiscard]
    public function ifEnrolled(): static
    {
        return clone ($this, ['onlyIfEnrolled' => true]);
    }

    /**
     * What's left of this requirement for a user who can't meet all of it:
     * the categories and phishing resistance they can give, and as many
     * factors as they can, never one while they have a second.
     *
     * @internal
     *
     * @param  list<Category>  $categories  the categories the user can prove
     */
    #[\NoDiscard]
    public function limitedTo(array $categories, bool $phishingResistant, bool $deviceBound = false): static
    {
        return clone ($this, [
            'factors' => max(1, min(max($this->factors, 2), count($categories))),
            'categories' => array_values(array_filter($this->categories, fn (Category $category) => in_array($category, $categories, true))),
            'requiresPhishingResistance' => $this->requiresPhishingResistance && $phishingResistant,
            'requiresDeviceBound' => $this->requiresDeviceBound && $deviceBound,
        ]);
    }

    /**
     * @param  list<Verification>  $verifications
     */
    public function isMetBy(array $verifications): bool
    {
        $verified = $this->categoriesIn($verifications);

        return count($verified) >= $this->factors
            && array_all($this->categories, fn (Category $category) => in_array($category, $verified, true))
            && (! $this->requiresPhishingResistance || $this->hasPhishingResistant($verifications))
            && (! $this->requiresDeviceBound || $this->hasDeviceBoundKey($verifications));
    }

    /**
     * Whether a further verification like this one would bring the given
     * verifications closer to meeting the requirement.
     *
     * @param  list<Verification>  $verifications
     */
    public function wouldProgress(array $verifications, Verification $next): bool
    {
        $verified = $this->categoriesIn($verifications);
        $new = array_filter($next->categories, fn (Category $category) => ! in_array($category, $verified, true));

        if ($this->requiresDeviceBound && ! $this->hasDeviceBoundKey($verifications)) {
            return $this->hasDeviceBoundKey([$next]);
        }

        if ($this->requiresPhishingResistance && ! $this->hasPhishingResistant($verifications)) {
            return $this->hasPhishingResistant([$next]);
        }

        if ($new === []) {
            return false;
        }

        if (array_any($this->categories, fn (Category $required) => ! in_array($required, $verified, true) && in_array($required, $new, true))) {
            return true;
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
            'requiresDeviceBound' => $this->requiresDeviceBound || $other->requiresDeviceBound,
            'noDowngrade' => $this->noDowngrade || $other->noDowngrade,
            'downgradeExceptions' => match (true) {
                $this->noDowngrade && $other->noDowngrade => array_values(array_intersect($this->downgradeExceptions, $other->downgradeExceptions)),
                $this->noDowngrade => $this->downgradeExceptions,
                default => $other->downgradeExceptions,
            },
            'phishingResistanceExceptions' => match (true) {
                $this->requiresPhishingResistance && $other->requiresPhishingResistance => array_values(array_intersect($this->phishingResistanceExceptions, $other->phishingResistanceExceptions)),
                $this->requiresPhishingResistance => $this->phishingResistanceExceptions,
                default => $other->phishingResistanceExceptions,
            },
            'acceptsRecoveryCodes' => $this->acceptsRecoveryCodes && $other->acceptsRecoveryCodes,
        ]);
    }

    /**
     * @return array{factors: int, categories: list<string>, phishing_resistant: bool, device_bound: bool, if_enrolled: bool, no_downgrade: bool, downgrade_exceptions: list<string>, phishing_resistance_exceptions: list<string>, accepts_recovery_codes: bool}
     */
    public function toArray(): array
    {
        return [
            'factors' => $this->factors,
            'categories' => array_map(fn (Category $category) => $category->value, $this->categories),
            'phishing_resistant' => $this->requiresPhishingResistance,
            'device_bound' => $this->requiresDeviceBound,
            'if_enrolled' => $this->onlyIfEnrolled,
            'no_downgrade' => $this->noDowngrade,
            'downgrade_exceptions' => $this->downgradeExceptions,
            'phishing_resistance_exceptions' => $this->phishingResistanceExceptions,
            'accepts_recovery_codes' => $this->acceptsRecoveryCodes,
        ];
    }

    /**
     * @param  array{factors: int, categories: list<string>, phishing_resistant: bool, device_bound?: bool, if_enrolled: bool, no_downgrade?: bool, downgrade_exceptions?: list<string>, phishing_resistance_exceptions?: list<string>, accepts_recovery_codes?: bool}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            factors: $data['factors'],
            categories: array_map(Category::from(...), $data['categories']),
            requiresPhishingResistance: $data['phishing_resistant'],
            requiresDeviceBound: $data['device_bound'] ?? false,
            onlyIfEnrolled: $data['if_enrolled'],
            noDowngrade: $data['no_downgrade'] ?? false,
            downgradeExceptions: $data['downgrade_exceptions'] ?? [],
            phishingResistanceExceptions: $data['phishing_resistance_exceptions'] ?? [],
            acceptsRecoveryCodes: $data['accepts_recovery_codes'] ?? true,
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
    private function hasDeviceBoundKey(array $verifications): bool
    {
        return array_any($verifications, fn (Verification $verification) => $verification->phishingResistant && $verification->deviceBound);
    }

    /**
     * @param  list<Verification>  $verifications
     */
    private function hasPhishingResistant(array $verifications): bool
    {
        return array_any($verifications, fn (Verification $verification) => $verification->phishingResistant
            || ($verification->categories !== [] && in_array($verification->factor, $this->phishingResistanceExceptions, true)));
    }
}
