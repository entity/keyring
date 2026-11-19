<?php

declare(strict_types=1);

namespace Keyring\Login;

use InvalidArgumentException;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Factors\RecoveryCodes;

/**
 * What a user must prove before an attempt is complete.
 *
 * "Factors" counts distinct categories, so a password plus a PIN is still one
 * factor: two of the same kind aren't multi-factor. Only authentication
 * factors count. "Steps" counts every category, so an emailed code, which
 * isn't one, can still be asked for without being taken for a factor.
 * The assurance levels ask for more than a count: from AAL2 up, one of the
 * factors has to be something the user has.
 */
final readonly class Requirement
{
    /**
     * @param  list<Category>  $categories
     * @param  list<string>  $downgradeExceptions  factors noDowngrade() still accepts instead of a key
     * @param  list<string>  $phishingResistanceExceptions  factors accepted in place of the key this asks for
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
        public int $steps = 0,
        public bool $requiresAttestedKey = false,
    ) {}

    public static function aal1(): self
    {
        return new self(factors: 1);
    }

    /**
     * AAL2: two factors, one of them something the user has. NIST SP
     * 800-63B-4 (Sec. 2.2.1) takes a password or a biometric only beside a
     * physical authenticator, never the two alone. A passkey that verified
     * the user is both at once. For two categories of any kind, ask for
     * factors(2).
     */
    public static function aal2(): self
    {
        return new self(factors: 2, categories: [Category::Possession]);
    }

    /**
     * AAL3: two factors, one of them a phishing-resistant key that can't
     * leave its device and that its maker vouched for when it was added.
     * The other is that key's own user verification, or a password: what
     * any other authenticator proved doesn't count. A synced passkey reaches
     * AAL2, not AAL3, and so does a key nothing vouches for.
     */
    public static function aal3(): self
    {
        return self::aal2()->attestedKey();
    }

    public static function factors(int $count): self
    {
        return new self(factors: max(1, $count));
    }

    /**
     * That many categories of any kind, one of them an authentication
     * factor. A step that isn't one, like an emailed code, counts here and
     * nowhere else, so the session it starts can still be AAL1.
     */
    public static function steps(int $count): self
    {
        return new self(steps: max(1, $count));
    }

    /**
     * The requirement named in middleware parameters: a level, then anything
     * more to ask on top of it, e.g. keyring:aal2,device-bound.
     */
    public static function named(string $level, string ...$also): self
    {
        return array_reduce($also, fn (self $requirement, string $name) => match (strtolower($name)) {
            'phishing-resistant' => $requirement->phishingResistant(),
            'device-bound' => $requirement->deviceBound(),
            default => throw new InvalidArgumentException("Unknown requirement [{$name}]."),
        }, self::for(Assurance::fromName($level)));
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
     * security key or a passkey that doesn't sync. That's the key's own
     * report, so it's worth asking for and short of what AAL3 means.
     */
    #[\NoDiscard]
    public function deviceBound(): static
    {
        return clone ($this, ['requiresPhishingResistance' => true, 'requiresDeviceBound' => true]);
    }

    /**
     * Require a device-bound key that was added with a verified attestation
     * (WebAuthn's requireAttestation()), and count only what can't be
     * copied off a device: that key's own proof, and factors that aren't
     * something the user holds, like the password. NIST's terms for AAL3,
     * where syncable authenticators aren't used at all.
     */
    #[\NoDiscard]
    public function attestedKey(): static
    {
        return clone ($this->deviceBound(), ['requiresAttestedKey' => true]);
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
     * Accept these factors in place of the key this asks for: recovery
     * codes, for someone whose key is lost.
     *
     * @internal
     *
     * @param  list<string>  $factors
     */
    #[\NoDiscard]
    public function acceptingInstead(array $factors): static
    {
        return clone ($this, ['phishingResistanceExceptions' => $factors]);
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
     * A user with nothing beyond one factor signs in with that.
     */
    #[\NoDiscard]
    public function ifEnrolled(): static
    {
        return clone ($this, ['onlyIfEnrolled' => true]);
    }

    /**
     * What's left of this requirement for a user who can't meet all of it:
     * the categories and phishing resistance they can give, and as many
     * factors as they can, never one while they have a second. Short of two
     * factors, a step that isn't one (an emailed code) is asked for beside
     * the one they have: the app chose to offer it, and it's all there is.
     * An attested key is only asked for when the user can also give the
     * second factor that counts beside it.
     *
     * @internal
     *
     * @param  list<Verification>  $provable  everything the user could prove
     */
    #[\NoDiscard]
    public function limitedTo(array $provable): static
    {
        $limited = clone ($this, [
            'requiresPhishingResistance' => $this->requiresPhishingResistance && array_any($provable, fn (Verification $verification) => $verification->phishingResistant),
            'requiresDeviceBound' => $this->requiresDeviceBound && array_any($provable, fn (Verification $verification) => $verification->phishingResistant && $verification->deviceBound),
            'requiresAttestedKey' => $this->requiresAttestedKey && self::aal2()->attestedKey()->isMetBy($provable),
        ]);

        $categories = $limited->categoriesIn($limited->counted($provable));
        $factors = max(1, min(max($this->factors, 2), count($this->authenticating($categories))));
        $steps = min(max($this->steps, $this->factors, 2), count($categories));

        return clone ($limited, [
            'factors' => $factors,
            'steps' => $steps > $factors ? $steps : 0,
            'categories' => array_values(array_filter($this->categories, fn (Category $category) => in_array($category, $categories, true))),
        ]);
    }

    /**
     * @param  list<Verification>  $verifications
     */
    public function isMetBy(array $verifications): bool
    {
        $verifications = $this->counted($verifications);
        $verified = $this->categoriesIn($verifications);

        return count($this->authenticating($verified)) >= $this->factors
            && count($verified) >= $this->steps
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
        if ($this->counted([$next]) === []) {
            return false;
        }

        $verifications = $this->counted($verifications);
        $verified = $this->categoriesIn($verifications);
        $new = array_values(array_filter($next->categories, fn (Category $category) => ! in_array($category, $verified, true)));

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

        // Only offer a factor if the requirement can still be met afterwards:
        // the categories still missing must fit in the slots that remain.
        $factors = $this->authenticating($verified);
        $after = [...$factors, ...$this->authenticating($new)];
        $missing = array_filter($this->categories, fn (Category $category) => $category->authenticates() && ! in_array($category, $after, true));

        if (count($after) > count($factors) && count($factors) < $this->factors && count($missing) <= max(0, $this->factors - count($after))) {
            return true;
        }

        // A step of any kind helps once the factors still to come won't
        // cover the steps asked for.
        return count($verified) + max(0, $this->factors - count($factors)) < $this->steps;
    }

    /**
     * The stricter of two requirements.
     */
    #[\NoDiscard]
    public function atLeast(self $other): static
    {
        return clone ($this, [
            'factors' => max($this->factors, $other->factors),
            'steps' => max($this->steps, $other->steps),
            'categories' => array_values(array_unique([...$this->categories, ...$other->categories], SORT_REGULAR)),
            'requiresPhishingResistance' => $this->requiresPhishingResistance || $other->requiresPhishingResistance,
            'requiresDeviceBound' => $this->requiresDeviceBound || $other->requiresDeviceBound,
            'requiresAttestedKey' => $this->requiresAttestedKey || $other->requiresAttestedKey,
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
     * @return array{factors: int, steps: int, categories: list<string>, phishing_resistant: bool, device_bound: bool, attested_key: bool, if_enrolled: bool, no_downgrade: bool, downgrade_exceptions: list<string>, phishing_resistance_exceptions: list<string>, accepts_recovery_codes: bool}
     */
    public function toArray(): array
    {
        return [
            'factors' => $this->factors,
            'steps' => $this->steps,
            'categories' => array_map(fn (Category $category) => $category->value, $this->categories),
            'phishing_resistant' => $this->requiresPhishingResistance,
            'device_bound' => $this->requiresDeviceBound,
            'attested_key' => $this->requiresAttestedKey,
            'if_enrolled' => $this->onlyIfEnrolled,
            'no_downgrade' => $this->noDowngrade,
            'downgrade_exceptions' => $this->downgradeExceptions,
            'phishing_resistance_exceptions' => $this->phishingResistanceExceptions,
            'accepts_recovery_codes' => $this->acceptsRecoveryCodes,
        ];
    }

    /**
     * @param  array{factors: int, steps?: int, categories: list<string>, phishing_resistant: bool, device_bound?: bool, attested_key?: bool, if_enrolled: bool, no_downgrade?: bool, downgrade_exceptions?: list<string>, phishing_resistance_exceptions?: list<string>, accepts_recovery_codes?: bool}  $data
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
            steps: $data['steps'] ?? 0,
            requiresAttestedKey: $data['attested_key'] ?? false,
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
     * The verifications this requirement takes into account. One that asks
     * for an attested key leaves out everything else the user holds: a
     * synced passkey that verified them says nothing of who touched the
     * key, and at AAL3 nothing that can be copied counts.
     *
     * @param  list<Verification>  $verifications
     * @return list<Verification>
     */
    private function counted(array $verifications): array
    {
        if (! $this->requiresAttestedKey) {
            return $verifications;
        }

        return array_values(array_filter($verifications, fn (Verification $verification) => $this->isAttestedKey($verification)
            || $this->standsIn($verification)
            || ! in_array(Category::Possession, $verification->categories, true)));
    }

    /**
     * Whether a verification is of a factor accepted in place of the key
     * asked for. A used-up set of recovery codes proves nothing.
     */
    private function standsIn(Verification $verification): bool
    {
        return $verification->categories !== [] && in_array($verification->factor, $this->phishingResistanceExceptions, true);
    }

    private function isAttestedKey(Verification $verification): bool
    {
        return $verification->phishingResistant && $verification->deviceBound && $verification->attested;
    }

    /**
     * The categories that are authentication factors, which are the ones
     * "factors" counts.
     *
     * @param  list<Category>  $categories
     * @return list<Category>
     */
    private function authenticating(array $categories): array
    {
        return array_values(array_filter($categories, fn (Category $category) => $category->authenticates()));
    }

    /**
     * @param  list<Verification>  $verifications
     */
    private function hasDeviceBoundKey(array $verifications): bool
    {
        return array_any($verifications, fn (Verification $verification) => ($verification->phishingResistant && $verification->deviceBound) || $this->standsIn($verification));
    }

    /**
     * @param  list<Verification>  $verifications
     */
    private function hasPhishingResistant(array $verifications): bool
    {
        return array_any($verifications, fn (Verification $verification) => $verification->phishingResistant || $this->standsIn($verification));
    }
}
