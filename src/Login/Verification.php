<?php

namespace Keyring\Login;

use Keyring\Enums\Category;
use Keyring\Models\Authenticator;

/**
 * A record that a factor was verified, and what it proved.
 *
 * Categories are worked out at verification time rather than enrollment, so a
 * WebAuthn credential only counts as inherence when the authenticator actually
 * verified the user on this occasion.
 */
final readonly class Verification
{
    /**
     * @param  list<Category>  $categories
     */
    public function __construct(
        public string $factor,
        public ?string $authenticator,
        public array $categories,
        public bool $phishingResistant = false,
        public int $at = 0,
        public bool $deviceBound = false,
        public bool $attested = false,
    ) {}

    /**
     * A verification of the authenticator now. Categories, phishing
     * resistance and device binding come from its factor unless the factor
     * saw otherwise. Whether it's attested was settled when it was added.
     *
     * @param  list<Category>|null  $categories
     */
    public static function of(Authenticator $authenticator, ?array $categories = null, ?bool $phishingResistant = null, ?bool $deviceBound = null): self
    {
        $factor = $authenticator->factor();

        return new self(
            factor: $factor->key(),
            authenticator: $authenticator->isVirtual() ? null : $authenticator->id,
            categories: $categories ?? $factor->categories($authenticator),
            phishingResistant: $phishingResistant ?? $factor->phishingResistant($authenticator),
            at: now()->getTimestamp(),
            deviceBound: $deviceBound ?? $factor->deviceBound($authenticator),
            attested: $factor->attested($authenticator),
        );
    }

    /**
     * @return array{factor: string, authenticator: ?string, categories: list<string>, phishing_resistant: bool, at: int, device_bound: bool, attested: bool}
     */
    public function toArray(): array
    {
        return [
            'factor' => $this->factor,
            'authenticator' => $this->authenticator,
            'categories' => array_map(fn (Category $category) => $category->value, $this->categories),
            'phishing_resistant' => $this->phishingResistant,
            'at' => $this->at,
            'device_bound' => $this->deviceBound,
            'attested' => $this->attested,
        ];
    }

    /**
     * @param  array{factor: string, authenticator: ?string, categories: list<string>, phishing_resistant?: bool, at?: int, device_bound?: bool, attested?: bool}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            factor: $data['factor'],
            authenticator: $data['authenticator'],
            categories: array_map(Category::from(...), $data['categories']),
            phishingResistant: $data['phishing_resistant'] ?? false,
            at: $data['at'] ?? 0,
            deviceBound: $data['device_bound'] ?? false,
            attested: $data['attested'] ?? false,
        );
    }
}
