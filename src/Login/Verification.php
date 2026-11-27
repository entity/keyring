<?php

declare(strict_types=1);

namespace Keyring\Login;

use Keyring\Enums\Category;
use Keyring\Models\Authenticator;

/**
 * A record that a factor was verified, and what it proved.
 *
 * Categories are worked out at verification time rather than enrollment, so a
 * WebAuthn credential only counts as inherence when the authenticator actually
 * verified the user on this occasion.
 *
 * "at" is when Keyring checked it, which is what assurance levels and their
 * timeouts go by. "authenticatedAt" is when the user really proved it, for
 * a factor that hears of one earlier than that: an identity provider whose
 * ID token says, with auth_time, that the user signed in there an hour ago
 * and was let straight through this time. Freshness (keyring.fresh, and
 * StepUp with a moment) goes by that instead, so a sign in nobody typed
 * anything for doesn't count as a recent verification. UNKNOWN when the
 * factor should have heard when and didn't, so it never counts as recent.
 * Null when they're the same.
 */
final readonly class Verification
{
    /**
     * The authenticatedAt of a verification whose factor should have heard
     * when the user proved it and didn't: unknown, so treat it as not
     * recent. Only freshness goes by it; the verification still counts
     * toward the session's assurance level from "at".
     */
    public const int UNKNOWN = 0;

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
        public ?int $authenticatedAt = null,
    ) {}

    /**
     * When the user last proved it: authenticatedAt, unless that's later
     * than when it was checked. UNKNOWN when that's unknown.
     */
    public function provedAt(): int
    {
        return min($this->at, $this->authenticatedAt ?? $this->at);
    }

    /**
     * A verification of the authenticator now. Categories, phishing
     * resistance and device binding come from its factor unless the factor
     * saw otherwise. Whether it's attested was settled when it was added.
     * $authenticatedAt is when the user really proved it, if earlier.
     *
     * @param  list<Category>|null  $categories
     */
    public static function of(Authenticator $authenticator, ?array $categories = null, ?bool $phishingResistant = null, ?bool $deviceBound = null, ?int $authenticatedAt = null): self
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
            authenticatedAt: $authenticatedAt,
        );
    }

    /**
     * @return array{factor: string, authenticator: ?string, categories: list<string>, phishing_resistant: bool, at: int, device_bound: bool, attested: bool, authenticated_at?: int}
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
            ...($this->authenticatedAt === null ? [] : ['authenticated_at' => $this->authenticatedAt]),
        ];
    }

    /**
     * @param  array{factor: string, authenticator: ?string, categories: list<string>, phishing_resistant?: bool, at?: int, device_bound?: bool, attested?: bool, authenticated_at?: int}  $data
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
            authenticatedAt: $data['authenticated_at'] ?? null,
        );
    }
}
