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
 *
 * providerAmr and providerAcr are what an identity provider said, with
 * "amr" and "acr" in its ID token, about how the user signed in there: its
 * claim, kept for an app that reports it on, and never Keyring's own. They
 * count toward nothing: not the categories, the session's level, phishing
 * resistance or freshness, however strong they sound.
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
     * @param  list<string>  $providerAmr  the "amr" values the identity provider sent, as it named them
     * @param  ?string  $providerAcr  the "acr" the identity provider sent
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
        public array $providerAmr = [],
        public ?string $providerAcr = null,
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
     * When the user last proved it, as provedAt() says, or null when that's
     * unknown (UNKNOWN). Reach for this when reporting the time, such as
     * auth_time, so an unknown one can't read as a sign in from 1970.
     */
    public function provedAtIfKnown(): ?int
    {
        $provedAt = $this->provedAt();

        return $provedAt === self::UNKNOWN ? null : $provedAt;
    }

    /**
     * A verification of the authenticator now. Categories, phishing
     * resistance and device binding come from its factor unless the factor
     * saw otherwise. Whether it's attested was settled when it was added.
     * $authenticatedAt is when the user really proved it, if earlier.
     * $providerAmr and $providerAcr are an identity provider's say, kept as
     * they're given.
     *
     * @param  list<Category>|null  $categories
     * @param  list<string>  $providerAmr
     */
    public static function of(Authenticator $authenticator, ?array $categories = null, ?bool $phishingResistant = null, ?bool $deviceBound = null, ?int $authenticatedAt = null, array $providerAmr = [], ?string $providerAcr = null): self
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
            providerAmr: $providerAmr,
            providerAcr: $providerAcr,
        );
    }

    /**
     * The provider's claims are only there when it made them, so a
     * verification of any other factor keeps the shape it always had.
     *
     * @return array{factor: string, authenticator: ?string, categories: list<string>, phishing_resistant: bool, at: int, device_bound: bool, attested: bool, authenticated_at?: int, provider_amr?: list<string>, provider_acr?: string}
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
            ...($this->providerAmr === [] ? [] : ['provider_amr' => $this->providerAmr]),
            ...($this->providerAcr === null ? [] : ['provider_acr' => $this->providerAcr]),
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        // Serialised natively by an earlier release, such as inside a queued
        // listener's job, it has no authenticatedAt, providerAmr or
        // providerAcr: they load with their defaults.
        $this->factor = $data['factor'];
        $this->authenticator = $data['authenticator'];
        $this->categories = $data['categories'];
        $this->phishingResistant = $data['phishingResistant'];
        $this->at = $data['at'];
        $this->deviceBound = $data['deviceBound'];
        $this->attested = $data['attested'];
        $this->authenticatedAt = $data['authenticatedAt'] ?? null;
        $this->providerAmr = $data['providerAmr'] ?? [];
        $this->providerAcr = $data['providerAcr'] ?? null;
    }

    /**
     * One saved before a key was added, such as by a session from an
     * earlier release, loads with that key's default.
     *
     * @param  array{factor: string, authenticator: ?string, categories: list<string>, phishing_resistant?: bool, at?: int, device_bound?: bool, attested?: bool, authenticated_at?: int, provider_amr?: list<string>, provider_acr?: string}  $data
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
            providerAmr: $data['provider_amr'] ?? [],
            providerAcr: $data['provider_acr'] ?? null,
        );
    }
}
