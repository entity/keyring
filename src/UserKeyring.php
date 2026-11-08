<?php

namespace Keyring;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * Everything a user can sign in with, across every registered factor.
 */
class UserKeyring
{
    /** @var Collection<int, Authenticator>|null */
    protected ?Collection $authenticators = null;

    public function __construct(
        public readonly Authenticatable&Model $user,
    ) {}

    /**
     * Every confirmed authenticator, defaults first, then by factor priority.
     *
     * @return Collection<int, Authenticator>
     */
    public function all(): Collection
    {
        return $this->authenticators ??= $this->load();
    }

    /**
     * The authenticator offered first for an extra factor.
     */
    public function default(): ?Authenticator
    {
        return $this->all()->firstWhere('is_default', true)
            ?? $this->all()->first(fn (Authenticator $authenticator) => ! $authenticator->isVirtual());
    }

    /**
     * @return Collection<int, Authenticator>
     */
    public function of(string $factor): Collection
    {
        return $this->all()->where('factor', $factor)->values();
    }

    public function find(?string $id): ?Authenticator
    {
        return $id === null ? null : $this->all()->first(fn (Authenticator $authenticator) => $authenticator->id === $id);
    }

    public function has(Category $category): bool
    {
        return $this->all()->contains(
            fn (Authenticator $authenticator) => in_array($category, $authenticator->factor()->categories($authenticator), true),
        );
    }

    /**
     * Whether the user's authenticators could, together, meet the requirement.
     */
    public function canMeet(Requirement $requirement): bool
    {
        return $requirement->isMetBy($this->all()->map(fn (Authenticator $authenticator) => Verification::of($authenticator))->all());
    }

    /**
     * Authenticators that would bring the verifications closer to the requirement.
     *
     * @param  list<Verification>  $verifications
     * @return Collection<int, Authenticator>
     */
    public function usefulFor(Requirement $requirement, array $verifications): Collection
    {
        $used = array_filter(array_map(fn (Verification $verification) => $verification->authenticator ?? $verification->factor, $verifications));

        return $this->all()
            ->reject(fn (Authenticator $authenticator) => in_array($authenticator->id, $used, true))
            ->filter(fn (Authenticator $authenticator) => $requirement->wouldProgress(
                $verifications,
                $authenticator->factor()->categories($authenticator),
                $authenticator->factor()->phishingResistant($authenticator),
                $authenticator->factor,
            ))
            ->values();
    }

    /**
     * The keyring as it would be without the given authenticators.
     */
    public function without(Authenticator ...$authenticators): static
    {
        $ids = array_map(fn (Authenticator $authenticator) => $authenticator->id, $authenticators);

        $keyring = clone $this;
        $keyring->authenticators = $this->all()->reject(fn (Authenticator $other) => in_array($other->id, $ids, true))->values();

        return $keyring;
    }

    /**
     * Whether any authenticator can start a login on its own.
     */
    public function canSignIn(): bool
    {
        return $this->all()->contains(function (Authenticator $authenticator) {
            $factor = $authenticator->factor();

            return $factor instanceof PrimaryFactor && $factor->startsLogin();
        });
    }

    public function refresh(): static
    {
        $this->authenticators = null;

        return $this;
    }

    /**
     * @return Collection<int, Authenticator>
     */
    protected function load(): Collection
    {
        $stored = Keyring::authenticatorModel()::query()
            ->whereMorphedTo('authenticatable', $this->user)
            ->confirmed()
            ->get()
            ->each(fn (Authenticator $authenticator) => $authenticator->setRelation('authenticatable', $this->user));

        return Keyring::registered()
            ->flatMap(fn (Factor $factor) => $factor->authenticators($this->user, $stored))
            ->sortBy([
                fn (Authenticator $a, Authenticator $b) => $b->is_default <=> $a->is_default,
                fn (Authenticator $a, Authenticator $b) => $b->factor()->priority() <=> $a->factor()->priority(),
                fn (Authenticator $a, Authenticator $b) => $a->created_at <=> $b->created_at,
            ])
            ->values();
    }
}
