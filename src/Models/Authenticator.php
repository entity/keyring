<?php

namespace Keyring\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;
use Keyring\Contracts\Factor;
use Keyring\Database\Factories\AuthenticatorFactory;
use Keyring\Facades\Keyring;
use LogicException;

/**
 * One way a user can prove who they are: a TOTP app, a security key, a set of
 * recovery codes. Factors without stored state (like the password) are
 * represented by unsaved "virtual" authenticators.
 *
 * @property string $id
 * @property string $factor
 * @property string $name
 * @property string|null $secret
 * @property string|null $credential_id
 * @property string|null $public_key
 * @property int $sign_count
 * @property string|null $aaguid
 * @property list<string>|null $transports
 * @property array<string, mixed>|null $meta
 * @property bool $is_default
 * @property Carbon|null $confirmed_at
 * @property Carbon|null $last_used_at
 * @property Carbon|null $created_at
 */
#[Table('keyring_authenticators')]
#[Unguarded]
#[Hidden('secret', 'public_key', 'credential_id', 'authenticatable_type', 'authenticatable_id')]
#[UseFactory(AuthenticatorFactory::class)]
class Authenticator extends Model
{
    /** @use HasFactory<AuthenticatorFactory> */
    use HasFactory, HasUlids;

    protected function casts(): array
    {
        return [
            'secret' => 'encrypted',
            'transports' => 'array',
            'meta' => 'array',
            'is_default' => 'boolean',
            'sign_count' => 'integer',
            'confirmed_at' => 'datetime',
            'last_used_at' => 'datetime',
        ];
    }

    /**
     * An unsaved authenticator for factors that keep their state elsewhere.
     */
    public static function virtual(Factor $factor, Authenticatable&Model $user, string $name): self
    {
        $model = Keyring::authenticatorModel();

        $authenticator = new $model([
            'id' => $factor->key(),
            'factor' => $factor->key(),
            'name' => $name,
            'confirmed_at' => $user->getAttribute('created_at'),
        ]);

        $authenticator->setRelation('authenticatable', $user);

        return $authenticator;
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    public function user(): Authenticatable&Model
    {
        $user = $this->authenticatable;

        return $user instanceof Authenticatable ? $user : throw new LogicException('The authenticator has no user.');
    }

    public function factor(): Factor
    {
        return Keyring::factor($this->factor);
    }

    public function isVirtual(): bool
    {
        return ! $this->exists && $this->id === $this->factor;
    }

    public function markAsUsed(): void
    {
        if (! $this->isVirtual()) {
            $this->forceFill(['last_used_at' => now()])->save();
        }
    }

    public function meta(string $key, mixed $default = null): mixed
    {
        return data_get($this->meta, $key, $default);
    }

    public function withMeta(string $key, mixed $value): static
    {
        $meta = $this->meta ?? [];
        data_set($meta, $key, $value);
        $this->meta = $meta;

        return $this;
    }

    /**
     * @param  Builder<static>  $query
     */
    public function scopeConfirmed(Builder $query): void
    {
        $query->whereNotNull('confirmed_at');
    }
}
