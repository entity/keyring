<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Keyring\Contracts\Enrollable;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Category;
use Keyring\Events\RecoveryCodeUsed;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * Single-use codes the user saved when setting up their first second factor.
 * Stored as keyed hashes, never in plain text.
 */
class RecoveryCodes extends Factor implements Enrollable
{
    public function __construct(
        protected int $count = 8,
    ) {}

    public const KEY = 'recovery';

    public function key(): string
    {
        return self::KEY;
    }

    /**
     * A used-up set proves nothing, so it doesn't count as a factor (or
     * users would be asked for codes they no longer have).
     */
    public function categories(Authenticator $authenticator): array
    {
        return $this->hashes($authenticator) === [] ? [] : [Category::Possession];
    }

    /**
     * Always offered last.
     */
    public function priority(): int
    {
        return 0;
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $candidates = $this->candidates((string) $request->input('code'));

        $used = $this->consume($authenticator, function (Authenticator $locked) use ($candidates) {
            $hashes = $this->hashes($locked);
            $match = array_find_key($hashes, fn (string $stored) => array_any($candidates, fn (string $hash) => hash_equals($stored, $hash)));

            if ($match === null) {
                return false;
            }

            unset($hashes[$match]);
            $locked->secret = json_encode(array_values($hashes));

            return true;
        });

        if (! $used) {
            return null;
        }

        RecoveryCodeUsed::dispatch($authenticator, count($this->hashes($authenticator)));

        return $this->verified($authenticator);
    }

    public function present(Authenticator $authenticator): array
    {
        return [...parent::present($authenticator), 'remaining' => count($this->hashes($authenticator))];
    }

    public function multiple(): bool
    {
        return false;
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        ['codes' => $codes, 'secret' => $secret] = $this->generate();

        return Enrollment::make($this->key(), ['codes' => $codes], ['secret' => $secret]);
    }

    public function enrollmentRules(): array
    {
        return [];
    }

    /**
     * Confirming means "I've saved these". New codes replace the old ones.
     */
    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        return $this->make($enrollment->state('secret'));
    }

    /**
     * A recovery codes authenticator for the given secret.
     */
    public function make(string $secret): Authenticator
    {
        return $this->makeAuthenticator(['name' => __('Recovery codes'), 'secret' => $secret]);
    }

    /**
     * Make a fresh set of codes. Returns the plain codes to show the user once,
     * and the secret to store.
     *
     * @return array{codes: list<string>, secret: string}
     */
    public function generate(): array
    {
        $codes = array_map(
            fn () => Str::lower(Str::random(5).'-'.Str::random(5)),
            range(1, $this->count),
        );

        return ['codes' => $codes, 'secret' => $this->secretFor($codes)];
    }

    /**
     * The value to store for a set of plain codes.
     *
     * @param  list<string>  $codes
     */
    public function secretFor(array $codes): string
    {
        return json_encode(array_map($this->hash(...), $codes));
    }

    /**
     * @return list<string>
     */
    protected function hashes(Authenticator $authenticator): array
    {
        return json_decode($authenticator->secret ?? '[]', true) ?: [];
    }

    protected function hash(string $code, ?string $key = null): string
    {
        return hash_hmac('sha256', Str::lower($this->normalizeCode($code)), $key ?? config('app.key'));
    }

    /**
     * The code hashed with the current key and every previous one, so rotating
     * APP_KEY (with APP_PREVIOUS_KEYS) doesn't throw away saved codes.
     *
     * @return list<string>
     */
    protected function candidates(string $code): array
    {
        return array_map(
            fn (string $key) => $this->hash($code, $key),
            [config('app.key'), ...config('app.previous_keys', [])],
        );
    }
}
