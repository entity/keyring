<?php

namespace Keyring\Factors;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Contracts\Enrollable;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Support\Input;
use LogicException;
use PragmaRX\Google2FA\Google2FA;

/**
 * Time-based one-time passwords from an authenticator app (RFC 6238).
 *
 * The last accepted time step is stored on the authenticator, so a code can't
 * be replayed within its window.
 */
class Totp extends Factor implements Enrollable
{
    public const string KEY = 'totp';

    /** The most 30 second steps either side of now a code may be from. */
    public const int MAX_WINDOW = 1;

    /**
     * A window of 1 takes the step before and the step after now as well,
     * as RFC 6238 recommends for a clock that's a little off, so a code
     * works for up to 90 seconds. OWASP ASVS 6.5.5 caps a code's life at 30
     * seconds, which is a window of 0. Nothing wider than 1 is accepted.
     *
     * @throws LogicException
     */
    public function __construct(
        protected Google2FA $engine,
        protected int $window = 1,
        protected ?string $issuer = null,
    ) {
        throw_if($window < 0 || $window > self::MAX_WINDOW, LogicException::class, sprintf(
            'The [%s] factor was given a window of %d. Keyring accepts 0 (a code works for its own 30 seconds, as OWASP ASVS 6.5.5 asks) or 1 (one step either side, for clocks that are a little off): a wider one keeps every code working for minutes.',
            self::KEY, $window,
        ));
    }

    public function key(): string
    {
        return self::KEY;
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Possession];
    }

    public function priority(): int
    {
        return 60;
    }

    public function rules(): array
    {
        return ['code' => ['required', 'string', 'max:16']];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $timestep = $authenticator->secret === null ? false : $this->check($authenticator->secret, $request, (int) $authenticator->meta('last_timestep', 0));

        $used = $timestep !== false && $this->consume($authenticator, function (Authenticator $locked) use ($timestep) {
            if ($timestep <= (int) $locked->meta('last_timestep', 0)) {
                return false;
            }

            $locked->withMeta('last_timestep', $timestep);

            return true;
        });

        return $used ? $this->verified($authenticator) : null;
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        $secret = $this->engine->generateSecretKey(32);
        $url = $this->engine->getQRCodeUrl($this->issuer ?? config('app.name') ?? '', (string) $user->getAttribute(Keyring::username()), $secret);

        return Enrollment::make($this->key(), [
            'secret' => $secret,
            'url' => $url,
            'qr' => $this->qr($url),
        ], [
            'secret' => $secret,
            'name' => $this->nameFrom($request, __('Authenticator app')),
        ]);
    }

    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        if (($timestep = $this->check($enrollment->state('secret'), $request)) === false) {
            return null;
        }

        return $this->makeAuthenticator([
            'name' => $this->nameFrom($request, $enrollment->state('name')),
            'secret' => $enrollment->state('secret'),
            'meta' => ['last_timestep' => $timestep],
        ]);
    }

    /**
     * The time step the request's code is from, if it's a valid code for the
     * secret newer than the given step.
     */
    protected function check(#[\SensitiveParameter] string $secret, Request $request, int $after = 0): int|false
    {
        $code = $this->normalizeCode((string) Input::get($request, 'code'));

        $timestep = ctype_digit($code)
            ? $this->engine->verifyKeyNewer($secret, $code, $after, $this->window, static::timestep())
            : false;

        return is_int($timestep) ? $timestep : false;
    }

    protected function qr(string $url): string
    {
        $svg = new Writer(new ImageRenderer(new RendererStyle(192, 0), new SvgImageBackEnd))->writeString($url);

        return trim(substr($svg, strpos($svg, "\n") + 1));
    }

    /**
     * The current 30 second step, on Laravel's clock rather than the system
     * one, so tests can travel through time.
     */
    public static function timestep(int $offset = 0): int
    {
        return intdiv(now()->getTimestamp(), 30) + $offset;
    }
}
