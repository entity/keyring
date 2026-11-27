<?php

declare(strict_types=1);

namespace Keyring\Enums;

use InvalidArgumentException;

/**
 * How much a sign in or a confirm through an identity provider counts
 * toward a fresh verification (keyring.fresh): a provider's "freshness" in
 * keyring.sso.providers.
 */
enum SsoFreshness: string
{
    // The provider says when the user signed in there (auth_time), and can
    // be asked to have them sign in again (max_age=0, prompt=login). A sign
    // in counts from its auth_time, never when it has none, and a confirm
    // asks for a new sign in and needs an auth_time from after it.
    case Reauthenticate = 'reauthenticate';

    // A sign in, and a confirm, which is a plain round trip to the
    // provider, count as proved when the user comes back, however old their
    // session there is. Someone at a browser still signed in there gets a
    // fresh verification without typing anything.
    case RoundTrip = 'round_trip';

    // A sign in never counts as fresh, and nor does a confirm, a plain
    // round trip that counts toward the session's level alone, as signing
    // in through the provider again would. The confirm page only offers
    // the provider's links toward a level: a fresh verification needs
    // another method.
    case Never = 'never';

    /**
     * A provider's "freshness" from its config: one of the values, false
     * for never, or $default when it's left out.
     *
     * @throws InvalidArgumentException for anything else
     */
    public static function configured(mixed $value, string $provider, self $default): self
    {
        return match (true) {
            $value === null => $default,
            $value === false => self::Never,
            is_string($value) && self::tryFrom($value) !== null => self::from($value),
            default => throw new InvalidArgumentException("Identity provider [{$provider}] has a \"freshness\" that isn't reauthenticate, round_trip or never."),
        };
    }

    /**
     * The one that counts for least: never over reauthenticate over a round
     * trip. A provider that isn't known (null) loosens nothing, and with
     * none known at all, nothing counts.
     */
    public static function strictest(?self ...$modes): self
    {
        $known = array_filter($modes);

        return match (true) {
            $known === [] || in_array(self::Never, $known, true) => self::Never,
            in_array(self::Reauthenticate, $known, true) => self::Reauthenticate,
            default => self::RoundTrip,
        };
    }
}
