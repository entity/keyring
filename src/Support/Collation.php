<?php

declare(strict_types=1);

namespace Keyring\Support;

use Illuminate\Support\Str;
use Normalizer;

final class Collation
{
    /**
     * Text as the loosest database would compare it: without accents, case,
     * width, spaces or characters that don't show. MySQL's collations take
     * "tàylor" for "taylor", and Laravel's default one takes "Signed_Out "
     * for "signed_out", so two values a query would take for each other
     * fold to the same text.
     *
     * Collations don't agree on "ß": MySQL's utf8mb4_general_ci takes it for
     * "s", and utf8mb4_unicode_ci and utf8mb4_0900_ai_ci for "ss". So a run
     * of "s" folds to one, and "klauß", "klaus" and "klauss" are all found
     * as each other.
     */
    public static function fold(string $value): string
    {
        $value = Normalizer::normalize($value, Normalizer::NFKD) ?: $value;
        $value = preg_replace('/[\p{M}\p{C}\s]+/u', '', $value) ?? $value;
        $value = Str::lower(Str::transliterate($value, ''));

        return preg_replace('/s{2,}/', 's', $value) ?? $value;
    }
}
