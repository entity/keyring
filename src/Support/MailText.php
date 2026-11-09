<?php

namespace Keyring\Support;

use Illuminate\Support\HtmlString;
use Illuminate\Support\Str;

/**
 * Mail lines are parsed as Markdown, so a value a user or client can influence
 * could add links or images to a genuine security email. A character reference
 * can't form Markdown, and the HTML and plain-text parts both decode it, so
 * the text reads exactly as written in each.
 */
final class MailText
{
    public static function plain(string $text): HtmlString
    {
        return new HtmlString((string) preg_replace_callback(
            '/[!-\/:-@\[-`{-~]/',
            fn (array $match) => '&#'.ord($match[0]).';',
            Str::squish(mb_scrub($text)),
        ));
    }
}
