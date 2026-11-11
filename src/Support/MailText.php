<?php

declare(strict_types=1);

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

    /**
     * A line that ends with where to reach the app's support: its
     * "support_contact", which is a page or an email address. Either is
     * written as a Markdown link, which the plain-text part shows in full.
     * Anything else, like a phone number, stays plain text.
     */
    public static function contact(string $text, string $contact): HtmlString
    {
        $href = match (true) {
            filter_var($contact, FILTER_VALIDATE_EMAIL) !== false => 'mailto:'.$contact,
            Str::startsWith($contact, ['https://', 'http://']) && preg_match('/[\s<>()]/', $contact) === 0 => $contact,
            default => null,
        };

        return new HtmlString(self::plain($text).' '.($href === null ? self::plain($contact) : '['.self::plain($contact).']('.$href.')'));
    }

    /**
     * An address with all but the first letter of its name hidden, to hint
     * at it without giving it away: t•••@example.com.
     */
    public static function maskAddress(string $email): string
    {
        [$name, $domain] = array_pad(explode('@', $email, 2), 2, '');

        return mb_substr($name, 0, 1).'•••@'.$domain;
    }
}
