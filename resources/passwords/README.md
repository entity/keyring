# Common Passwords

`common.txt` is the list `Keyring\Support\PasswordRules` refuses new passwords from, in every environment and whether or not the breach check can run. OWASP ASVS 6.2.4 asks for at least the top 3,000 passwords that fit the app's password policy. Keyring has two minimum lengths, 8 characters with a second factor and 15 without, so the list holds the top of each.

## Source

[SecLists](https://github.com/danielmiessler/SecLists), maintained by Daniel Miessler, Jason Haddix, Ignacio Portal and g0tmi1k, at tag `2026.2` (commit `145f1f45ba7bc5fd6b3966d3a79bf95654deb20e`):

| File | SHA-256 |
|---|---|
| [`Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt`](https://raw.githubusercontent.com/danielmiessler/SecLists/145f1f45ba7bc5fd6b3966d3a79bf95654deb20e/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt) | `424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51` |
| [`Passwords/Common-Credentials/10k-most-common.txt`](https://raw.githubusercontent.com/danielmiessler/SecLists/145f1f45ba7bc5fd6b3966d3a79bf95654deb20e/Passwords/Common-Credentials/10k-most-common.txt) | `68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce` |

The first is the million most common passwords in the xato.net set of ten million, most common first. The second is the list Keyring shipped before, kept so nothing it refused is let through now.

## What's in the List

Each source line is trimmed and lowercased, and a line that then repeats an earlier one is dropped, which leaves 966,730 passwords in the first file: 476,787 of 8 characters or more, and 10,898 of 15 or more. From those, in the file's order:

| Entries | |
|---|---|
| 10,000 | The most common of 8 characters or more. |
| 3,000 | The most common of 15 characters or more. 10 are already among the 10,000. |
| 2,087 | Every entry of 8 characters or more in `10k-most-common.txt`. 62 are in neither set above. |

That makes 13,052 entries, 3,001 of them 15 characters or more, sorted by byte value, one per line. All are printable ASCII without spaces at either end, and the longest is 33 characters. The file is about 144 KB.

Passwords of 15 characters or more are rare in the source: the 3,000th is its 757,575th entry, so the long ones are far less common than the short ones.

## How It's Compared

`PasswordRules` reads the file once per process into an array keyed by password, so a lookup is one hash lookup. A new password is trimmed and lowercased before it's looked up, which is why every entry is stored that way: `Sunshine1 ` is refused because `sunshine1` is listed.

`tests/Feature/PasswordRulesTest.php` pins the counts above and the file's shape. Rebuild the list by the steps above and update both together.

## Licence

SecLists is MIT licensed:

> MIT License
>
> Copyright (c) 2018 Daniel Miessler
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
