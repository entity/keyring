<?php

declare(strict_types=1);

// docs/sso-providers.md gives each driver in full, and the tests run the
// copies in tests/Fixtures/Sso. They're the same code but for the
// namespace and the file's header, so they can't drift apart.
it('has the drivers docs/sso-providers.md gives match the ones the tests run', function () {
    preg_match_all('/```php\n(namespace App\\\\Sso;\n.*?)```/s', (string) file_get_contents(__DIR__.'/../../docs/sso-providers.md'), $blocks);

    $documented = [];

    foreach ($blocks[1] as $block) {
        preg_match('/^class (\w+)/m', $block, $class);
        $documented[$class[1]] = preg_replace('/^namespace App\\\\Sso;\n/', '', $block);
    }

    $fixtures = glob(__DIR__.'/../Fixtures/Sso/*.php');

    expect(array_keys($documented))->toEqualCanonicalizing(array_map(fn (string $path) => basename($path, '.php'), $fixtures));

    foreach ($fixtures as $path) {
        $code = preg_replace('/^<\?php\n\ndeclare\(strict_types=1\);\n\nnamespace Keyring\\\\Tests\\\\Fixtures\\\\Sso;\n/', '', (string) file_get_contents($path));

        expect(trim($documented[basename($path, '.php')]))->toBe(trim($code), basename($path).' differs from docs/sso-providers.md');
    }
});
