# Contributing

Thank you for considering a contribution to Keyring. Every fix, test, and suggestion helps, and we're glad you're here.

Keyring's checks are Composer scripts, listed below:

```bash
composer test      # tests
composer lint      # fix code style with Pint
composer analyse   # static analysis
composer refactor  # apply Rector's rules
composer check     # everything CI runs: Rector (dry run), Pint, PHPStan, and Pest
```

Run `composer check` before opening a pull request.

The `bin/ci` script runs every CI job on your own machine. That covers the checks above, the oldest dependencies Keyring allows, PostgreSQL, MySQL (in Docker), and the browser package. To run only some of the jobs, name them, as in `bin/ci tests js`. Only run one `bin/ci` at a time. The installer's tests publish into a test application that every run shares, so two runs at once fail each other.

The race tests run operations in separate processes against a real database. That means they need PostgreSQL or MySQL, and they run as their own suite. CI runs them on both databases:

```bash
DB_CONNECTION=pgsql DB_DATABASE=keyring_test vendor/bin/pest --testsuite=Concurrency
```

Please don't open a public issue for a security problem. The [security policy](SECURITY.md) explains how to report one.
