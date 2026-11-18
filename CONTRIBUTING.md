# Contributing

```bash
composer test      # tests
composer lint      # code style
composer analyse   # static analysis
composer refactor  # apply Rector's rules
composer check     # everything CI runs: Rector (dry run), Pint, PHPStan and Pest
```

Run `composer check` before opening a pull request.

`bin/ci` runs every CI job on your own machine: the checks above, the oldest dependencies Keyring allows, PostgreSQL, MySQL (in Docker) and the browser package. `bin/ci tests js` runs only the jobs you name. Run one at a time.

The race tests run operations in separate processes against a real database, so they need PostgreSQL or MySQL and run as their own suite (CI runs them on both):

```bash
DB_CONNECTION=pgsql DB_DATABASE=keyring_test vendor/bin/pest --testsuite=Concurrency
```

Please don't open a public issue for a security problem. See the [security policy](SECURITY.md) for how to report one.
