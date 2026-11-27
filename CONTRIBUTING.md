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

CI also requires every line of `src/` and `js/src/` to be covered by a test. That needs a coverage driver, pcov or Xdebug, and PHP runs with assertions on so the `assert()` calls count too. `bin/ci tests js` checks coverage the same way CI does. If a line really can't be reached by a test, such as one that only runs when two requests race each other, give it a `@codeCoverageIgnore` comment that says why.

The `bin/ci` script runs every CI job on your own machine. That covers the checks above, the oldest dependencies Keyring allows, PostgreSQL, MySQL (in Docker), and the browser package. To run only some of the jobs, name them, as in `bin/ci tests js`. Only run one `bin/ci` at a time. The installer's tests publish into a test application that every run shares, so two runs at once fail each other.

The race tests run operations in separate processes against a real database. That means they need PostgreSQL or MySQL, and they run as their own suite. CI runs them on both databases:

```bash
DB_CONNECTION=pgsql DB_DATABASE=keyring_test vendor/bin/pest --testsuite=Concurrency
```

The single sign-on tests use a fake identity provider. The Integration suite signs in with a real one instead: Keycloak, run in Docker on port 8180 and bound to this machine only. It's skipped unless `KEYRING_KEYCLOAK_URL` is set, so `composer check` and CI don't run it. `bin/keycloak test` starts Keycloak, sets up a realm, runs the suite against it, and removes the container. To keep Keycloak running between runs, use `bin/keycloak start`, then `KEYRING_KEYCLOAK_URL=http://127.0.0.1:8180 vendor/bin/pest --testsuite=Integration`, and `bin/keycloak stop` when you're done.

Please don't open a public issue for a security problem. The [security policy](SECURITY.md) explains how to report one.
