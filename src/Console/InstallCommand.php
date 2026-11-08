<?php

namespace Keyring\Console;

use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\ServiceProvider;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'keyring:install')]
#[Description('Install Keyring: config, migrations, a service provider and your registration action')]
#[Signature('keyring:install
        {--force : Overwrite files that already exist}')]
class InstallCommand extends Command
{
    public function handle(Filesystem $files): int
    {
        $this->callSilently('vendor:publish', ['--tag' => 'keyring-config', '--force' => $this->option('force')]);

        // Publishing again would add the migrations twice, under new timestamps.
        if ($files->glob(database_path('migrations/*_create_keyring_authenticators_table.php')) === []) {
            $this->callSilently('vendor:publish', ['--tag' => 'keyring-migrations']);
        }

        $this->copy($files, $this->stub('KeyringServiceProvider.php'), app_path('Providers/KeyringServiceProvider.php'));
        $this->copy($files, $this->stub('CreateNewUser.php'), app_path('Actions/Keyring/CreateNewUser.php'));

        ServiceProvider::addProviderToBootstrapFile('App\\Providers\\KeyringServiceProvider');

        $this->components->info('Keyring installed.');
        $this->components->bulletList([
            'Add <comment>use Keyring\Concerns\HasKeyring;</comment> to your User model',
            'Run <comment>php artisan migrate</comment>',
            'Build the <comment>auth/*</comment> pages Keyring renders, see the "Pages" docs',
            'Already using Fortify? Run <comment>php artisan keyring:import fortify</comment>',
        ]);

        return self::SUCCESS;
    }

    /**
     * Copy a stub into the app, leaving anything already there unless --force.
     */
    protected function copy(Filesystem $files, string $from, string $to): void
    {
        if ($files->exists($to) && ! $this->option('force')) {
            $this->components->warn("Skipped {$to}, it already exists.");

            return;
        }

        $files->ensureDirectoryExists(dirname($to));
        $files->copy($from, $to);
    }

    protected function stub(string $path): string
    {
        return __DIR__.'/../../stubs/'.$path;
    }
}
