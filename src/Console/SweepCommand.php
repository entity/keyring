<?php

declare(strict_types=1);

namespace Keyring\Console;

use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Keyring\Sessions\AnnouncingSessionRegistry;
use Keyring\Sessions\SessionRegistryManager;
use Keyring\Sessions\Sessions;
use Keyring\Sessions\Sweep;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * End the sessions that timed out with no request to end them, and announce
 * again those whose announcement was lost, so every session that ends is
 * announced at least once. Database driver only.
 */
#[AsCommand(name: 'keyring:sweep')]
#[Signature('keyring:sweep')]
#[Description('End timed-out sessions and announce any ended session that was never announced')]
class SweepCommand extends Command
{
    public function handle(SessionRegistryManager $manager, Sessions $sessions): int
    {
        $registry = $manager->driver();
        $sweeper = $registry instanceof AnnouncingSessionRegistry ? $registry->sweeper() : null;

        if ($sweeper === null) {
            $this->components->info('The ['.$manager->getDefaultDriver().'] session registry driver has nothing to sweep. Its sessions are announced as they end.');

            return self::SUCCESS;
        }

        if (! $sweeper->canSweep()) {
            $this->components->error('The sessions table is missing the columns the sweep needs. Publish and run Keyring\'s migrations: php artisan keyring:install, then php artisan migrate.');

            return self::FAILURE;
        }

        $result = $registry->sweep(Sweep::limit(), $sessions->idleLimit(remembered: false), $sessions->idleLimit(remembered: true));

        $this->components->info("Ended {$result?->ended} timed-out sessions, and announced {$result?->announcedAgain} ended sessions again.");

        if ($result?->more) {
            $this->components->warn('More are left than one run may take ('.Sweep::limit().'). The next run carries on.');
        }

        return self::SUCCESS;
    }
}
