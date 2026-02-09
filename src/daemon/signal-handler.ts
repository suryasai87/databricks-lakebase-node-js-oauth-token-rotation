import { getLogger } from '../logging/logger.js';

type CleanupFn = () => Promise<void>;

export class SignalHandler {
  private cleanupFns: CleanupFn[] = [];
  private isShuttingDown = false;
  private abortController: AbortController;

  constructor() {
    this.abortController = new AbortController();
  }

  /**
   * Register a cleanup function to run on shutdown.
   * Functions run in reverse registration order (LIFO).
   */
  onCleanup(fn: CleanupFn): void {
    this.cleanupFns.push(fn);
  }

  /**
   * Install signal handlers for SIGTERM and SIGINT.
   */
  install(): void {
    const handler = (signal: string) => {
      void this.shutdown(signal);
    };

    process.on('SIGTERM', () => handler('SIGTERM'));
    process.on('SIGINT', () => handler('SIGINT'));
  }

  /**
   * Returns an AbortSignal that fires on shutdown.
   * Use this to cancel pending operations (setTimeout, fetch, etc.)
   */
  getAbortSignal(): AbortSignal {
    return this.abortController.signal;
  }

  isAborted(): boolean {
    return this.abortController.signal.aborted;
  }

  private async shutdown(signal: string): Promise<void> {
    if (this.isShuttingDown) return;
    this.isShuttingDown = true;

    const logger = getLogger();
    logger.info(`Received ${signal}, starting graceful shutdown...`);

    // Abort any pending operations
    this.abortController.abort();

    // Run cleanup functions in reverse order
    for (let i = this.cleanupFns.length - 1; i >= 0; i--) {
      try {
        await this.cleanupFns[i]!();
      } catch (err) {
        logger.error(
          `Cleanup error: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    logger.info('Graceful shutdown complete');
    process.exit(0);
  }
}
