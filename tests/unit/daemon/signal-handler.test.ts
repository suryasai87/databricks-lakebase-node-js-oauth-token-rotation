import { SignalHandler } from '../../../src/daemon/signal-handler';

// Mock the logger
jest.mock('../../../src/logging/logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }),
}));

// Mock process.exit to prevent actually exiting
const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as never);

describe('SignalHandler', () => {
  let handler: SignalHandler;

  beforeEach(() => {
    jest.clearAllMocks();
    handler = new SignalHandler();
  });

  afterEach(() => {
    // Remove all listeners we may have added to avoid leaking between tests
    process.removeAllListeners('SIGTERM');
    process.removeAllListeners('SIGINT');
  });

  it('should not be aborted initially', () => {
    expect(handler.isAborted()).toBe(false);
  });

  it('should provide a non-aborted AbortSignal initially', () => {
    const signal = handler.getAbortSignal();
    expect(signal.aborted).toBe(false);
  });

  it('should register cleanup functions without error', () => {
    const fn = jest.fn(async () => {});
    expect(() => handler.onCleanup(fn)).not.toThrow();
  });

  it('should install signal handlers for SIGTERM and SIGINT', () => {
    const onSpy = jest.spyOn(process, 'on');
    handler.install();

    const signalCalls = onSpy.mock.calls.filter(
      ([event]) => event === 'SIGTERM' || event === 'SIGINT',
    );
    expect(signalCalls.length).toBe(2);

    onSpy.mockRestore();
  });

  it('should run cleanup functions on SIGTERM', async () => {
    const cleanupFn = jest.fn(async () => {});
    handler.onCleanup(cleanupFn);
    handler.install();

    // Emit SIGTERM
    process.emit('SIGTERM', 'SIGTERM');

    // Wait for async cleanup to complete
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(cleanupFn).toHaveBeenCalledTimes(1);
    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it('should run cleanup functions on SIGINT', async () => {
    const cleanupFn = jest.fn(async () => {});
    handler.onCleanup(cleanupFn);
    handler.install();

    // Emit SIGINT
    process.emit('SIGINT', 'SIGINT');

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(cleanupFn).toHaveBeenCalledTimes(1);
    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it('should run cleanup functions in reverse order (LIFO)', async () => {
    const order: number[] = [];
    handler.onCleanup(async () => { order.push(1); });
    handler.onCleanup(async () => { order.push(2); });
    handler.onCleanup(async () => { order.push(3); });
    handler.install();

    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(order).toEqual([3, 2, 1]);
  });

  it('should set aborted state after receiving signal', async () => {
    handler.install();

    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(handler.isAborted()).toBe(true);
    expect(handler.getAbortSignal().aborted).toBe(true);
  });

  it('should only run cleanup once even if signal is sent twice', async () => {
    const cleanupFn = jest.fn(async () => {});
    handler.onCleanup(cleanupFn);
    handler.install();

    process.emit('SIGTERM', 'SIGTERM');
    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(cleanupFn).toHaveBeenCalledTimes(1);
  });

  it('should handle errors in cleanup functions gracefully', async () => {
    const errorFn = jest.fn(async () => {
      throw new Error('cleanup error');
    });
    const successFn = jest.fn(async () => {});

    handler.onCleanup(successFn);
    handler.onCleanup(errorFn);
    handler.install();

    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Both functions should have been called (error in one doesn't block the other)
    expect(errorFn).toHaveBeenCalledTimes(1);
    expect(successFn).toHaveBeenCalledTimes(1);
    expect(mockExit).toHaveBeenCalledWith(0);
  });
});
