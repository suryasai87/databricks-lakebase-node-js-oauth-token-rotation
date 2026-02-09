// Mock the logger
jest.mock('../../../src/logging/logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }),
}));

// We need to mock the promisified execFile. The source does:
//   import { execFile } from 'node:child_process';
//   const execFileAsync = promisify(execFile);
//
// jest.mock factories are hoisted, so we use a global __mockExecFileAsync
// that can be assigned during factory execution.
const __mockExecFileAsync = jest.fn();

jest.mock('node:child_process', () => ({
  execFile: jest.fn(),
}));

jest.mock('node:util', () => {
  const original = jest.requireActual('node:util');
  return {
    ...original,
    promisify: jest.fn(() => __mockExecFileAsync),
  };
});

import { CliFallbackProvider } from '../../../src/auth/cli-fallback.provider';

describe('CliFallbackProvider', () => {
  let provider: CliFallbackProvider;

  beforeEach(() => {
    __mockExecFileAsync.mockReset();
    provider = new CliFallbackProvider('https://my-workspace.databricks.com');
  });

  it('should have name set to cli-fallback', () => {
    expect(provider.name).toBe('cli-fallback');
  });

  describe('isAvailable', () => {
    it('should return true when databricks CLI responds to --version', async () => {
      __mockExecFileAsync.mockResolvedValueOnce({ stdout: 'Databricks CLI v0.220.0', stderr: '' });
      expect(await provider.isAvailable()).toBe(true);
    });

    it('should return false when databricks CLI is not installed', async () => {
      __mockExecFileAsync.mockRejectedValueOnce(new Error('command not found: databricks'));
      expect(await provider.isAvailable()).toBe(false);
    });
  });

  describe('getToken', () => {
    it('should return a raw JWT token when CLI outputs a JWT directly', async () => {
      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dummysig';
      __mockExecFileAsync.mockResolvedValue({ stdout: fakeJwt, stderr: '' });

      const token = await provider.getToken();
      expect(token).toBe(fakeJwt);
    });

    it('should parse JSON format response and extract access_token', async () => {
      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dummysig';
      const jsonResponse = JSON.stringify({ access_token: fakeJwt });
      __mockExecFileAsync.mockResolvedValue({ stdout: jsonResponse, stderr: '' });

      const token = await provider.getToken();
      expect(token).toBe(fakeJwt);
    });

    it('should extract JWT from mixed output', async () => {
      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dummysig';
      const mixedOutput = `Some log line\nToken: ${fakeJwt}\n`;
      __mockExecFileAsync.mockResolvedValue({ stdout: mixedOutput, stderr: '' });

      const token = await provider.getToken();
      expect(token).toBe(fakeJwt);
    });

    it('should return null when CLI output has no recognizable token', async () => {
      // All calls return unrecognizable output
      __mockExecFileAsync.mockResolvedValue({ stdout: 'no token here', stderr: '' });

      const token = await provider.getToken();
      expect(token).toBeNull();
    });

    it('should attempt login and retry when initial token fetch fails', async () => {
      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig';

      let callCount = 0;
      __mockExecFileAsync.mockImplementation(async (_cmd: string, args: string[]) => {
        callCount++;
        if (Array.isArray(args) && args.includes('login')) {
          return { stdout: 'Login successful', stderr: '' };
        }
        if (callCount === 1) {
          // First tryGetCliToken fails
          throw new Error('not authenticated');
        }
        // Second tryGetCliToken after login succeeds
        return { stdout: fakeJwt, stderr: '' };
      });

      const token = await provider.getToken();
      expect(token).toBe(fakeJwt);
      expect(callCount).toBeGreaterThanOrEqual(3); // tryGetCliToken, login, tryGetCliToken
    });

    it('should return null when both token fetch and login fail', async () => {
      __mockExecFileAsync.mockRejectedValue(new Error('command failed'));

      const token = await provider.getToken();
      expect(token).toBeNull();
    });

    it('should strip trailing slashes from workspace URL', () => {
      const providerWithSlash = new CliFallbackProvider(
        'https://workspace.databricks.com///',
      );
      expect(providerWithSlash.name).toBe('cli-fallback');
    });

    it('should trim whitespace from CLI output', async () => {
      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig';
      __mockExecFileAsync.mockResolvedValue({ stdout: `  \n  ${fakeJwt}  \n  `, stderr: '' });

      const token = await provider.getToken();
      expect(token).toBe(fakeJwt);
    });
  });
});
