// Global test setup
// Suppress console output during tests unless debugging
if (!process.env['DEBUG_TESTS']) {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'debug').mockImplementation(() => {});
}
