import winston from 'winston';
import path from 'node:path';
import os from 'node:os';
import { humanFormat, fileFormat } from './log-formatter.js';

let _logger: winston.Logger | null = null;

function expandPath(filePath: string): string {
  if (filePath.startsWith('~/')) {
    return path.join(os.homedir(), filePath.slice(2));
  }
  return filePath;
}

export function createLogger(logFilePath?: string): winston.Logger {
  const resolvedPath = expandPath(
    logFilePath ?? '~/.databricks_oauth_rotator.log',
  );

  const logger = winston.createLogger({
    level: 'debug',
    transports: [
      new winston.transports.Console({
        level: 'info',
        format: humanFormat,
      }),
      new winston.transports.File({
        filename: resolvedPath,
        level: 'debug',
        format: fileFormat,
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5,
        tailable: true,
      }),
    ],
  });

  _logger = logger;
  return logger;
}

export function getLogger(): winston.Logger {
  if (!_logger) {
    _logger = createLogger();
  }
  return _logger;
}

export { expandPath };
