import winston from 'winston';

export const humanFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message }) => {
    return `${timestamp} - ${level.toUpperCase()} - ${message}`;
  }),
);

export const jsonFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.json(),
);

export const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message }) => {
    return `${timestamp} - databricks-rotator - ${level.toUpperCase()} - ${message}`;
  }),
);
