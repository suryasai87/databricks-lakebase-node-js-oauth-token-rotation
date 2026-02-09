import jwt from 'jsonwebtoken';
import type { TokenInfo } from '../types/token.types.js';

interface JwtPayload {
  sub?: string;
  client_id?: string;
  scope?: string;
  iss?: string;
  aud?: string;
  exp?: number;
  iat?: number;
}

export function decodeToken(token: string): TokenInfo {
  const decoded = jwt.decode(token, { complete: false }) as JwtPayload | null;

  if (!decoded) {
    return {
      scopes: [],
      isExpired: true,
    };
  }

  const now = Date.now() / 1000;
  const expiresInMinutes = decoded.exp
    ? (decoded.exp - now) / 60
    : undefined;

  return {
    subject: decoded.sub,
    clientId: decoded.client_id,
    scopes: decoded.scope ? decoded.scope.split(' ') : [],
    issuer: decoded.iss,
    audience: typeof decoded.aud === 'string' ? decoded.aud : undefined,
    expiresAt: decoded.exp
      ? new Date(decoded.exp * 1000).toISOString()
      : undefined,
    expiresInMinutes: expiresInMinutes
      ? Math.round(expiresInMinutes * 100) / 100
      : undefined,
    isExpired: decoded.exp ? now >= decoded.exp : undefined,
    issuedAt: decoded.iat
      ? new Date(decoded.iat * 1000).toISOString()
      : undefined,
  };
}

export function isTokenExpired(token: string): boolean {
  const info = decodeToken(token);
  return info.isExpired ?? true;
}

export function getTokenExpiryMinutes(token: string): number | undefined {
  const info = decodeToken(token);
  return info.expiresInMinutes;
}
