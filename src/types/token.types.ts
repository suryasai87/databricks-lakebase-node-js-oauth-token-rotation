export interface TokenInfo {
  subject?: string;
  clientId?: string;
  scopes: string[];
  issuer?: string;
  audience?: string;
  expiresAt?: string;
  expiresInMinutes?: number;
  isExpired?: boolean;
  issuedAt?: string;
}

export interface TokenProvider {
  readonly name: string;
  getToken(): Promise<string | null>;
  isAvailable(): Promise<boolean>;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}
