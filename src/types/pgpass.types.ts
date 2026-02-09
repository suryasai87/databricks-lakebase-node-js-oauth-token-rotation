export interface PgPassEntry {
  hostname: string;
  port: string;
  database: string;
  username: string;
  password: string;
}

export interface PgPassUpdateResult {
  success: boolean;
  action: 'created' | 'updated' | 'appended';
  filePath: string;
  error?: string;
}
