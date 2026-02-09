import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

const SERVICE_NAME = 'databricks-node-oauth-rotator';

function getServicePath(): string {
  return path.join(
    os.homedir(),
    '.config',
    'systemd',
    'user',
    `${SERVICE_NAME}.service`,
  );
}

export function generateSystemdUnit(
  nodePath: string,
  scriptPath: string,
): string {
  return `[Unit]
Description=Databricks Lakebase OAuth Token Rotator (Node.js)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${nodePath} ${scriptPath}
Restart=always
RestartSec=60
Environment=PATH=/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target
`;
}

export function installSystemdService(
  nodePath: string,
  scriptPath: string,
): void {
  const servicePath = getServicePath();
  const dir = path.dirname(servicePath);

  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const content = generateSystemdUnit(nodePath, scriptPath);
  writeFileSync(servicePath, content, { mode: 0o644 });

  execFileSync('systemctl', ['--user', 'daemon-reload']);
  execFileSync('systemctl', ['--user', 'enable', SERVICE_NAME]);
  execFileSync('systemctl', ['--user', 'start', SERVICE_NAME]);
}

export function uninstallSystemdService(): void {
  try {
    execFileSync('systemctl', ['--user', 'stop', SERVICE_NAME]);
  } catch {
    // May not be running
  }
  try {
    execFileSync('systemctl', ['--user', 'disable', SERVICE_NAME]);
  } catch {
    // May not be enabled
  }

  const servicePath = getServicePath();
  if (existsSync(servicePath)) {
    const { unlinkSync } = require('node:fs') as typeof import('node:fs');
    unlinkSync(servicePath);
    execFileSync('systemctl', ['--user', 'daemon-reload']);
  }
}

export { SERVICE_NAME, getServicePath };
