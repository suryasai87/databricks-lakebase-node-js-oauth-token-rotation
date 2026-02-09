import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

const SERVICE_LABEL = 'com.databricks.node.oauth.rotator';

function getPlistPath(): string {
  return path.join(
    os.homedir(),
    'Library',
    'LaunchAgents',
    `${SERVICE_LABEL}.plist`,
  );
}

export function generatePlist(nodePath: string, scriptPath: string): string {
  const logDir = os.homedir();
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${nodePath}</string>
        <string>${scriptPath}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${logDir}/.databricks_node_oauth_rotator_stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${logDir}/.databricks_node_oauth_rotator_stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
    </dict>
</dict>
</plist>`;
}

export function installLaunchAgent(
  nodePath: string,
  scriptPath: string,
): void {
  const plistPath = getPlistPath();
  const dir = path.dirname(plistPath);

  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const content = generatePlist(nodePath, scriptPath);
  writeFileSync(plistPath, content, { mode: 0o644 });

  execFileSync('launchctl', ['load', plistPath]);
}

export function uninstallLaunchAgent(): void {
  const plistPath = getPlistPath();
  if (existsSync(plistPath)) {
    try {
      execFileSync('launchctl', ['unload', plistPath]);
    } catch {
      // May already be unloaded
    }
    const { unlinkSync } = require('node:fs') as typeof import('node:fs');
    unlinkSync(plistPath);
  }
}

export { SERVICE_LABEL, getPlistPath };
