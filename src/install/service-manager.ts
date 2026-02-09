import os from 'node:os';
import { execFileSync } from 'node:child_process';
import {
  installLaunchAgent,
  uninstallLaunchAgent,
  SERVICE_LABEL,
} from './launchd-installer.js';
import {
  installSystemdService,
  uninstallSystemdService,
  SERVICE_NAME,
} from './systemd-installer.js';

type Platform = 'darwin' | 'linux';

function getPlatform(): Platform {
  const platform = os.platform();
  if (platform === 'darwin' || platform === 'linux') {
    return platform;
  }
  throw new Error(`Unsupported platform: ${platform}`);
}

export function install(nodePath: string, scriptPath: string): void {
  const platform = getPlatform();
  if (platform === 'darwin') {
    installLaunchAgent(nodePath, scriptPath);
    console.log(`Installed macOS LaunchAgent: ${SERVICE_LABEL}`);
  } else {
    installSystemdService(nodePath, scriptPath);
    console.log(`Installed Linux systemd service: ${SERVICE_NAME}`);
  }
}

export function uninstall(): void {
  const platform = getPlatform();
  if (platform === 'darwin') {
    uninstallLaunchAgent();
    console.log(`Uninstalled macOS LaunchAgent: ${SERVICE_LABEL}`);
  } else {
    uninstallSystemdService();
    console.log(`Uninstalled Linux systemd service: ${SERVICE_NAME}`);
  }
}

export function status(): string {
  const platform = getPlatform();
  try {
    if (platform === 'darwin') {
      const output = execFileSync(
        'launchctl',
        ['list', SERVICE_LABEL],
        { encoding: 'utf-8' },
      );
      return `Service: ${SERVICE_LABEL}\nStatus: Active\n${output}`;
    } else {
      const output = execFileSync(
        'systemctl',
        ['--user', 'status', SERVICE_NAME],
        { encoding: 'utf-8' },
      );
      return output;
    }
  } catch {
    return 'Service is not running or not installed';
  }
}
