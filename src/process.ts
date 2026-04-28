import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";

export interface SafeSpawnRequest {
  command: string;
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

const SHELL_METACHARS = /[|&;<>()`$]/;
const SHELL_EXECUTABLES = /^(cmd|cmd\.exe|sh|bash|zsh|fish|powershell|powershell\.exe|pwsh|pwsh\.exe)$/i;

export function validateSafeSpawn(request: SafeSpawnRequest): void {
  if (!request.command || request.command.trim() !== request.command) {
    throw new Error("Spawn command must be a non-empty executable name or path.");
  }
  if (SHELL_EXECUTABLES.test(request.command)) {
    throw new Error("Refusing to spawn an interactive shell executable.");
  }
  if (SHELL_METACHARS.test(request.command)) {
    throw new Error("Spawn command must not contain shell metacharacters.");
  }
  for (const arg of request.args ?? []) {
    if (arg.includes("\0")) {
      throw new Error("Spawn arguments must not contain NUL bytes.");
    }
  }
}

export function spawnSafe(request: SafeSpawnRequest): ChildProcess {
  validateSafeSpawn(request);
  const options: SpawnOptions = {
    cwd: request.cwd,
    env: request.env,
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  };
  return spawn(request.command, request.args ?? [], options);
}
