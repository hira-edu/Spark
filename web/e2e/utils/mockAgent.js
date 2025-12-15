import { execFileSync, spawn } from 'child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import path from 'path';

const REPO_ROOT = path.join(process.cwd(), '..');
const STATE_DIR = path.join(process.cwd(), '.playwright');
const BIN_DIR = path.join(STATE_DIR, 'bin');
const PID_FILE = path.join(STATE_DIR, 'mock-agent.pid');
const LOG_FILE = path.join(STATE_DIR, 'mock-agent.log');
const TEST_CLIENT_PATH = path.join(REPO_ROOT, 'test_client.go');
const MOCK_HELPER_PATH = path.join(REPO_ROOT, 'test_client_mock_server.go');

function ensureStateDir() {
  if (!existsSync(STATE_DIR)) {
    mkdirSync(STATE_DIR, { recursive: true });
  }
  if (!existsSync(BIN_DIR)) {
    mkdirSync(BIN_DIR, { recursive: true });
  }
}

function readPid() {
  if (!existsSync(PID_FILE)) return 0;
  try {
    return parseInt(readFileSync(PID_FILE, 'utf-8').trim(), 10) || 0;
  } catch {
    return 0;
  }
}

function killTree(pid) {
  if (!pid) return;
  if (process.platform === 'win32') {
    try {
      execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
    } catch {
      // ignore
    }
    return;
  }

  try {
    process.kill(-pid, 'SIGTERM');
  } catch {
    try { process.kill(pid, 'SIGTERM'); } catch {}
  }
}

function buildMockBinary(outPath, logPrefix = '[MockAgent]') {
  ensureStateDir();
  if (!existsSync(TEST_CLIENT_PATH)) {
    throw new Error('test_client.go not found - cannot build mock agent binary');
  }

  console.log(`${logPrefix} Building mock agent binary: ${outPath}`);
  execFileSync('go', [
    'build',
    '-tags',
    'mockserver',
    '-o',
    outPath,
    TEST_CLIENT_PATH,
    MOCK_HELPER_PATH,
  ], { cwd: REPO_ROOT, stdio: 'inherit' });
  return outPath;
}

export function stopMockAgent(logPrefix = '[MockAgent]') {
  const pid = readPid();
  if (!pid) return false;
  killTree(pid);
  try { rmSync(PID_FILE); } catch {}
  console.log(`${logPrefix} Stopped mock agent PID ${pid}`);
  return true;
}

export function getMockAgentLogPath() {
  ensureStateDir();
  return LOG_FILE;
}

export async function ensureMockAgentRunning({
  host = '127.0.0.1',
  port = 18080,
  salt = 'testsalt1234567890123',
  uuidHex = '00112233445566778899aabbccddeeff',
  forceRestart = false,
  logPrefix = '[MockAgent]',
} = {}) {
  ensureStateDir();

  const pid = readPid();
  if (pid && !forceRestart) {
    // Best-effort liveness check.
    try {
      process.kill(pid, 0);
      return { pid, alreadyRunning: true, uuidHex };
    } catch {
      // stale pid
      try { rmSync(PID_FILE); } catch {}
    }
  }

  if (pid && forceRestart) {
    stopMockAgent(logPrefix);
  }

  if (!existsSync(TEST_CLIENT_PATH)) {
    throw new Error('test_client.go not found - cannot start mock agent');
  }

  const binaryPath = buildMockBinary(path.join(BIN_DIR, process.platform === 'win32' ? 'mock-agent.exe' : 'mock-agent'), logPrefix);
  const args = [
    '--host', host,
    '--port', String(port),
    '--salt', salt,
    '--mock-desktop',
    '--uuid-hex', uuidHex,
    '--no-interactive',
  ];

  const child = spawn(binaryPath, args, {
    cwd: REPO_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
    env: {
      ...process.env,
      ROCKET_E2E: '1',
    },
  });

  const logStream = [];
  const append = (chunk) => {
    const text = chunk.toString();
    logStream.push(text);
    // Keep log bounded in memory, while always writing full file.
    if (logStream.length > 2000) logStream.splice(0, logStream.length - 2000);
    try { writeFileSync(LOG_FILE, logStream.join('')); } catch {}
  };
  child.stdout?.on('data', append);
  child.stderr?.on('data', append);

  child.unref();
  writeFileSync(PID_FILE, String(child.pid));
  console.log(`${logPrefix} Mock agent starting (pid ${child.pid}, uuid ${uuidHex})`);
  return { pid: child.pid, started: true, uuidHex, logPath: LOG_FILE };
}
