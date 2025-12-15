import { execFileSync, spawn } from 'child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import path from 'path';

const DEFAULT_PORT = process.env.MOCK_DEVICE_PORT || '18081';
const REPO_ROOT = path.join(process.cwd(), '..');
const STATE_DIR = path.join(process.cwd(), '.playwright');
const BIN_DIR = path.join(STATE_DIR, 'bin');
const DEFAULT_BINARY = process.env.MOCK_DEVICE_BIN ||
  path.join(BIN_DIR, process.platform === 'win32' ? 'mock-device.exe' : 'mock-device');
const PID_FILE = path.join(STATE_DIR, 'mock-device.pid');
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

export async function waitForMockDevice(port = DEFAULT_PORT, timeout = 10000) {
  const url = `http://127.0.0.1:${port}/mock/health`;
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const response = await fetch(url);
      if (response.ok) return true;
    } catch (err) {
      // retry
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Mock device server at ${url} not ready after ${timeout}ms`);
}

function setMockEnv(port) {
  process.env.MOCK_DEVICE_PORT = String(port);
  process.env.MOCK_DEVICE_HTTP = `http://127.0.0.1:${port}`;
  process.env.MOCK_DEVICE_WS = `ws://127.0.0.1:${port}/mock-desktop`;
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

  // On POSIX, kill the whole process group when detached: true was used.
  try {
    process.kill(-pid, 'SIGTERM');
  } catch {
    try { process.kill(pid, 'SIGTERM'); } catch {}
  }
}

async function buildMockBinary(outPath, logPrefix = '[MockDevice]') {
  ensureStateDir();
  if (!existsSync(TEST_CLIENT_PATH)) {
    throw new Error('test_client.go not found - cannot build mock device binary');
  }

  console.log(`${logPrefix} Building mock device binary: ${outPath}`);
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

export function stopMockDevice(logPrefix = '[MockDevice]') {
  const pid = readPid();
  if (!pid) return false;
  killTree(pid);
  try {
    rmSync(PID_FILE);
  } catch {
    // ignore cleanup errors
  }
  console.log(`${logPrefix} Stopped mock device PID ${pid}`);
  return true;
}

export async function ensureMockDeviceRunning({
  port = DEFAULT_PORT,
  forceRestart = false,
  logPrefix = '[MockDevice]',
  waitTimeout = 10000,
  binaryPath = DEFAULT_BINARY,
} = {}) {
  ensureStateDir();
  setMockEnv(port);

  const running = await waitForMockDevice(port, 1500).then(() => true).catch(() => false);
  if (running && !forceRestart) {
    return { port, pid: readPid(), alreadyRunning: true };
  }

  if (running || forceRestart) {
    stopMockDevice(logPrefix);
    // Ensure the port is actually free before starting a new process.
    const start = Date.now();
    while (Date.now() - start < 5000) {
      const stillRunning = await waitForMockDevice(port, 250).then(() => true).catch(() => false);
      if (!stillRunning) break;
      await new Promise((r) => setTimeout(r, 150));
    }
  }

  if (!existsSync(TEST_CLIENT_PATH)) {
    throw new Error('test_client.go not found - cannot start mock device server');
  }

  const resolvedBinaryPath = await buildMockBinary(binaryPath, logPrefix);
  const command = resolvedBinaryPath;
  const args = ['--mock-desktop', '--mock-standalone', '--mock-port', String(port)];

  const child = spawn(command, args, {
    cwd: REPO_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });

  child.stdout?.on('data', (data) => {
    console.log(`[MockDevice] ${data.toString().trim()}`);
  });
  child.stderr?.on('data', (data) => {
    console.error(`[MockDevice Error] ${data.toString().trim()}`);
  });

  child.unref();
  writeFileSync(PID_FILE, String(child.pid));
  await waitForMockDevice(port, waitTimeout);
  console.log(`${logPrefix} Mock device listening on 127.0.0.1:${port} (pid ${child.pid})`);
  return { port, pid: child.pid, started: true };
}
