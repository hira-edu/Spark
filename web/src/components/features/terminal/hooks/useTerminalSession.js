import { useState, useRef, useCallback, useEffect } from 'react';
import { message } from 'antd';
import { encrypt, decrypt, genRandHex, getBaseURL, hex2ua, str2hex, ua2hex, ua2str, translate } from '../../../../utils/utils';
import i18n from '../../../../locale/locale';

/**
 * useTerminalSession - Hook for managing a single terminal session
 * @param {Object} device - The device to connect to
 * @param {Object} options - Options for the session
 */
export function useTerminalSession(device, options = {}) {
  const { onOutput, onStatusChange } = options;

  const [status, setStatus] = useState('disconnected');
  const [sessionStart, setSessionStart] = useState(null);
  const [shell, setShell] = useState('');
  const [cwd, setCwd] = useState('');

  const wsRef = useRef(null);
  const secretRef = useRef(null);
  const tickerRef = useRef(null);

  // Update status callback
  useEffect(() => {
    if (onStatusChange) {
      onStatusChange(status);
    }
  }, [status, onStatusChange]);

  // Send data over WebSocket
  const sendData = useCallback(async (data) => {
    const ws = wsRef.current;
    const secret = secretRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN || !secret) return;

    const body = await encrypt(new TextEncoder().encode(JSON.stringify(data)), secret);
    const buffer = new Uint8Array(body.length + 8);
    buffer.set(new Uint8Array([34, 22, 19, 17, 20, 3]), 0);
    buffer.set(new Uint8Array([body.length >> 8, body.length & 0xFF]), 6);
    buffer.set(body, 8);
    ws.send(buffer);
  }, []);

  // Handle incoming messages
  const handleMessage = useCallback(async (data) => {
    const secret = secretRef.current;
    if (!secret) return;

    data = new Uint8Array(data);

    // Check for raw output (binary header)
    if (data[0] === 34 && data[1] === 22 && data[2] === 19 && data[3] === 17 && data[4] === 21 && data[5] === 0) {
      const output = ua2str(data.slice(8));
      if (onOutput) {
        onOutput(output);
      }
      return;
    }

    // Decrypt and parse JSON message
    try {
      const decrypted = await decrypt(data, secret);
      const parsed = JSON.parse(decrypted);

      if (parsed?.act === 'TERMINAL_OUTPUT') {
        const output = hex2ua(parsed?.data?.output);
        if (onOutput) {
          onOutput(ua2str(output));
        }
        return;
      }

      if (parsed?.act === 'WARN') {
        message.warn(parsed.msg ? translate(parsed.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
        return;
      }

      if (parsed?.act === 'QUIT') {
        message.warn(parsed.msg ? translate(parsed.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
        disconnect();
        return;
      }

      // Handle shell info
      if (parsed?.act === 'TERMINAL_INFO') {
        if (parsed.data?.shell) setShell(parsed.data.shell);
        if (parsed.data?.cwd) setCwd(parsed.data.cwd);
      }
    } catch (err) {
      console.error('Failed to parse message:', err);
    }
  }, [onOutput]);

  // Connect to the device
  const connect = useCallback(() => {
    if (!device?.id) return;

    // Generate new secret
    secretRef.current = hex2ua(genRandHex(32));
    const secretHex = ua2hex(secretRef.current);

    setStatus('connecting');

    const ws = new WebSocket(
      getBaseURL(true, `api/device/terminal?device=${device.id}&secret=${secretHex}`)
    );
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
      setSessionStart(Date.now());
    };

    ws.onmessage = (e) => {
      handleMessage(e.data);
    };

    ws.onclose = () => {
      setStatus('disconnected');
      cleanup();
      if (onOutput) {
        onOutput(`\r\n${i18n.t('COMMON.DISCONNECTED')}\r\n`);
      }
    };

    ws.onerror = (e) => {
      console.error('WebSocket error:', e);
      setStatus('error');
      cleanup();
      message.warn(i18n.t('COMMON.CONNECTION_FAILED'));
    };

    // Keep-alive ping
    tickerRef.current = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        sendData({ act: 'PING' });
      }
    }, 10000);
  }, [device, handleMessage, sendData]);

  // Disconnect from the device
  const disconnect = useCallback(() => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      sendData({ act: 'TERMINAL_KILL' });
    }
    cleanup();
    setStatus('disconnected');
  }, [sendData]);

  // Cleanup resources
  const cleanup = useCallback(() => {
    if (tickerRef.current) {
      clearInterval(tickerRef.current);
      tickerRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
      wsRef.current = null;
    }
    setSessionStart(null);
  }, []);

  // Send input to terminal
  const sendInput = useCallback((input) => {
    const isWindows = device?.os?.toLowerCase().includes('windows');
    sendData({
      act: 'TERMINAL_INPUT',
      data: {
        input: str2hex(input),
      },
    });
  }, [device, sendData]);

  // Resize terminal
  const resize = useCallback((cols, rows) => {
    sendData({
      act: 'TERMINAL_RESIZE',
      data: { cols, rows },
    });
  }, [sendData]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      cleanup();
    };
  }, [cleanup]);

  return {
    status,
    sessionStart,
    shell,
    cwd,
    connect,
    disconnect,
    sendInput,
    resize,
  };
}

export default useTerminalSession;
