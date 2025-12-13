import { useState, useRef, useCallback, useEffect } from 'react';
import { message } from 'antd';
import { encrypt, decrypt, genRandHex, getBaseURL, hex2ua, ua2hex, ua2str, translate } from '../../../../utils/utils';
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
    // Ensure body is a Uint8Array
    const bodyArray = body instanceof Uint8Array ? body : new Uint8Array(body);
    const bodyLength = bodyArray.length;
    const buffer = new Uint8Array(bodyLength + 8);
    // Terminal JSON command: magic(4) + service(21) + op(1) + length(2) + payload
    buffer.set(new Uint8Array([34, 22, 19, 17, 21, 1]), 0);
    buffer.set(new Uint8Array([bodyLength >> 8, bodyLength & 0xFF]), 6);
    buffer.set(bodyArray, 8);
    ws.send(buffer);
  }, []);

  // Handle incoming messages
  const handleMessage = useCallback(async (data) => {
    const secret = secretRef.current;
    if (!secret) return;

    data = new Uint8Array(data);

    const isMagic = data[0] === 34 && data[1] === 22 && data[2] === 19 && data[3] === 17;
    const service = isMagic ? data[4] : null;
    const op = isMagic ? data[5] : null;

    // Check for raw output (binary header: magic[4] + service + op + event[16] + length[2])
    if (isMagic && service === 21 && op === 0) {
      // Binary protocol: 4-byte magic + 1-byte service + 1-byte op + 16-byte event + 2-byte length + payload
      // Skip 24-byte header to get actual terminal output
      const output = ua2str(data.slice(24));
      if (onOutput) {
        onOutput(output);
      }
      return;
    }

    // Server-to-browser JSON packets for terminal use a 6-byte header (magic + service + op),
    // matching the pattern used by other Rocket feature handlers.
    if (isMagic && ((service === 21 && op === 1) || (service === 20 && op === 3))) {
      try {
        const decrypted = await decrypt(data.slice(6), secret);
        const parsed = JSON.parse(decrypted);
        if (parsed?.act === 'TERMINAL_OUTPUT') {
          const output = hex2ua(parsed?.data?.output);
          if (onOutput) {
            onOutput(ua2str(output));
          }
          return;
        }
        if (parsed?.act === 'WARN') {
          message.warning(parsed.msg ? translate(parsed.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
          return;
        }
        if (parsed?.act === 'QUIT') {
          message.warning(parsed.msg ? translate(parsed.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
          disconnect();
          return;
        }
        if (parsed?.act === 'TERMINAL_INFO') {
          if (parsed.data?.shell) setShell(parsed.data.shell);
          if (parsed.data?.cwd) setCwd(parsed.data.cwd);
        }
      } catch (err) {
        console.error('Failed to parse headered JSON message:', err);
      }
      return;
    }

    // Decrypt and parse legacy/unframed JSON message
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
        message.warning(parsed.msg ? translate(parsed.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
        return;
      }

      if (parsed?.act === 'QUIT') {
        message.warning(parsed.msg ? translate(parsed.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
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
      message.warning(i18n.t('COMMON.CONNECTION_FAILED'));
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
    const ws = wsRef.current;
    const secret = secretRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN || !secret) return;

    // Low-latency raw input: service=21, op=0 (server injects terminal event UUID).
    const payload = new TextEncoder().encode(input);
    const payloadLength = payload.length;
    const buffer = new Uint8Array(payloadLength + 8);
    buffer.set(new Uint8Array([34, 22, 19, 17, 21, 0]), 0);
    buffer.set(new Uint8Array([payloadLength >> 8, payloadLength & 0xFF]), 6);
    buffer.set(payload, 8);
    ws.send(buffer);
  }, []);

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
