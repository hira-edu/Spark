import React, { useState, useRef, useCallback, useEffect } from 'react';
import { Input, Modal, message } from 'antd';
import { TabBar, Header, Footer, XTermWrapper } from './components';
import { useTerminalSession } from './hooks';
import './TerminalPanel.css';
import '../../../vendors/zmodem.js/zmodem_browser';

// Generate unique session ID
const generateSessionId = () => `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

/**
 * TerminalPanel - Main component for terminal with multi-session support
 */
const TerminalPanel = ({
  device,
  onClose,
}) => {
  const Zmodem = window.Zmodem;

  // Sessions state
  const [sessions, setSessions] = useState([
    { id: generateSessionId(), title: 'Session 1', status: 'disconnected' },
  ]);
  const [activeSessionId, setActiveSessionId] = useState(sessions[0].id);

  // Terminal settings
  const [theme, setTheme] = useState('dark');
  const [fontSize, setFontSize] = useState(16);

  // Refs for terminal instances
  const terminalRefs = useRef({});
  const zmodemRefs = useRef({});
  const pendingTransferRef = useRef(null);
  const pendingTransferTimerRef = useRef(null);
  const uploadInputRef = useRef(null);

  // Get active session
  const activeSession = sessions.find((s) => s.id === activeSessionId);

  // Terminal session hook for active session
  const {
    status,
    sessionStart,
    shell,
    cwd,
    connect,
    disconnect,
    sendInput,
    sendBytes,
    resize,
  } = useTerminalSession(device, {
    onOutputBytes: (bytes) => {
      const ensureZmodem = () => {
        if (!Zmodem) {
          return null;
        }
        const existing = zmodemRefs.current[activeSessionId];
        if (existing?.sentry) {
          return existing;
        }

        const toTerminal = (octets) => {
          const termRef = terminalRefs.current[activeSessionId];
          if (!termRef) {
            return;
          }
          termRef.write(new Uint8Array(octets));
        };

        const sender = (octets) => {
          if (!sendBytes) {
            return;
          }
          sendBytes(new Uint8Array(octets));
        };

        const onDetect = (detection) => {
          const pending = pendingTransferRef.current;
          if (!pending) {
            detection.deny();
            return;
          }

          const expectedRole = pending.type === 'upload' ? 'send' : 'receive';
          if (detection.get_session_role() !== expectedRole) {
            pendingTransferRef.current = null;
            detection.deny();
            message.warning(`ZMODEM role mismatch (expected ${expectedRole})`);
            return;
          }

          let session;
          try {
            session = detection.confirm();
          } catch (err) {
            pendingTransferRef.current = null;
            message.error('Failed to start ZMODEM session');
            return;
          }

          // Clear pending timeout once we have a session
          if (pendingTransferTimerRef.current) {
            clearTimeout(pendingTransferTimerRef.current);
            pendingTransferTimerRef.current = null;
          }
          pendingTransferRef.current = null;

          session.on('session_end', () => {
            message.success('ZMODEM transfer complete');
          });

          if (pending.type === 'upload') {
            const files = pending.files || [];
            message.loading({ content: 'Uploading via ZMODEM…', key: 'zmodem' });
            Zmodem.Browser.send_files(session, files, {
              on_progress: (file, xfer) => {
                const details = xfer?.get_details?.() || {};
                message.loading({
                  content: `Uploading ${details.name || file.name} (${xfer.get_offset?.() || 0}/${details.size || file.size} bytes)…`,
                  key: 'zmodem',
                });
              },
            })
              .then(() => session.close())
              .then(() => {
                message.success({ content: 'Upload complete', key: 'zmodem' });
              })
              .catch((err) => {
                message.error({ content: `Upload failed: ${String(err)}`, key: 'zmodem' });
                try { session.abort(); } catch (e) { /* ignore */ }
              });
          } else {
            // Download (receive)
            session.on('offer', (offer) => {
              const details = offer.get_details();
              message.loading({ content: `Receiving ${details.name}…`, key: 'zmodem' });
              offer.accept({ on_input: 'spool_uint8array' })
                .then((packets) => {
                  Zmodem.Browser.save_to_disk(packets, details.name);
                  message.success({ content: `Saved ${details.name}`, key: 'zmodem' });
                })
                .catch((err) => {
                  message.error({ content: `Receive failed: ${String(err)}`, key: 'zmodem' });
                  try { offer.skip(); } catch (e) { /* ignore */ }
                });
            });

            try {
              session.start();
            } catch (err) {
              message.error({ content: `Failed to start receive: ${String(err)}`, key: 'zmodem' });
              try { session.abort(); } catch (e) { /* ignore */ }
            }
          }
        };

        const onRetract = () => {
          // No-op; detections can be retracted on false positives.
        };

        const sentry = new Zmodem.Sentry({
          to_terminal: toTerminal,
          sender,
          on_detect: onDetect,
          on_retract: onRetract,
        });

        zmodemRefs.current[activeSessionId] = { sentry };
        return zmodemRefs.current[activeSessionId];
      };

      const z = ensureZmodem();
      if (!z?.sentry) {
        const termRef = terminalRefs.current[activeSessionId];
        if (termRef) {
          termRef.write(bytes);
        }
        return;
      }

      z.sentry.consume(bytes);
    },
    onStatusChange: (newStatus) => {
      setSessions((prev) =>
        prev.map((s) =>
          s.id === activeSessionId ? { ...s, status: newStatus } : s
        )
      );
    },
  });

  // Connect when session becomes active
  useEffect(() => {
    if (device?.id && activeSessionId) {
      connect();
    }
    return () => {
      disconnect();
    };
  }, [device?.id, activeSessionId]);

  // Handle terminal data input
  const handleTerminalData = useCallback((data) => {
    sendInput(data);
  }, [sendInput]);

  // Handle terminal resize
  const handleTerminalResize = useCallback(({ cols, rows }) => {
    resize(cols, rows);
  }, [resize]);

  // Create new session
  const handleNewSession = useCallback(() => {
    const newSession = {
      id: generateSessionId(),
      title: `Session ${sessions.length + 1}`,
      status: 'disconnected',
    };
    setSessions((prev) => [...prev, newSession]);
    setActiveSessionId(newSession.id);
  }, [sessions.length]);

  // Close session
  const handleCloseSession = useCallback((sessionId) => {
    setSessions((prev) => {
      const filtered = prev.filter((s) => s.id !== sessionId);
      if (filtered.length === 0) {
        // Close the panel if no sessions left
        if (onClose) onClose();
        return prev;
      }
      // Switch to another session if closing active
      if (sessionId === activeSessionId) {
        setActiveSessionId(filtered[0].id);
      }
      return filtered;
    });

    // Clean up terminal ref
    delete terminalRefs.current[sessionId];
  }, [activeSessionId, onClose]);

  // Handle quick command
  const handleQuickCommand = useCallback((command) => {
    sendInput(command + '\n');
  }, [sendInput]);

  // Handle clear
  const handleClear = useCallback(() => {
    const termRef = terminalRefs.current[activeSessionId];
    if (termRef) {
      termRef.clear();
    }
    sendInput('clear\n');
  }, [activeSessionId, sendInput]);

  // Handle reconnect
  const handleReconnect = useCallback(() => {
    disconnect();
    setTimeout(() => {
      connect();
    }, 100);
  }, [disconnect, connect]);

  const clearPendingTransfer = useCallback(() => {
    pendingTransferRef.current = null;
    if (pendingTransferTimerRef.current) {
      clearTimeout(pendingTransferTimerRef.current);
      pendingTransferTimerRef.current = null;
    }
  }, []);

  const setPendingTransferWithTimeout = useCallback((pending) => {
    clearPendingTransfer();
    pendingTransferRef.current = pending;
    pendingTransferTimerRef.current = setTimeout(() => {
      pendingTransferRef.current = null;
      pendingTransferTimerRef.current = null;
      message.warning('ZMODEM transfer timed out (is lrzsz installed on the remote?)');
    }, 30000);
  }, [clearPendingTransfer]);

  const handleUpload = useCallback(() => {
    if (status !== 'connected') {
      return;
    }
    if (!window.Zmodem) {
      message.warning('ZMODEM library not available');
      return;
    }
    uploadInputRef.current?.click();
  }, [status]);

  const posixShellQuote = (value) => {
    const str = String(value ?? '');
    return `'${str.replace(/'/g, `'\"'\"'`)}'`;
  };

  const handleDownload = useCallback(() => {
    if (status !== 'connected') {
      return;
    }
    if (!window.Zmodem) {
      message.warning('ZMODEM library not available');
      return;
    }

    let remotePath = '';
    Modal.confirm({
      title: 'Download via ZMODEM',
      content: (
        <div>
          <div style={{ marginBottom: 8 }}>Remote path (file or glob supported by your shell):</div>
          <Input autoFocus onChange={(e) => { remotePath = e.target.value; }} placeholder="/path/to/file" />
        </div>
      ),
      okText: 'Start',
      onOk: () => {
        const trimmed = (remotePath || '').trim();
        if (!trimmed) {
          message.warning('Remote path required');
          return Promise.reject();
        }

        setPendingTransferWithTimeout({ type: 'download' });
        sendInput(`sz -e -- ${posixShellQuote(trimmed)}\n`);
        message.info('Waiting for ZMODEM download…');
        return Promise.resolve();
      },
    });
  }, [status, sendInput, setPendingTransferWithTimeout]);

  // Store terminal ref
  const setTerminalRef = useCallback((ref) => {
    if (ref) {
      terminalRefs.current[activeSessionId] = ref;
    }
  }, [activeSessionId]);

  return (
    <div className="terminal-panel">
      {/* Tab Bar */}
      <TabBar
        sessions={sessions}
        activeSessionId={activeSessionId}
        onSelectSession={setActiveSessionId}
        onNewSession={handleNewSession}
        onCloseSession={handleCloseSession}
      />

      {/* Header */}
      <Header
        device={device}
        status={status}
        shell={shell}
        cwd={cwd}
        sessionStart={sessionStart}
      />

      {/* Terminal Content */}
      <div className="terminal-panel-content">
        <XTermWrapper
          ref={setTerminalRef}
          theme={theme}
          fontSize={fontSize}
          onData={handleTerminalData}
          onResize={handleTerminalResize}
        />
      </div>

      {/* Footer */}
      <Footer
        os={device?.os}
        onQuickCommand={handleQuickCommand}
        onUpload={handleUpload}
        onDownload={handleDownload}
        onClear={handleClear}
        onReconnect={handleReconnect}
        theme={theme}
        onThemeChange={setTheme}
        fontSize={fontSize}
        onFontSizeChange={setFontSize}
        status={status}
      />

      <input
        ref={uploadInputRef}
        type="file"
        multiple
        style={{ display: 'none' }}
        onChange={(e) => {
          const files = e.target.files ? Array.from(e.target.files) : [];
          e.target.value = '';
          if (!files.length) {
            return;
          }

          setPendingTransferWithTimeout({ type: 'upload', files });
          // Remote must run rz to receive; trigger it for common shells.
          sendInput('rz -y\n');
          message.info('Waiting for ZMODEM upload…');
        }}
      />
    </div>
  );
};

export default TerminalPanel;
