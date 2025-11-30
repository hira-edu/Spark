import React, { useState, useRef, useCallback, useEffect } from 'react';
import { TabBar, Header, Footer, XTermWrapper } from './components';
import { useTerminalSession } from './hooks';
import './TerminalPanel.css';

// Generate unique session ID
const generateSessionId = () => `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

/**
 * TerminalPanel - Main component for terminal with multi-session support
 */
const TerminalPanel = ({
  device,
  onClose,
}) => {
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
    resize,
  } = useTerminalSession(device, {
    onOutput: (data) => {
      const termRef = terminalRefs.current[activeSessionId];
      if (termRef) {
        termRef.write(data);
      }
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
        onUpload={() => {/* TODO: Implement Zmodem upload */}}
        onDownload={() => {/* TODO: Implement Zmodem download */}}
        onClear={handleClear}
        onReconnect={handleReconnect}
        theme={theme}
        onThemeChange={setTheme}
        fontSize={fontSize}
        onFontSizeChange={setFontSize}
        status={status}
      />
    </div>
  );
};

export default TerminalPanel;
