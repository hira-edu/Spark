import React, { useState, useRef, useCallback, useEffect } from 'react';
import { message } from 'antd';
import { Toolbar } from './components/Toolbar';
import { DesktopCanvas, InputOverlay } from './components/Canvas';
import { ControlBar } from './components/Controls';
import { useDesktopStream, useInputCapture, useFullscreen } from './hooks';
import i18n from '../../../locale/locale';
import './DesktopViewer.css';

/**
 * DesktopViewer - Main component for remote desktop viewing and control
 */
const DesktopViewer = ({
  device,
  shareToken = null,
  allowControl = true,
  onClose,
}) => {
  // State
  const [quality, setQuality] = useState(70);
  const [targetFps, setTargetFps] = useState(30);
  const [mouseEnabled, setMouseEnabled] = useState(true);
  const [keyboardEnabled, setKeyboardEnabled] = useState(true);
  const [selectedMonitor, setSelectedMonitor] = useState(0);

  // Refs
  const containerRef = useRef(null);
  const canvasRef = useRef(null);

  // Desktop stream hook
  const {
    status,
    latency,
    fps,
    bandwidth,
    resolution,
    monitors,
    connect,
    disconnect,
    sendConfig,
    sendInput,
    requestShot,
  } = useDesktopStream(device, canvasRef, { shareToken, allowControl });

  // Input capture hook
  const {
    pointerLocked,
    requestPointerLock,
    exitPointerLock,
  } = useInputCapture(canvasRef, {
    enabled: status === 'connected' && allowControl,
    mouseEnabled,
    keyboardEnabled,
    onInput: sendInput,
  });

  // Fullscreen hook
  const {
    isFullscreen,
    toggleFullscreen,
  } = useFullscreen(containerRef);

  // Connect on mount
  useEffect(() => {
    if (device?.id) {
      connect();
    }
    return () => {
      disconnect();
    };
  }, [device?.id, shareToken, connect, disconnect]);

  // Send config when settings change
  useEffect(() => {
    if (status === 'connected') {
      sendConfig({
        quality,
        fps: targetFps,
        display: selectedMonitor,
      });
    }
  }, [quality, targetFps, selectedMonitor, status, sendConfig]);

  // Handle screenshot
  const handleScreenshot = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    try {
      const link = document.createElement('a');
      link.download = `screenshot_${device?.hostname || 'remote'}_${Date.now()}.png`;
      link.href = canvas.toDataURL('image/png');
      link.click();
      message.success(i18n.t('COMMON.SUCCESS'));
    } catch (err) {
      console.error('Screenshot failed:', err);
      message.error(i18n.t('COMMON.UNKNOWN_ERROR'));
    }
  }, [device]);

  // Handle clipboard sync
  const handleClipboardSync = useCallback(async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        // TODO: Send clipboard to remote
        message.success('Clipboard synced');
      }
    } catch (err) {
      console.error('Clipboard access failed:', err);
      message.error('Failed to access clipboard');
    }
  }, []);

  // Handle reconnect
  const handleReconnect = useCallback(() => {
    disconnect();
    connect();
  }, [disconnect, connect]);

  // Handle canvas click - request pointer lock
  const handleCanvasClick = useCallback(() => {
    if (allowControl && mouseEnabled) {
      requestPointerLock();
    }
  }, [allowControl, mouseEnabled, requestPointerLock]);

  // Handle monitor selection
  const handleMonitorSelect = useCallback((index) => {
    setSelectedMonitor(index);
  }, []);

  // Keyboard shortcut for ESC to release pointer lock
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && pointerLocked) {
        exitPointerLock();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [pointerLocked, exitPointerLock]);

  const isConnected = status === 'connected';

  return (
    <div
      ref={containerRef}
      className={`desktop-viewer ${isFullscreen ? 'desktop-viewer--fullscreen' : ''}`}
    >
      {/* Top Toolbar */}
      <Toolbar
        device={device}
        status={status}
        latency={latency}
        fps={fps}
        bandwidth={bandwidth}
        resolution={resolution}
        onClose={onClose}
      />

      {/* Canvas Container */}
      <div className="desktop-viewer-content">
        <DesktopCanvas
          ref={canvasRef}
          pointerLocked={pointerLocked}
          onCanvasClick={handleCanvasClick}
        />

        {/* Overlays */}
        <InputOverlay
          pointerLocked={pointerLocked}
          status={status}
          onReconnect={handleReconnect}
        />
      </div>

      {/* Bottom Control Bar */}
      <ControlBar
        quality={quality}
        onQualityChange={setQuality}
        targetFps={targetFps}
        onFpsChange={setTargetFps}
        mouseEnabled={mouseEnabled}
        onMouseToggle={() => setMouseEnabled(!mouseEnabled)}
        keyboardEnabled={keyboardEnabled}
        onKeyboardToggle={() => setKeyboardEnabled(!keyboardEnabled)}
        onScreenshot={handleScreenshot}
        onClipboard={handleClipboardSync}
        isFullscreen={isFullscreen}
        onFullscreen={toggleFullscreen}
        monitors={monitors}
        selectedMonitor={selectedMonitor}
        onMonitorSelect={handleMonitorSelect}
        disabled={!isConnected || !allowControl}
      />
    </div>
  );
};

export default DesktopViewer;
