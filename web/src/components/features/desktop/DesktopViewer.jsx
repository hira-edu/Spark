import React, { useState, useRef, useCallback, useEffect } from 'react';
import { message } from 'antd';
import { Toolbar } from './components/Toolbar';
import { DesktopCanvas, InputOverlay } from './components/Canvas';
import CursorOverlay from './components/Canvas/CursorOverlay';
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
  shareSecret = null,
  allowControl = true,
  onClose,
}) => {
  // State
  const [quality, setQuality] = useState(50); // Balanced quality and performance
  const [targetFps, setTargetFps] = useState(30);
  const [mouseEnabled, setMouseEnabled] = useState(true);
  const [keyboardEnabled, setKeyboardEnabled] = useState(true);
  const [selectedMonitor, setSelectedMonitor] = useState(0);
  const deviceId = device?.id || null;

  // Refs
  const containerRef = useRef(null);
  const contentRef = useRef(null);
  const canvasRef = useRef(null);

  // Desktop stream hook
  const {
    status,
    latency,
    fps,
    bandwidth,
    resolution,
    monitors,
    cursor,
    connect,
    disconnect,
    sendConfig,
    sendInput,
    sendClipboard,
    sendFileDrop,
    requestShot,
  } = useDesktopStream(device, canvasRef, { shareToken, shareSecret, allowControl });

  // Input capture hook
  const {
    pointerLocked,
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
    if (deviceId) {
      connect();
    }
    return () => {
      disconnect();
    };
  }, [deviceId, shareToken, shareSecret, connect, disconnect]);

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
    if (!allowControl) {
      message.warning(i18n.t('SHARE.VIEW_ONLY_NOTICE') || 'View-only mode');
      return;
    }
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        sendClipboard(text);
        message.success(i18n.t('SHARE.COPIED'));
      } else {
        message.info(i18n.t('COMMON.EMPTY') || 'Clipboard empty');
      }
    } catch (err) {
      console.error('Clipboard access failed:', err);
      message.error('Failed to access clipboard');
    }
  }, [allowControl, sendClipboard]);

  // Handle reconnect
  const handleReconnect = useCallback(() => {
    disconnect();
    connect();
  }, [disconnect, connect]);

  // Handle canvas click - request pointer lock
  const handleCanvasClick = useCallback(() => {
    if (!allowControl || !mouseEnabled) return;
    const canvas = canvasRef.current;
    if (canvas) {
      canvas.focus();
    }
  }, [allowControl, mouseEnabled]);

  // Handle monitor selection
  const handleMonitorSelect = useCallback((index) => {
    setSelectedMonitor(index);
  }, []);

  // Keyboard shortcut for ESC to release pointer lock
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        exitPointerLock();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [pointerLocked, exitPointerLock]);

  // File drag/drop -> send metadata as a control op
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;

    const preventDefault = (e) => {
      e.preventDefault();
    };
    const handleDrop = (e) => {
      e.preventDefault();
      if (!allowControl) return;
      const { files } = e.dataTransfer || {};
      if (files && files.length > 0) {
        sendFileDrop(files);
      }
    };

    canvas.addEventListener('dragover', preventDefault);
    canvas.addEventListener('drop', handleDrop);
    return () => {
      canvas.removeEventListener('dragover', preventDefault);
      canvas.removeEventListener('drop', handleDrop);
    };
  }, [allowControl, sendFileDrop]);

  const isConnected = status === 'connected';
  const canvasRect = canvasRef.current?.getBoundingClientRect();
  const contentRect = contentRef.current?.getBoundingClientRect();
  // Calculate scale factors safely - avoid division by zero
  const scaleX = canvasRect && resolution.width > 0 ? canvasRect.width / resolution.width : 1;
  const scaleY = canvasRect && resolution.height > 0 ? canvasRect.height / resolution.height : 1;
  // Use the minimum scale to preserve aspect ratio; validate both values
  const validScaleX = Number.isFinite(scaleX) && scaleX > 0 ? scaleX : 1;
  const validScaleY = Number.isFinite(scaleY) && scaleY > 0 ? scaleY : 1;
  const cursorScale = Math.min(validScaleX, validScaleY);

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
      <div className="desktop-viewer-content" ref={contentRef}>
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

        {/* Remote Cursor Overlay */}
        {status === 'connected' && (
          <CursorOverlay
            cursor={cursor}
            canvasRect={canvasRect}
            containerRect={contentRect}
            scale={cursorScale}
          />
        )}
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
