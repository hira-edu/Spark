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
  allowControl = true,
  onClose,
}) => {
  // State
  const [quality, setQuality] = useState(40);
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
    cursor,
    connect,
    disconnect,
    sendConfig,
    sendInput,
    sendClipboard,
    sendFileDrop,
    requestShot,
  } = useDesktopStream(device, canvasRef, { shareToken, allowControl });

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
  const scaleX = canvasRect && resolution.width ? canvasRect.width / resolution.width : 1;
  const scaleY = canvasRect && resolution.height ? canvasRect.height / resolution.height : 1;
  const cursorScaleBase = Number.isFinite(scaleX) && scaleX > 0 ? scaleX : 1;
  const cursorScale = Number.isFinite(scaleY) && scaleY > 0 ? Math.min(cursorScaleBase, scaleY) : cursorScaleBase;

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

        {/* Remote Cursor Overlay */}
        {status === 'connected' && (
          <CursorOverlay
            cursor={cursor}
            canvasRect={canvasRect}
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
