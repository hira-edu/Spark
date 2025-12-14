import React, { useState, useRef, useCallback, useEffect } from 'react';
import { message } from 'antd';
import { Toolbar } from './components/Toolbar';
import { DesktopCanvas, InputOverlay } from './components/Canvas';
import CursorOverlay from './components/Canvas/CursorOverlay';
import { ControlBar } from './components/Controls';
import { useDesktopStream, useDesktopWebRTC, useInputCapture, useFullscreen } from './hooks';
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
  const [codec, setCodec] = useState('jpeg');
  const [qualityAuto, setQualityAuto] = useState(true);
  const [quality, setQuality] = useState(75); // Used when Auto quality is off
  const [targetFps, setTargetFps] = useState(30);
  const [mouseEnabled, setMouseEnabled] = useState(true);
  const [keyboardEnabled, setKeyboardEnabled] = useState(true);
  const [selectedMonitor, setSelectedMonitor] = useState(0);
  const [webrtcIceServers, setWebrtcIceServers] = useState(null);
  const [webrtcIceLoaded, setWebrtcIceLoaded] = useState(false);
  const deviceId = device?.id || null;

  // Refs
  const containerRef = useRef(null);
  const contentRef = useRef(null);
  const canvasRef = useRef(null);
  const sendSignalRef = useRef(null);

  // Fetch ICE servers from the server config (TURN credentials, TurnOnly policy, etc).
  useEffect(() => {
    let cancelled = false;
    setWebrtcIceServers(null);
    setWebrtcIceLoaded(false);

    (async () => {
      try {
        const url = shareToken
          ? `/api/share/ice?token=${encodeURIComponent(shareToken)}`
          : '/api/device/webrtc/config';
        const res = await fetch(url);
        const body = await res.json();
        if (body?.code === 0 && body?.data?.ice) {
          const ice = body.data.ice;
          const servers = [];

          if (Array.isArray(ice.ice_servers)) {
            ice.ice_servers.forEach((s) => {
              if (s && s.urls) servers.push(s);
            });
          }

          if (servers.length === 0) {
            (ice.stun || []).forEach((u) => servers.push({ urls: u }));
            (ice.turn || []).forEach((u) => servers.push({ urls: u }));
          }

          if (servers.length > 0 && !cancelled) {
            setWebrtcIceServers(servers);
          }
        }
      } catch (_) {
        // Fall back to the hook defaults (public STUN) when config is unavailable.
      } finally {
        if (!cancelled) setWebrtcIceLoaded(true);
      }
    })();

    return () => { cancelled = true; };
  }, [shareToken]);

  const {
    videoRef: webrtcVideoRef,
    isActive: webrtcActive,
    controlChannel: webrtcControlChannel,
    start: startWebRTC,
    stop: stopWebRTC,
    handleSignalMessage,
  } = useDesktopWebRTC({
    enabled: true,
    allowControl,
    iceServers: webrtcIceServers,
    sendSignal: useCallback((payload) => {
      if (sendSignalRef.current) {
        sendSignalRef.current(payload);
      }
    }, []),
  });

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
    sendSignal,
  } = useDesktopStream(device, canvasRef, {
    shareToken,
    shareSecret,
    allowControl,
    controlChannel: webrtcControlChannel,
    onJSONMessage: handleSignalMessage,
    suppressFrames: webrtcActive,
  });

  // Wire WS-only sendSignal into the WebRTC hook.
  useEffect(() => {
    sendSignalRef.current = sendSignal || null;
  }, [sendSignal]);

  // Start WebRTC after the desktop session is initialized (resolution known).
  useEffect(() => {
    if (!webrtcIceLoaded) return;
    if (status !== 'connected') {
      stopWebRTC();
      return;
    }
    if (resolution?.width > 0 && resolution?.height > 0) {
      startWebRTC();
    }
  }, [webrtcIceLoaded, status, resolution?.width, resolution?.height, startWebRTC, stopWebRTC]);

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
      const config = {
        fps: targetFps,
        display: selectedMonitor,
        codec,
      };

      // Adaptive quality only applies to JPEG tiles.
      if (codec === 'jpeg') {
        config.qualityAuto = qualityAuto;
        if (!qualityAuto) {
          config.quality = quality;
        }
      }

      sendConfig(config);
    }
  }, [codec, qualityAuto, quality, targetFps, selectedMonitor, status, sendConfig]);

  // When WebRTC video is active, suppress the WS tile/canvas stream for this session.
  useEffect(() => {
    if (status === 'connected') {
      sendConfig({ transport: webrtcActive ? 'webrtc' : 'tiles' });
    }
  }, [status, webrtcActive, sendConfig]);

  // Handle screenshot
  const handleScreenshot = useCallback(() => {
    try {
      // When WebRTC is active, the canvas may be transparent; capture the <video> frame instead.
      if (webrtcActive && webrtcVideoRef.current && webrtcVideoRef.current.videoWidth > 0) {
        const video = webrtcVideoRef.current;
        const snap = document.createElement('canvas');
        snap.width = video.videoWidth;
        snap.height = video.videoHeight;
        const ctx = snap.getContext('2d');
        if (ctx) {
          ctx.drawImage(video, 0, 0, snap.width, snap.height);
          const link = document.createElement('a');
          link.download = `screenshot_${device?.hostname || 'remote'}_${Date.now()}.png`;
          link.href = snap.toDataURL('image/png');
          link.click();
          message.success(i18n.t('COMMON.SUCCESS'));
          return;
        }
      }

      const canvas = canvasRef.current;
      if (!canvas) return;
      const link = document.createElement('a');
      link.download = `screenshot_${device?.hostname || 'remote'}_${Date.now()}.png`;
      link.href = canvas.toDataURL('image/png');
      link.click();
      message.success(i18n.t('COMMON.SUCCESS'));
    } catch (err) {
      console.error('Screenshot failed:', err);
      message.error(i18n.t('COMMON.UNKNOWN_ERROR'));
    }
  }, [device, webrtcActive, webrtcVideoRef]);

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
        <div className={`desktop-webrtc-layer ${webrtcActive ? 'desktop-webrtc-layer--active' : ''}`}>
          <video
            ref={webrtcVideoRef}
            className="desktop-webrtc-video"
            autoPlay
            playsInline
            muted
          />
        </div>
        <DesktopCanvas
          ref={canvasRef}
          pointerLocked={pointerLocked}
          onCanvasClick={handleCanvasClick}
          className={webrtcActive ? 'desktop-canvas-wrapper--webrtc' : ''}
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
        codec={codec}
        onCodecChange={setCodec}
        quality={quality}
        onQualityChange={setQuality}
        qualityAuto={qualityAuto}
        onQualityAutoChange={setQualityAuto}
        targetFps={targetFps}
        onFpsChange={setTargetFps}
        allowControl={allowControl}
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
        disabled={!isConnected}
      />
    </div>
  );
};

export default DesktopViewer;
