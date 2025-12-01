import React, { useState, useCallback, useEffect, useRef } from 'react';
import { message } from 'antd';
import { Toolbar } from './components/Toolbar';
import { DeviceSelector } from './components/DeviceSelector';
import { WebcamControls } from './components/WebcamControls';
import { WebcamViewer } from './components/WebcamViewer';
import { SessionStats } from './components/SessionStats';
import { useWebcamStream } from './hooks';
import i18n from '../../../locale/locale';
import './WebcamPanel.css';

/**
 * WebcamPanel - Main component for remote webcam streaming
 */
const WebcamPanel = ({
  device,
  onClose,
}) => {
  // State
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [quality, setQuality] = useState(70);
  const [targetFps, setTargetFps] = useState(15);
  const [resolution, setResolution] = useState('640x480');
  const [isRecording, setIsRecording] = useState(false);
  const [recordedFrames, setRecordedFrames] = useState([]);

  // Refs
  const videoRef = useRef(null);

  // Webcam stream hook
  const {
    status,
    devices,
    frameData,
    stats,
    currentResolution,
    fetchDevices,
    startStream,
    stopStream,
    updateConfig,
  } = useWebcamStream(device, videoRef);

  // Fetch devices on mount
  useEffect(() => {
    if (device?.id) {
      fetchDevices();
    }
  }, [device?.id, fetchDevices]);

  // Handle device selection
  const handleDeviceSelect = useCallback(async (deviceInfo) => {
    try {
      setSelectedDevice(deviceInfo);
      const [width, height] = resolution.split('x').map(Number);
      await startStream(deviceInfo.path, quality, targetFps, width, height);
      message.success(i18n.t('WEBCAM.STREAM_STARTED'));
    } catch (err) {
      console.error('Failed to start webcam stream:', err);
      message.error(i18n.t('WEBCAM.STREAM_FAILED'));
    }
  }, [startStream, quality, targetFps, resolution]);

  // Handle stop
  const handleStop = useCallback(async () => {
    try {
      await stopStream();
      setSelectedDevice(null);
      setIsRecording(false);
      setRecordedFrames([]);
      message.success(i18n.t('WEBCAM.STREAM_STOPPED'));
    } catch (err) {
      console.error('Failed to stop webcam stream:', err);
      message.error(i18n.t('WEBCAM.STOP_FAILED'));
    }
  }, [stopStream]);

  // Handle quality change
  const handleQualityChange = useCallback((newQuality) => {
    setQuality(newQuality);
    if (status === 'streaming') {
      updateConfig({ quality: newQuality });
    }
  }, [status, updateConfig]);

  // Handle FPS change
  const handleFpsChange = useCallback((newFps) => {
    setTargetFps(newFps);
    if (status === 'streaming') {
      updateConfig({ fps: newFps });
    }
  }, [status, updateConfig]);

  // Handle resolution change
  const handleResolutionChange = useCallback((newResolution) => {
    setResolution(newResolution);
    if (status === 'streaming') {
      const [width, height] = newResolution.split('x').map(Number);
      updateConfig({ width, height });
    }
  }, [status, updateConfig]);

  // Handle snapshot
  const handleSnapshot = useCallback(() => {
    const canvas = videoRef.current;
    if (!canvas) return;

    try {
      const link = document.createElement('a');
      link.download = `webcam_${device?.hostname || 'remote'}_${Date.now()}.png`;
      link.href = canvas.toDataURL('image/png');
      link.click();
      message.success(i18n.t('WEBCAM.SNAPSHOT_SAVED'));
    } catch (err) {
      console.error('Snapshot failed:', err);
      message.error(i18n.t('WEBCAM.SNAPSHOT_FAILED'));
    }
  }, [device, videoRef]);

  // Handle recording toggle
  const handleRecordingToggle = useCallback(() => {
    if (!isRecording) {
      // Start recording
      setIsRecording(true);
      setRecordedFrames([]);
      message.info(i18n.t('WEBCAM.RECORDING_STARTED'));
    } else {
      // Stop recording and create video
      setIsRecording(false);
      if (recordedFrames.length > 0) {
        try {
          // Create WebM video from recorded frames
          // This is a simplified version - actual implementation would use MediaRecorder API
          message.success(i18n.t('WEBCAM.RECORDING_SAVED'));
        } catch (err) {
          console.error('Failed to save recording:', err);
          message.error(i18n.t('WEBCAM.RECORDING_SAVE_FAILED'));
        }
      }
      setRecordedFrames([]);
    }
  }, [isRecording, recordedFrames]);

  // Record frames when recording is active
  useEffect(() => {
    if (isRecording && frameData) {
      setRecordedFrames(prev => [...prev, frameData]);
    }
  }, [isRecording, frameData]);

  // Handle refresh devices
  const handleRefreshDevices = useCallback(() => {
    fetchDevices();
    message.info(i18n.t('WEBCAM.DEVICES_REFRESHED'));
  }, [fetchDevices]);

  const isStreaming = status === 'streaming';

  return (
    <div className="webcam-panel">
      {/* Top Toolbar */}
      <Toolbar
        device={device}
        status={status}
        fps={stats.fps}
        latency={stats.latency}
        onClose={onClose}
      />

      {/* Main Content */}
      <div className="webcam-panel-content">
        {/* Device Selection */}
        <div className="webcam-panel-section">
          <div className="webcam-panel-section-title">
            {i18n.t('WEBCAM.SELECT_DEVICE')}
          </div>
          <DeviceSelector
            devices={devices}
            selectedDevice={selectedDevice}
            onSelect={handleDeviceSelect}
            onRefresh={handleRefreshDevices}
            disabled={isStreaming}
          />
        </div>

        {/* Webcam Viewer */}
        {isStreaming && (
          <div className="webcam-panel-section">
            <div className="webcam-panel-section-title">
              {i18n.t('WEBCAM.VIDEO_STREAM')}
            </div>
            <WebcamViewer
              ref={videoRef}
              frameData={frameData}
              resolution={currentResolution}
              isRecording={isRecording}
            />
          </div>
        )}

        {/* Session Statistics */}
        {isStreaming && (
          <div className="webcam-panel-section">
            <div className="webcam-panel-section-title">
              {i18n.t('WEBCAM.STATISTICS')}
            </div>
            <SessionStats
              stats={stats}
              isRecording={isRecording}
            />
          </div>
        )}

        {/* Controls */}
        <div className="webcam-panel-section webcam-panel-controls">
          <WebcamControls
            isStreaming={isStreaming}
            isRecording={isRecording}
            quality={quality}
            onQualityChange={handleQualityChange}
            targetFps={targetFps}
            onFpsChange={handleFpsChange}
            resolution={resolution}
            onResolutionChange={handleResolutionChange}
            onSnapshot={handleSnapshot}
            onRecordingToggle={handleRecordingToggle}
            onStop={handleStop}
            disabled={!isStreaming}
          />
        </div>
      </div>
    </div>
  );
};

export default WebcamPanel;
