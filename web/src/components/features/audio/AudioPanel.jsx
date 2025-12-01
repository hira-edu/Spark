import React, { useState, useCallback, useEffect } from 'react';
import { message } from 'antd';
import { Toolbar } from './components/Toolbar';
import { DeviceSelector } from './components/DeviceSelector';
import { AudioControls } from './components/AudioControls';
import { AudioVisualizer } from './components/AudioVisualizer';
import { SessionStats } from './components/SessionStats';
import { useAudioStream } from './hooks';
import i18n from '../../../locale/locale';
import './AudioPanel.css';

/**
 * AudioPanel - Main component for remote audio streaming
 */
const AudioPanel = ({
  device,
  onClose,
}) => {
  // State
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [volume, setVolume] = useState(80);
  const [muted, setMuted] = useState(false);
  const [isRecording, setIsRecording] = useState(false);
  const [recordingData, setRecordingData] = useState([]);

  // Audio stream hook
  const {
    status,
    devices,
    audioData,
    stats,
    fetchDevices,
    startStream,
    stopStream,
  } = useAudioStream(device);

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
      await startStream(deviceInfo.index);
      message.success(i18n.t('AUDIO.STREAM_STARTED'));
    } catch (err) {
      console.error('Failed to start audio stream:', err);
      message.error(i18n.t('AUDIO.STREAM_FAILED'));
    }
  }, [startStream]);

  // Handle stop
  const handleStop = useCallback(async () => {
    try {
      await stopStream();
      setSelectedDevice(null);
      setIsRecording(false);
      setRecordingData([]);
      message.success(i18n.t('AUDIO.STREAM_STOPPED'));
    } catch (err) {
      console.error('Failed to stop audio stream:', err);
      message.error(i18n.t('AUDIO.STOP_FAILED'));
    }
  }, [stopStream]);

  // Handle recording toggle
  const handleRecordingToggle = useCallback(() => {
    if (!isRecording) {
      // Start recording
      setIsRecording(true);
      setRecordingData([]);
      message.info(i18n.t('AUDIO.RECORDING_STARTED'));
    } else {
      // Stop recording and download
      setIsRecording(false);
      if (recordingData.length > 0) {
        try {
          const blob = new Blob(recordingData, { type: 'audio/ogg; codecs=opus' });
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.download = `audio_${device?.hostname || 'remote'}_${Date.now()}.opus`;
          link.href = url;
          link.click();
          URL.revokeObjectURL(url);
          message.success(i18n.t('AUDIO.RECORDING_SAVED'));
        } catch (err) {
          console.error('Failed to save recording:', err);
          message.error(i18n.t('AUDIO.RECORDING_SAVE_FAILED'));
        }
      }
      setRecordingData([]);
    }
  }, [isRecording, recordingData, device]);

  // Append audio data when recording
  useEffect(() => {
    if (isRecording && audioData) {
      setRecordingData(prev => [...prev, audioData]);
    }
  }, [isRecording, audioData]);

  // Handle volume change
  const handleVolumeChange = useCallback((newVolume) => {
    setVolume(newVolume);
    // Apply volume to audio playback if needed
  }, []);

  // Handle mute toggle
  const handleMuteToggle = useCallback(() => {
    setMuted(!muted);
  }, [muted]);

  // Handle refresh devices
  const handleRefreshDevices = useCallback(() => {
    fetchDevices();
    message.info(i18n.t('AUDIO.DEVICES_REFRESHED'));
  }, [fetchDevices]);

  const isStreaming = status === 'streaming';

  return (
    <div className="audio-panel">
      {/* Top Toolbar */}
      <Toolbar
        device={device}
        status={status}
        onClose={onClose}
      />

      {/* Main Content */}
      <div className="audio-panel-content">
        {/* Device Selection */}
        <div className="audio-panel-section">
          <div className="audio-panel-section-title">
            {i18n.t('AUDIO.SELECT_DEVICE')}
          </div>
          <DeviceSelector
            devices={devices}
            selectedDevice={selectedDevice}
            onSelect={handleDeviceSelect}
            onRefresh={handleRefreshDevices}
            disabled={isStreaming}
          />
        </div>

        {/* Audio Visualizer */}
        {isStreaming && (
          <div className="audio-panel-section">
            <div className="audio-panel-section-title">
              {i18n.t('AUDIO.AUDIO_STREAM')}
            </div>
            <AudioVisualizer
              audioData={audioData}
              muted={muted}
              volume={volume}
            />
          </div>
        )}

        {/* Session Statistics */}
        {isStreaming && (
          <div className="audio-panel-section">
            <div className="audio-panel-section-title">
              {i18n.t('AUDIO.STATISTICS')}
            </div>
            <SessionStats
              stats={stats}
              isRecording={isRecording}
            />
          </div>
        )}

        {/* Controls */}
        <div className="audio-panel-section audio-panel-controls">
          <AudioControls
            isStreaming={isStreaming}
            isRecording={isRecording}
            volume={volume}
            muted={muted}
            onVolumeChange={handleVolumeChange}
            onMuteToggle={handleMuteToggle}
            onRecordingToggle={handleRecordingToggle}
            onStop={handleStop}
            disabled={!isStreaming}
          />
        </div>
      </div>
    </div>
  );
};

export default AudioPanel;
