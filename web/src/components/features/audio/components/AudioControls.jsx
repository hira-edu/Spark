import React from 'react';
import { Button, Slider, Space } from 'antd';
import {
  PauseCircleOutlined,
  AudioMutedOutlined,
  AudioOutlined,
  VideoCameraAddOutlined,
  VideoCameraOutlined,
} from '@ant-design/icons';
import i18n from '../../../../locale/locale';
import './AudioControls.css';

/**
 * AudioControls - Audio playback and recording controls
 */
export const AudioControls = ({
  isStreaming,
  isRecording,
  volume,
  muted,
  onVolumeChange,
  onMuteToggle,
  onRecordingToggle,
  onStop,
  disabled,
}) => {
  return (
    <div className="audio-controls">
      {/* Volume Control */}
      <div className="audio-controls-section audio-controls-volume">
        <Button
          type="text"
          icon={muted ? <AudioMutedOutlined /> : <AudioOutlined />}
          onClick={onMuteToggle}
          disabled={disabled}
          className={`audio-controls-mute-btn ${muted ? 'audio-controls-mute-btn--muted' : ''}`}
        />
        <Slider
          min={0}
          max={100}
          value={muted ? 0 : volume}
          onChange={onVolumeChange}
          disabled={disabled || muted}
          className="audio-controls-slider"
          tooltip={{
            formatter: (value) => `${value}%`,
          }}
        />
        <span className="audio-controls-volume-label">
          {muted ? '0%' : `${volume}%`}
        </span>
      </div>

      {/* Action Buttons */}
      <div className="audio-controls-section audio-controls-actions">
        <Space size="middle">
          <Button
            type={isRecording ? 'primary' : 'default'}
            danger={isRecording}
            icon={isRecording ? <VideoCameraOutlined /> : <VideoCameraAddOutlined />}
            onClick={onRecordingToggle}
            disabled={disabled}
            className="audio-controls-record-btn"
          >
            {isRecording ? i18n.t('AUDIO.STOP_RECORDING') : i18n.t('AUDIO.START_RECORDING')}
          </Button>

          {isStreaming && (
            <Button
              type="primary"
              danger
              icon={<PauseCircleOutlined />}
              onClick={onStop}
              className="audio-controls-stop-btn"
            >
              {i18n.t('AUDIO.STOP_STREAM')}
            </Button>
          )}
        </Space>
      </div>
    </div>
  );
};
