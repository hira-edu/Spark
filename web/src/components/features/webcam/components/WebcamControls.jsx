import React from 'react';
import { Button, Slider, Space, Select, Row, Col } from 'antd';
import {
  PauseCircleOutlined,
  CameraOutlined,
  VideoCameraAddOutlined,
  VideoCameraOutlined,
} from '@ant-design/icons';
import i18n from '../../../../locale/locale';
import './WebcamControls.css';

const { Option } = Select;

/**
 * WebcamControls - Webcam streaming controls
 */
export const WebcamControls = ({
  isStreaming,
  isRecording,
  quality,
  onQualityChange,
  targetFps,
  onFpsChange,
  resolution,
  onResolutionChange,
  onSnapshot,
  onRecordingToggle,
  onStop,
  disabled,
}) => {
  const resolutions = ['640x480', '800x600', '1280x720', '1920x1080'];

  return (
    <div className="webcam-controls">
      {/* Quality and FPS Controls */}
      <Row gutter={[16, 16]}>
        <Col xs={24} md={8}>
          <div className="webcam-controls-section">
            <label className="webcam-controls-label">{i18n.t('WEBCAM.QUALITY')}</label>
            <Slider
              min={10}
              max={100}
              value={quality}
              onChange={onQualityChange}
              disabled={disabled}
              tooltip={{ formatter: (value) => `${value}%` }}
            />
            <span className="webcam-controls-value">{quality}%</span>
          </div>
        </Col>

        <Col xs={24} md={8}>
          <div className="webcam-controls-section">
            <label className="webcam-controls-label">{i18n.t('WEBCAM.FPS')}</label>
            <Slider
              min={5}
              max={30}
              value={targetFps}
              onChange={onFpsChange}
              disabled={disabled}
              tooltip={{ formatter: (value) => `${value} FPS` }}
            />
            <span className="webcam-controls-value">{targetFps} FPS</span>
          </div>
        </Col>

        <Col xs={24} md={8}>
          <div className="webcam-controls-section">
            <label className="webcam-controls-label">{i18n.t('WEBCAM.RESOLUTION')}</label>
            <Select
              value={resolution}
              onChange={onResolutionChange}
              disabled={disabled}
              style={{ width: '100%' }}
              className="webcam-controls-select"
            >
              {resolutions.map(res => (
                <Option key={res} value={res}>{res}</Option>
              ))}
            </Select>
          </div>
        </Col>
      </Row>

      {/* Action Buttons */}
      <div className="webcam-controls-actions">
        <Space size="middle" wrap>
          <Button
            type="default"
            icon={<CameraOutlined />}
            onClick={onSnapshot}
            disabled={disabled}
            className="webcam-controls-snapshot-btn"
          >
            {i18n.t('WEBCAM.SNAPSHOT')}
          </Button>

          <Button
            type={isRecording ? 'primary' : 'default'}
            danger={isRecording}
            icon={isRecording ? <VideoCameraOutlined /> : <VideoCameraAddOutlined />}
            onClick={onRecordingToggle}
            disabled={disabled}
            className="webcam-controls-record-btn"
          >
            {isRecording ? i18n.t('WEBCAM.STOP_RECORDING') : i18n.t('WEBCAM.START_RECORDING')}
          </Button>

          {isStreaming && (
            <Button
              type="primary"
              danger
              icon={<PauseCircleOutlined />}
              onClick={onStop}
              className="webcam-controls-stop-btn"
            >
              {i18n.t('WEBCAM.STOP_STREAM')}
            </Button>
          )}
        </Space>
      </div>
    </div>
  );
};
