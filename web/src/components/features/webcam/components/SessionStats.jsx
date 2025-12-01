import React from 'react';
import { Card, Statistic, Row, Col } from 'antd';
import {
  ClockCircleOutlined,
  CloudDownloadOutlined,
  FileOutlined,
  ThunderboltOutlined,
  VideoCameraOutlined,
} from '@ant-design/icons';
import i18n from '../../../../locale/locale';
import './SessionStats.css';

/**
 * SessionStats - Display webcam streaming statistics
 */
export const SessionStats = ({ stats, isRecording }) => {
  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDuration = (seconds) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (hrs > 0) {
      return `${hrs}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="webcam-session-stats">
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} md={6}>
          <Card className="webcam-session-stats-card">
            <Statistic
              title={i18n.t('WEBCAM.STAT_DURATION')}
              value={formatDuration(stats.duration || 0)}
              prefix={<ClockCircleOutlined />}
              valueStyle={{ color: '#3b82f6' }}
            />
          </Card>
        </Col>

        <Col xs={24} sm={12} md={6}>
          <Card className="webcam-session-stats-card">
            <Statistic
              title={i18n.t('WEBCAM.STAT_FRAMES')}
              value={stats.framesReceived || 0}
              prefix={<FileOutlined />}
              valueStyle={{ color: '#10b981' }}
            />
          </Card>
        </Col>

        <Col xs={24} sm={12} md={6}>
          <Card className="webcam-session-stats-card">
            <Statistic
              title={i18n.t('WEBCAM.STAT_BANDWIDTH')}
              value={formatBytes(stats.bytesReceived || 0)}
              prefix={<CloudDownloadOutlined />}
              valueStyle={{ color: '#8b5cf6' }}
            />
          </Card>
        </Col>

        <Col xs={24} sm={12} md={6}>
          <Card className="webcam-session-stats-card">
            <Statistic
              title={i18n.t('WEBCAM.STAT_FPS')}
              value={`${stats.fps || 0} FPS`}
              suffix={stats.latency ? `/ ${stats.latency}ms` : ''}
              prefix={<VideoCameraOutlined />}
              valueStyle={{ color: '#f59e0b', fontSize: '18px' }}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
};
