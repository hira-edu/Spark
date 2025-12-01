import React from 'react';
import { Button, Tag, Space } from 'antd';
import {
  CloseOutlined,
  CameraOutlined,
  LoadingOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
} from '@ant-design/icons';
import i18n from '../../../../locale/locale';
import './Toolbar.css';

/**
 * Toolbar - Top toolbar for webcam panel
 */
export const Toolbar = ({ device, status, fps, latency, onClose }) => {
  const getStatusConfig = () => {
    switch (status) {
      case 'streaming':
        return {
          icon: <CheckCircleOutlined />,
          color: 'success',
          text: i18n.t('WEBCAM.STATUS_STREAMING'),
        };
      case 'connecting':
        return {
          icon: <LoadingOutlined spin />,
          color: 'processing',
          text: i18n.t('WEBCAM.STATUS_CONNECTING'),
        };
      case 'error':
        return {
          icon: <CloseCircleOutlined />,
          color: 'error',
          text: i18n.t('WEBCAM.STATUS_ERROR'),
        };
      default:
        return {
          icon: <CameraOutlined />,
          color: 'default',
          text: i18n.t('WEBCAM.STATUS_DISCONNECTED'),
        };
    }
  };

  const statusConfig = getStatusConfig();

  return (
    <div className="webcam-toolbar">
      <div className="webcam-toolbar-left">
        <CameraOutlined className="webcam-toolbar-icon" />
        <span className="webcam-toolbar-title">
          {i18n.t('WEBCAM.TITLE')} - {device?.hostname || device?.id || 'Unknown'}
        </span>
        <Tag
          icon={statusConfig.icon}
          color={statusConfig.color}
          className="webcam-toolbar-status"
        >
          {statusConfig.text}
        </Tag>
        {status === 'streaming' && (
          <Space size="small" className="webcam-toolbar-stats">
            <Tag color="blue">{fps} FPS</Tag>
            <Tag color="cyan">{latency}ms</Tag>
          </Space>
        )}
      </div>

      <div className="webcam-toolbar-right">
        <Space size="small">
          <Button
            type="text"
            icon={<CloseOutlined />}
            onClick={onClose}
            className="webcam-toolbar-close"
          >
            {i18n.t('COMMON.CLOSE')}
          </Button>
        </Space>
      </div>
    </div>
  );
};
