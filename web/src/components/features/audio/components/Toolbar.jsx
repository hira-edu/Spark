import React from 'react';
import { Button, Tag, Space } from 'antd';
import {
  CloseOutlined,
  AudioOutlined,
  LoadingOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
} from '@ant-design/icons';
import i18n from '../../../../locale/locale';
import './Toolbar.css';

/**
 * Toolbar - Top toolbar for audio panel
 */
export const Toolbar = ({ device, status, onClose }) => {
  const getStatusConfig = () => {
    switch (status) {
      case 'streaming':
        return {
          icon: <CheckCircleOutlined />,
          color: 'success',
          text: i18n.t('AUDIO.STATUS_STREAMING'),
        };
      case 'connecting':
        return {
          icon: <LoadingOutlined spin />,
          color: 'processing',
          text: i18n.t('AUDIO.STATUS_CONNECTING'),
        };
      case 'error':
        return {
          icon: <CloseCircleOutlined />,
          color: 'error',
          text: i18n.t('AUDIO.STATUS_ERROR'),
        };
      default:
        return {
          icon: <AudioOutlined />,
          color: 'default',
          text: i18n.t('AUDIO.STATUS_DISCONNECTED'),
        };
    }
  };

  const statusConfig = getStatusConfig();

  return (
    <div className="audio-toolbar">
      <div className="audio-toolbar-left">
        <AudioOutlined className="audio-toolbar-icon" />
        <span className="audio-toolbar-title">
          {i18n.t('AUDIO.TITLE')} - {device?.hostname || device?.id || 'Unknown'}
        </span>
        <Tag
          icon={statusConfig.icon}
          color={statusConfig.color}
          className="audio-toolbar-status"
        >
          {statusConfig.text}
        </Tag>
      </div>

      <div className="audio-toolbar-right">
        <Space size="small">
          <Button
            type="text"
            icon={<CloseOutlined />}
            onClick={onClose}
            className="audio-toolbar-close"
          >
            {i18n.t('COMMON.CLOSE')}
          </Button>
        </Space>
      </div>
    </div>
  );
};
