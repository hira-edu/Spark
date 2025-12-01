import React from 'react';
import { Button, Empty, Space, Card, Tag } from 'antd';
import {
  AudioOutlined,
  ReloadOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';
import i18n from '../../../../locale/locale';
import './DeviceSelector.css';

/**
 * DeviceSelector - Audio device selection component
 */
export const DeviceSelector = ({
  devices,
  selectedDevice,
  onSelect,
  onRefresh,
  disabled,
}) => {
  if (!devices || devices.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description={i18n.t('AUDIO.NO_DEVICES')}
        className="device-selector-empty"
      >
        <Button
          type="primary"
          icon={<ReloadOutlined />}
          onClick={onRefresh}
          disabled={disabled}
        >
          {i18n.t('AUDIO.REFRESH_DEVICES')}
        </Button>
      </Empty>
    );
  }

  return (
    <div className="device-selector">
      <div className="device-selector-header">
        <span>{i18n.t('AUDIO.AVAILABLE_DEVICES')} ({devices.length})</span>
        <Button
          type="text"
          size="small"
          icon={<ReloadOutlined />}
          onClick={onRefresh}
          disabled={disabled}
          className="device-selector-refresh"
        >
          {i18n.t('COMMON.REFRESH')}
        </Button>
      </div>

      <div className="device-selector-list">
        {devices.map((device, index) => {
          const isSelected = selectedDevice?.index === device.index;

          return (
            <Card
              key={device.index || index}
              className={`device-selector-item ${isSelected ? 'device-selector-item--selected' : ''}`}
              hoverable={!disabled}
              onClick={() => !disabled && onSelect(device)}
            >
              <div className="device-selector-item-content">
                <div className="device-selector-item-icon">
                  {isSelected ? (
                    <CheckCircleOutlined style={{ color: '#52c41a', fontSize: 24 }} />
                  ) : (
                    <AudioOutlined style={{ color: '#3b82f6', fontSize: 24 }} />
                  )}
                </div>

                <div className="device-selector-item-info">
                  <div className="device-selector-item-name">
                    {device.name || `Device ${device.index}`}
                  </div>
                  <div className="device-selector-item-details">
                    <Space size="small">
                      <Tag color="blue">{device.channels || 2} CH</Tag>
                      <Tag color="cyan">{device.sampleRate || 48000} Hz</Tag>
                      {device.default && (
                        <Tag color="green">{i18n.t('AUDIO.DEFAULT')}</Tag>
                      )}
                    </Space>
                  </div>
                </div>

                {isSelected && (
                  <div className="device-selector-item-badge">
                    {i18n.t('AUDIO.ACTIVE')}
                  </div>
                )}
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
};
