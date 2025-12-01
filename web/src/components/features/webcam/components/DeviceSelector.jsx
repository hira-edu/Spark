import React from 'react';
import { Button, Empty, Space, Card, Tag } from 'antd';
import {
  CameraOutlined,
  ReloadOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';
import i18n from '../../../../locale/locale';
import './DeviceSelector.css';

/**
 * DeviceSelector - Webcam device selection component
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
        description={i18n.t('WEBCAM.NO_DEVICES')}
        className="webcam-device-selector-empty"
      >
        <Button
          type="primary"
          icon={<ReloadOutlined />}
          onClick={onRefresh}
          disabled={disabled}
        >
          {i18n.t('WEBCAM.REFRESH_DEVICES')}
        </Button>
      </Empty>
    );
  }

  return (
    <div className="webcam-device-selector">
      <div className="webcam-device-selector-header">
        <span>{i18n.t('WEBCAM.AVAILABLE_DEVICES')} ({devices.length})</span>
        <Button
          type="text"
          size="small"
          icon={<ReloadOutlined />}
          onClick={onRefresh}
          disabled={disabled}
          className="webcam-device-selector-refresh"
        >
          {i18n.t('COMMON.REFRESH')}
        </Button>
      </div>

      <div className="webcam-device-selector-list">
        {devices.map((device, index) => {
          const isSelected = selectedDevice?.path === device.path;

          return (
            <Card
              key={device.path || index}
              className={`webcam-device-selector-item ${isSelected ? 'webcam-device-selector-item--selected' : ''}`}
              hoverable={!disabled}
              onClick={() => !disabled && onSelect(device)}
            >
              <div className="webcam-device-selector-item-content">
                <div className="webcam-device-selector-item-icon">
                  {isSelected ? (
                    <CheckCircleOutlined style={{ color: '#52c41a', fontSize: 24 }} />
                  ) : (
                    <CameraOutlined style={{ color: '#3b82f6', fontSize: 24 }} />
                  )}
                </div>

                <div className="webcam-device-selector-item-info">
                  <div className="webcam-device-selector-item-name">
                    {device.name || device.path}
                  </div>
                  <div className="webcam-device-selector-item-details">
                    <Space size="small">
                      <Tag color="blue">{device.path}</Tag>
                      {device.driver && (
                        <Tag color="cyan">{device.driver}</Tag>
                      )}
                    </Space>
                  </div>
                </div>

                {isSelected && (
                  <div className="webcam-device-selector-item-badge">
                    {i18n.t('WEBCAM.ACTIVE')}
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
