import React from 'react';
import { Empty, Spin } from 'antd';
import DeviceCard from './DeviceCard';
import DeviceListItem from './DeviceListItem';
import '../Overview.css';

/**
 * DeviceGrid - Grid or list layout for devices
 */
const DeviceGrid = ({ devices, loading, viewMode, onDeviceAction }) => {
  if (loading && devices.length === 0) {
    return (
      <div className="overview-loading">
        <Spin size="large" tip="Loading devices..." />
      </div>
    );
  }

  if (!loading && devices.length === 0) {
    return (
      <div className="overview-empty">
        <Empty
          description="No devices found"
          image={Empty.PRESENTED_IMAGE_SIMPLE}
        />
      </div>
    );
  }

  if (viewMode === 'list') {
    return (
      <div className="overview-device-list">
        <div className="overview-list-header">
          <div className="overview-list-col overview-list-col--hostname">Hostname</div>
          <div className="overview-list-col overview-list-col--user">User</div>
          <div className="overview-list-col overview-list-col--os">OS</div>
          <div className="overview-list-col overview-list-col--stats">CPU</div>
          <div className="overview-list-col overview-list-col--stats">RAM</div>
          <div className="overview-list-col overview-list-col--stats">Disk</div>
          <div className="overview-list-col overview-list-col--network">Network</div>
          <div className="overview-list-col overview-list-col--actions">Actions</div>
        </div>
        <div className="overview-list-body">
          {devices.map((device) => (
            <DeviceListItem
              key={device.id || device.conn}
              device={device}
              onAction={onDeviceAction}
            />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="overview-device-grid">
      {devices.map((device) => (
        <DeviceCard
          key={device.id || device.conn}
          device={device}
          onAction={onDeviceAction}
        />
      ))}
    </div>
  );
};

export default DeviceGrid;
