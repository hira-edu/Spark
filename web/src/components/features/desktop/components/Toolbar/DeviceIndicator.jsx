import React from 'react';
import { WindowsOutlined, AppleOutlined, DesktopOutlined, CloudServerOutlined } from '@ant-design/icons';
import './Toolbar.css';

/**
 * DeviceIndicator - Shows device name and OS icon
 */
const DeviceIndicator = ({ device }) => {
  const getOsIcon = (os) => {
    if (!os) return <DesktopOutlined />;
    const osLower = os.toLowerCase();
    if (osLower.includes('windows')) return <WindowsOutlined />;
    if (osLower.includes('darwin') || osLower.includes('mac')) return <AppleOutlined />;
    if (osLower.includes('linux')) return <CloudServerOutlined />;
    return <DesktopOutlined />;
  };

  return (
    <div className="device-indicator">
      <span className="device-indicator-icon">
        {getOsIcon(device?.os)}
      </span>
      <span className="device-indicator-name">
        {device?.hostname || 'Unknown Device'}
      </span>
    </div>
  );
};

export default DeviceIndicator;
