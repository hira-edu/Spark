import React from 'react';
import { WindowsOutlined, AppleOutlined, CloudServerOutlined, ClockCircleOutlined } from '@ant-design/icons';
import { StatusBadge } from '../../../shared';
import '../ProcessManager.css';

/**
 * Header - Process Manager header with device info
 */
const Header = ({ device, processCount, lastUpdate }) => {
  const getOsIcon = (os) => {
    if (!os) return null;
    const osLower = os.toLowerCase();
    if (osLower.includes('windows')) return <WindowsOutlined />;
    if (osLower.includes('darwin') || osLower.includes('mac')) return <AppleOutlined />;
    if (osLower.includes('linux')) return <CloudServerOutlined />;
    return null;
  };

  const formatTime = (timestamp) => {
    if (!timestamp) return '--:--:--';
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };

  return (
    <div className="procmgr-header">
      <div className="procmgr-header-left">
        <span className="procmgr-header-device">
          {getOsIcon(device?.os)}
          <span>{device?.hostname || 'Unknown'}</span>
        </span>
        <StatusBadge
          status="connected"
          label="Connected"
        />
      </div>
      <div className="procmgr-header-center">
        <span className="procmgr-header-count">
          {processCount} {processCount === 1 ? 'Process' : 'Processes'}
        </span>
      </div>
      <div className="procmgr-header-right">
        <span className="procmgr-header-time">
          <ClockCircleOutlined />
          <span>{formatTime(lastUpdate)}</span>
        </span>
      </div>
    </div>
  );
};

export default Header;
