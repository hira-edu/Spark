import React from 'react';
import { WindowsOutlined, AppleOutlined, CloudServerOutlined, ClockCircleOutlined } from '@ant-design/icons';
import { StatusBadge } from '../../../shared';
import './Terminal.css';

/**
 * Header - Terminal header with shell info and session timer
 */
const Header = ({
  device,
  status,
  shell,
  cwd,
  sessionStart,
}) => {
  const getOsIcon = (os) => {
    if (!os) return null;
    const osLower = os.toLowerCase();
    if (osLower.includes('windows')) return <WindowsOutlined />;
    if (osLower.includes('darwin') || osLower.includes('mac')) return <AppleOutlined />;
    if (osLower.includes('linux')) return <CloudServerOutlined />;
    return null;
  };

  const formatDuration = (start) => {
    if (!start) return '--:--';
    const diff = Math.floor((Date.now() - start) / 1000);
    const hours = Math.floor(diff / 3600);
    const minutes = Math.floor((diff % 3600) / 60);
    const seconds = diff % 60;
    if (hours > 0) {
      return `${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    }
    return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
  };

  return (
    <div className="terminal-header">
      <div className="terminal-header-left">
        <span className="terminal-header-device">
          {getOsIcon(device?.os)}
          <span>{device?.hostname || 'Unknown'}</span>
        </span>
        <StatusBadge
          status={status}
          label={status === 'connected' ? 'Connected' : status}
          pulse={status === 'connecting'}
        />
      </div>
      <div className="terminal-header-center">
        {shell && (
          <span className="terminal-header-shell">
            {shell}
          </span>
        )}
        {cwd && (
          <span className="terminal-header-cwd" title={cwd}>
            {cwd.length > 40 ? `...${cwd.slice(-37)}` : cwd}
          </span>
        )}
      </div>
      <div className="terminal-header-right">
        <span className="terminal-header-timer">
          <ClockCircleOutlined />
          <span>{formatDuration(sessionStart)}</span>
        </span>
      </div>
    </div>
  );
};

export default Header;
