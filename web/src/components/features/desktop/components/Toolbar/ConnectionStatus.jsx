import React from 'react';
import { StatusBadge } from '../../../../shared';
import './Toolbar.css';

/**
 * ConnectionStatus - Shows connection status with latency
 */
const ConnectionStatus = ({ status, latency }) => {
  const getStatusLabel = () => {
    switch (status) {
      case 'connected':
        return `Connected ${latency > 0 ? `${latency}ms` : ''}`;
      case 'connecting':
        return 'Connecting...';
      case 'reconnecting':
        return 'Reconnecting...';
      case 'disconnected':
        return 'Disconnected';
      case 'error':
        return 'Error';
      default:
        return 'Idle';
    }
  };

  const isConnecting = status === 'connecting' || status === 'reconnecting';

  return (
    <div className="connection-status">
      <StatusBadge
        status={status}
        label={getStatusLabel()}
        pulse={isConnecting}
      />
    </div>
  );
};

export default ConnectionStatus;
