import React from 'react';
import { CloseOutlined } from '@ant-design/icons';
import { IconButton } from '../../../../shared';
import DeviceIndicator from './DeviceIndicator';
import ConnectionStatus from './ConnectionStatus';
import StatsDisplay from './StatsDisplay';
import './Toolbar.css';

/**
 * Toolbar - Top toolbar for desktop viewer
 */
const Toolbar = ({
  device,
  status,
  latency,
  fps,
  bandwidth,
  resolution,
  onClose,
}) => {
  return (
    <div className="desktop-toolbar">
      <div className="desktop-toolbar-left">
        <DeviceIndicator device={device} />
      </div>

      <div className="desktop-toolbar-center">
        <ConnectionStatus status={status} latency={latency} />
      </div>

      <div className="desktop-toolbar-right">
        <StatsDisplay
          fps={fps}
          bandwidth={bandwidth}
          resolution={resolution}
        />
        <div className="toolbar-divider" />
        <IconButton
          icon={<CloseOutlined />}
          tooltip="Close"
          onClick={onClose}
          variant="danger"
        />
      </div>
    </div>
  );
};

export default Toolbar;
