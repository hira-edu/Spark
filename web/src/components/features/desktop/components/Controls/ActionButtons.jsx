import React from 'react';
import { CameraOutlined, CopyOutlined, FullscreenOutlined, FullscreenExitOutlined } from '@ant-design/icons';
import { IconButton } from '../../../../shared';
import './Controls.css';

/**
 * ActionButtons - Screenshot, clipboard, and fullscreen buttons
 */
const ActionButtons = ({
  onScreenshot,
  onClipboard,
  isFullscreen,
  onFullscreen,
  disabled = false,
}) => {
  return (
    <div className="action-buttons">
      <IconButton
        icon={<CameraOutlined />}
        tooltip="Take Screenshot"
        onClick={onScreenshot}
        disabled={disabled}
      />
      <IconButton
        icon={<CopyOutlined />}
        tooltip="Sync Clipboard"
        onClick={onClipboard}
        disabled={disabled}
      />
      <IconButton
        icon={isFullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
        tooltip={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
        onClick={onFullscreen}
        disabled={disabled}
      />
    </div>
  );
};

export default ActionButtons;
