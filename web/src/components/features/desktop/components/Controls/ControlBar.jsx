import React from 'react';
import { DesktopOutlined } from '@ant-design/icons';
import FPSSelector from './FPSSelector';
import InputToggle from './InputToggle';
import ActionButtons from './ActionButtons';
import MonitorStatus from './MonitorStatus';
import './Controls.css';

// Icons for input toggles - Simple outline style to match Ant Design icons
const MouseIcon = () => (
  <svg width="14" height="14" viewBox="0 0 1024 1024" fill="currentColor">
    <path d="M464 144c-114.9 0-208 93.1-208 208v320c0 114.9 93.1 208 208 208h96c114.9 0 208-93.1 208-208V352c0-114.9-93.1-208-208-208h-96zm-144 208c0-79.5 64.5-144 144-144v256H320V352zm144 384c-79.5 0-144-64.5-144-144v-96h144v240zm64-240h144v96c0 79.5-64.5 144-144 144V496zm144-144c0 79.5-64.5 144-144 144V208c79.5 0 144 64.5 144 144z" />
  </svg>
);

const KeyboardIcon = () => (
  <svg width="14" height="14" viewBox="0 0 1024 1024" fill="currentColor">
    <path d="M192 256c-35.3 0-64 28.7-64 64v384c0 35.3 28.7 64 64 64h640c35.3 0 64-28.7 64-64V320c0-35.3-28.7-64-64-64H192zm0 64h640v384H192V320zm64 64v64h64v-64h-64zm128 0v64h64v-64h-64zm128 0v64h64v-64h-64zm128 0v64h64v-64h-64zm128 0v64h64v-64h-64zM256 512v64h64v-64h-64zm128 0v64h64v-64h-64zm128 0v64h64v-64h-64zm128 0v64h64v-64h-64zm128 0v64h64v-64h-64zM320 640v64h384v-64H320z" />
  </svg>
);

/**
 * ControlBar - Bottom control bar for desktop viewer
 */
const ControlBar = ({
  targetFps,
  onFpsChange,
  allowControl = true,
  mouseEnabled,
  onMouseToggle,
  keyboardEnabled,
  onKeyboardToggle,
  onScreenshot,
  isFullscreen,
  onFullscreen,
  monitors = [],
  selectedMonitor,
  onMonitorSelect,
  disabled = false,
}) => {
  return (
    <div className="control-bar">
      <div className="control-bar-left">
        <FPSSelector
          value={targetFps}
          onChange={onFpsChange}
          disabled={disabled}
        />
      </div>

      <div className="control-bar-center">
        <InputToggle
          icon={<MouseIcon />}
          label="Mouse"
          active={mouseEnabled}
          onClick={onMouseToggle}
          disabled={disabled || !allowControl}
        />
        <InputToggle
          icon={<KeyboardIcon />}
          label="Keyboard"
          active={keyboardEnabled}
          onClick={onKeyboardToggle}
          disabled={disabled || !allowControl}
        />
        {monitors.length > 1 && (
          <>
            <div className="control-divider" />
            <InputToggle
              icon={<DesktopOutlined />}
              label={`Monitor ${selectedMonitor + 1}`}
              active={false}
              onClick={() => onMonitorSelect && onMonitorSelect((selectedMonitor + 1) % monitors.length)}
              disabled={disabled}
            />
          </>
        )}
      </div>

      <div className="control-bar-right">
        <MonitorStatus
          monitors={monitors}
          selectedMonitor={selectedMonitor}
        />
        <ActionButtons
          onScreenshot={onScreenshot}
          isFullscreen={isFullscreen}
          onFullscreen={onFullscreen}
          disabled={disabled}
        />
      </div>
    </div>
  );
};

export default ControlBar;
