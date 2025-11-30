import React from 'react';
import { DesktopOutlined } from '@ant-design/icons';
import QualitySlider from './QualitySlider';
import FPSSelector from './FPSSelector';
import InputToggle from './InputToggle';
import ActionButtons from './ActionButtons';
import './Controls.css';

// Icons for input toggles
const MouseIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M11.5 2C8.46243 2 6 4.46243 6 7.5V16.5C6 19.5376 8.46243 22 11.5 22H12.5C15.5376 22 18 19.5376 18 16.5V7.5C18 4.46243 15.5376 2 12.5 2H11.5ZM8 7.5C8 5.567 9.567 4 11.5 4H12.5C14.433 4 16 5.567 16 7.5V10H12V4.083C11.8348 4.0284 11.6707 4 11.5 4V10H8V7.5Z" />
  </svg>
);

const KeyboardIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M4 5C2.89543 5 2 5.89543 2 7V17C2 18.1046 2.89543 19 4 19H20C21.1046 19 22 18.1046 22 17V7C22 5.89543 21.1046 5 20 5H4ZM4 7H20V17H4V7ZM5 8V10H7V8H5ZM8 8V10H10V8H8ZM11 8V10H13V8H11ZM14 8V10H16V8H14ZM17 8V10H19V8H17ZM5 11V13H7V11H5ZM8 11V13H10V11H8ZM11 11V13H13V11H11ZM14 11V13H16V11H14ZM17 11V13H19V11H17ZM7 14V16H17V14H7Z" />
  </svg>
);

/**
 * ControlBar - Bottom control bar for desktop viewer
 */
const ControlBar = ({
  quality,
  onQualityChange,
  targetFps,
  onFpsChange,
  mouseEnabled,
  onMouseToggle,
  keyboardEnabled,
  onKeyboardToggle,
  onScreenshot,
  onClipboard,
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
        <QualitySlider
          value={quality}
          onChange={onQualityChange}
          disabled={disabled}
        />
        <div className="control-divider" />
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
          disabled={disabled}
        />
        <InputToggle
          icon={<KeyboardIcon />}
          label="Keyboard"
          active={keyboardEnabled}
          onClick={onKeyboardToggle}
          disabled={disabled}
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
        <ActionButtons
          onScreenshot={onScreenshot}
          onClipboard={onClipboard}
          isFullscreen={isFullscreen}
          onFullscreen={onFullscreen}
          disabled={disabled}
        />
      </div>
    </div>
  );
};

export default ControlBar;
