import React from 'react';
import { Tooltip } from 'antd';
import './Controls.css';

/**
 * InputToggle - Toggle button for mouse/keyboard input
 */
const InputToggle = ({ icon, label, active, onClick, disabled = false }) => {
  return (
    <Tooltip title={`${label}: ${active ? 'ON' : 'OFF'}`}>
      <button
        className={`input-toggle ${active ? 'input-toggle--active' : ''}`}
        onClick={onClick}
        disabled={disabled}
      >
        <span className="input-toggle-icon">{icon}</span>
        <span className="input-toggle-label">{label}</span>
      </button>
    </Tooltip>
  );
};

export default InputToggle;
