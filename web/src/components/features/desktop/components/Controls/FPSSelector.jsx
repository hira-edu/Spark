import React, { useCallback } from 'react';
import { Select } from 'antd';
import './Controls.css';

const FPS_OPTIONS = [
  { value: 60, label: '60 FPS' },
  { value: 30, label: '30 FPS' },
  { value: 15, label: '15 FPS' },
  { value: 10, label: '10 FPS' },
  { value: 5, label: '5 FPS' },
];

/**
 * FPSSelector - Adjusts the target framerate
 */
const FPSSelector = ({ value, onChange, disabled = false }) => {
  const handleChange = useCallback((val) => {
    if (onChange) {
      onChange(val);
    }
  }, [onChange]);

  return (
    <div className="fps-selector">
      <span className="control-label">FPS</span>
      <Select
        className="fps-selector-input"
        value={value}
        onChange={handleChange}
        disabled={disabled}
        options={FPS_OPTIONS}
        popupMatchSelectWidth={false}
        size="small"
      />
    </div>
  );
};

export default FPSSelector;
