import React, { useCallback } from 'react';
import { Slider, Switch, Tooltip } from 'antd';
import './Controls.css';

/**
 * QualitySlider - Adjusts the stream quality (JPEG/WebP compression)
 */
const QualitySlider = ({ value, onChange, auto = false, onAutoChange, disabled = false }) => {
  const handleChange = useCallback((val) => {
    if (onChange) {
      onChange(val);
    }
  }, [onChange]);

  const handleAutoChange = useCallback((checked) => {
    if (onAutoChange) {
      onAutoChange(checked);
    }
  }, [onAutoChange]);

  const getQualityLabel = (val) => {
    if (val >= 90) return 'Ultra';
    if (val >= 70) return 'High';
    if (val >= 50) return 'Medium';
    if (val >= 30) return 'Low';
    return 'Very Low';
  };

  return (
    <div className="quality-slider">
      <Tooltip title={auto ? 'Quality: Auto' : `Quality: ${getQualityLabel(value)}`}>
        <span className="control-label">Quality</span>
      </Tooltip>
      <Tooltip title={auto ? 'Adaptive quality enabled' : 'Fixed quality'}>
        <Switch
          size="small"
          checked={auto}
          onChange={handleAutoChange}
          disabled={disabled}
          checkedChildren="Auto"
          unCheckedChildren="Fixed"
        />
      </Tooltip>
      <Slider
        className="quality-slider-input"
        min={10}
        max={100}
        step={5}
        value={value}
        onChange={handleChange}
        disabled={disabled || auto}
        tooltip={{ formatter: (val) => `${val}%` }}
      />
      <span className="control-value">{auto ? 'Auto' : `${value}%`}</span>
    </div>
  );
};

export default QualitySlider;
