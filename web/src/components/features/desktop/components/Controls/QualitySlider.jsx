import React, { useCallback } from 'react';
import { Slider, Tooltip } from 'antd';
import './Controls.css';

/**
 * QualitySlider - Adjusts the stream quality (JPEG/WebP compression)
 */
const QualitySlider = ({ value, onChange, disabled = false }) => {
  const handleChange = useCallback((val) => {
    if (onChange) {
      onChange(val);
    }
  }, [onChange]);

  const getQualityLabel = (val) => {
    if (val >= 90) return 'Ultra';
    if (val >= 70) return 'High';
    if (val >= 50) return 'Medium';
    if (val >= 30) return 'Low';
    return 'Very Low';
  };

  return (
    <div className="quality-slider">
      <Tooltip title={`Quality: ${getQualityLabel(value)}`}>
        <span className="control-label">Quality</span>
      </Tooltip>
      <Slider
        className="quality-slider-input"
        min={10}
        max={100}
        step={5}
        value={value}
        onChange={handleChange}
        disabled={disabled}
        tooltip={{ formatter: (val) => `${val}%` }}
      />
      <span className="control-value">{value}%</span>
    </div>
  );
};

export default QualitySlider;
