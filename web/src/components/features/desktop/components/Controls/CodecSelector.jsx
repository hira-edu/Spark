import React, { useCallback } from 'react';
import { Select, Tooltip } from 'antd';
import './Controls.css';

const CODEC_OPTIONS = [
  { value: 'jpeg', label: 'JPEG' },
  { value: 'png', label: 'PNG (Lossless)' },
];

const CODEC_LABELS = {
  jpeg: 'JPEG',
  png: 'PNG (Lossless)',
};

/**
 * CodecSelector - Selects the tile/image codec used for the WS/canvas transport.
 * Note: When WebRTC is active, the codec here only affects the fallback tiles path.
 */
const CodecSelector = ({ value, onChange, disabled = false }) => {
  const handleChange = useCallback((val) => {
    if (onChange) {
      onChange(val);
    }
  }, [onChange]);

  const label = CODEC_LABELS[value] || value || 'Auto';

  return (
    <div className="codec-selector">
      <Tooltip title={`Codec: ${label}`}>
        <span className="control-label">Codec</span>
      </Tooltip>
      <Select
        className="codec-selector-input"
        value={value}
        onChange={handleChange}
        disabled={disabled}
        options={CODEC_OPTIONS}
        popupMatchSelectWidth={false}
        size="small"
      />
    </div>
  );
};

export default CodecSelector;

