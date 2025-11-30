import React from 'react';
import { formatSize } from '../../../../../utils/utils';
import './Toolbar.css';

/**
 * StatsDisplay - Shows FPS, bandwidth, and resolution stats
 */
const StatsDisplay = ({ fps, bandwidth, resolution }) => {
  return (
    <div className="stats-display">
      <div className="stat-item">
        <span className="stat-label">FPS</span>
        <span className="stat-value">{fps || 0}</span>
      </div>
      <div className="stat-divider" />
      <div className="stat-item">
        <span className="stat-label">BW</span>
        <span className="stat-value">{formatSize(bandwidth || 0)}/s</span>
      </div>
      <div className="stat-divider" />
      <div className="stat-item">
        <span className="stat-label">Res</span>
        <span className="stat-value">
          {resolution?.width || 0}x{resolution?.height || 0}
        </span>
      </div>
    </div>
  );
};

export default StatsDisplay;
