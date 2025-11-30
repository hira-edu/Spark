import React from 'react';
import './StatusBadge.css';

/**
 * StatusBadge - A status indicator with optional label
 * @param {'connected' | 'connecting' | 'disconnected' | 'error' | 'idle'} props.status - Status type
 * @param {string} props.label - Optional label text
 * @param {boolean} props.pulse - Whether to show pulse animation
 * @param {string} props.className - Additional class names
 */
const StatusBadge = ({ status = 'idle', label, pulse = false, className = '' }) => {
  return (
    <div className={`status-badge status-badge--${status} ${className}`}>
      <span className={`status-badge-dot ${pulse ? 'status-badge-dot--pulse' : ''}`} />
      {label && <span className="status-badge-label">{label}</span>}
    </div>
  );
};

export default StatusBadge;
