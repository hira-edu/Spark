import React from 'react';
import './Controls.css';

const MonitorStatus = ({ monitors = [], selectedMonitor = 0 }) => {
  if (!Array.isArray(monitors) || monitors.length === 0) {
    return <div className="monitor-status">Monitors: none reported</div>;
  }

  const labels = monitors.map((monitor, idx) => {
    const name = monitor?.name || monitor?.id || monitor?.label || `Monitor ${idx + 1}`;
    const resolution = monitor?.width && monitor?.height
      ? `${monitor.width}x${monitor.height}`
      : null;
    const flags = [];
    if (monitor?.primary) {
      flags.push('primary');
    }
    if (idx === selectedMonitor) {
      flags.push('active');
    }
    const meta = [resolution, flags.join(', ')].filter(Boolean).join(' ');
    return `${name}${meta ? ` (${meta})` : ''}`;
  });

  return (
    <div className="monitor-status" title={labels.join(' | ')}>
      Monitors: {labels.join(' | ')}
    </div>
  );
};

export default MonitorStatus;
