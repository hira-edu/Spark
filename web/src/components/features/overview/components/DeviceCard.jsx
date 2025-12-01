import React from 'react';
import { WindowsOutlined, AppleOutlined, CloudServerOutlined, MoreOutlined } from '@ant-design/icons';
import { Dropdown, Progress, Tooltip } from 'antd';
import { formatSize } from '../../../../utils/utils';
import i18n from '../../../../locale/locale';
import '../Overview.css';

/**
 * DeviceCard - Modern card displaying device info and stats
 */
const DeviceCard = ({ device, onAction }) => {
  const getOsIcon = (os) => {
    if (!os) return <CloudServerOutlined />;
    const osLower = os.toLowerCase();
    if (osLower.includes('windows')) return <WindowsOutlined />;
    if (osLower.includes('darwin') || osLower.includes('mac')) return <AppleOutlined />;
    if (osLower.includes('linux')) return <CloudServerOutlined />;
    return <CloudServerOutlined />;
  };

  const formatNetworkIO = (device) => {
    let sent = device.net_sent * 8 / 1024;
    let recv = device.net_recv * 8 / 1024;
    return `${format(sent)} ↑ / ${format(recv)} ↓`;

    function format(size) {
      if (size <= 1) return '0 Kbps';
      let k = 1024,
        i = Math.floor(Math.log(size) / Math.log(k)),
        units = ['Kbps', 'Mbps', 'Gbps', 'Tbps'];
      return (size / Math.pow(k, i)).toFixed(1) + ' ' + units[i];
    }
  };

  const getUsageColor = (usage) => {
    if (usage < 50) return '#52c41a';
    if (usage < 80) return '#faad14';
    return '#ff4d4f';
  };

  const quickActions = [
    { key: 'terminal', label: i18n.t('OVERVIEW.TERMINAL'), primary: true },
    { key: 'desktop', label: i18n.t('OVERVIEW.DESKTOP'), primary: true },
    { key: 'explorer', label: i18n.t('OVERVIEW.EXPLORER'), primary: true },
    { key: 'procmgr', label: i18n.t('OVERVIEW.PROC_MANAGER'), primary: true },
  ];

  const moreActions = [
    { key: 'execute', label: i18n.t('OVERVIEW.EXECUTE') },
    { key: 'screenshot', label: i18n.t('OVERVIEW.SCREENSHOT') },
    { key: 'audio', label: i18n.t('OVERVIEW.AUDIO') },
    { key: 'webcam', label: i18n.t('OVERVIEW.WEBCAM') },
    { key: 'share', label: i18n.t('COMMON.SHARE') || 'Share' },
    { type: 'divider' },
    { key: 'lock', label: i18n.t('OVERVIEW.LOCK') },
    { key: 'logoff', label: i18n.t('OVERVIEW.LOGOFF') },
    { key: 'hibernate', label: i18n.t('OVERVIEW.HIBERNATE') },
    { key: 'suspend', label: i18n.t('OVERVIEW.SUSPEND') },
    { type: 'divider' },
    { key: 'restart', label: i18n.t('OVERVIEW.RESTART'), danger: true },
    { key: 'shutdown', label: i18n.t('OVERVIEW.SHUTDOWN'), danger: true },
    { key: 'offline', label: i18n.t('OVERVIEW.OFFLINE'), danger: true },
  ];

  const cpu = device.cpu || {};
  const ram = device.ram || {};
  const disk = device.disk || {};

  const cpuUsage = Math.round((cpu.usage || 0) * 100) / 100;
  const ramUsage = Math.round((ram.usage || 0) * 100) / 100;
  const diskUsage = Math.round((disk.usage || 0) * 100) / 100;

  return (
    <div className="device-card">
      <div className="device-card-header">
        <div className="device-card-os-icon">
          {getOsIcon(device.os)}
        </div>
        <div className="device-card-info">
          <div className="device-card-hostname">{device.hostname || 'Unknown'}</div>
          <div className="device-card-meta">
            <span>{device.username || 'Unknown'}</span>
            <span className="device-card-separator">•</span>
            <span>{device.os || 'Unknown'}</span>
          </div>
        </div>
        <Dropdown
          menu={{
            items: moreActions,
            onClick: ({ key }) => onAction(key, device),
          }}
          trigger={['click']}
          placement="bottomRight"
        >
          <button className="device-card-more">
            <MoreOutlined />
          </button>
        </Dropdown>
      </div>

      <div className="device-card-stats">
        <StatItem
          label={i18n.t('OVERVIEW.CPU_USAGE')}
          value={`${cpuUsage}%`}
          usage={cpuUsage}
          color={getUsageColor(cpuUsage)}
          tooltip={
            <div>
              <div style={{ fontSize: '10px', marginBottom: '4px' }}>{cpu.model}</div>
              <div>{i18n.t('OVERVIEW.CPU_USAGE')}: {cpuUsage}%</div>
              <div>{i18n.t('OVERVIEW.CPU_LOGICAL_CORES')}: {cpu.cores?.logical || 0}</div>
              <div>{i18n.t('OVERVIEW.CPU_PHYSICAL_CORES')}: {cpu.cores?.physical || 0}</div>
            </div>
          }
        />
        <StatItem
          label={i18n.t('OVERVIEW.RAM_USAGE')}
          value={`${ramUsage}%`}
          usage={ramUsage}
          color={getUsageColor(ramUsage)}
          tooltip={
            <div>
              <div>{i18n.t('OVERVIEW.RAM_USAGE')}: {ramUsage}%</div>
              <div>{i18n.t('OVERVIEW.USED')}: {formatSize(ram.used || 0)}</div>
              <div>{i18n.t('OVERVIEW.FREE')}: {formatSize((ram.total || 0) - (ram.used || 0))}</div>
              <div>{i18n.t('OVERVIEW.TOTAL')}: {formatSize(ram.total || 0)}</div>
            </div>
          }
        />
        <StatItem
          label={i18n.t('OVERVIEW.DISK_USAGE')}
          value={`${diskUsage}%`}
          usage={diskUsage}
          color={getUsageColor(diskUsage)}
          tooltip={
            <div>
              <div>{i18n.t('OVERVIEW.DISK_USAGE')}: {diskUsage}%</div>
              <div>{i18n.t('OVERVIEW.USED')}: {formatSize(disk.used || 0)}</div>
              <div>{i18n.t('OVERVIEW.FREE')}: {formatSize((disk.total || 0) - (disk.used || 0))}</div>
              <div>{i18n.t('OVERVIEW.TOTAL')}: {formatSize(disk.total || 0)}</div>
            </div>
          }
        />
      </div>

      <div className="device-card-network">
        <div className="device-card-network-item">
          <span className="device-card-network-label">Ping</span>
          <span className="device-card-network-value">{device.latency || 0}ms</span>
        </div>
        <div className="device-card-network-item">
          <span className="device-card-network-label">{i18n.t('OVERVIEW.NETWORK')}</span>
          <span className="device-card-network-value">{formatNetworkIO(device)}</span>
        </div>
      </div>

      <div className="device-card-actions">
        {quickActions.map(action => (
          <button
            key={action.key}
            className="device-card-action-button"
            onClick={() => onAction(action.key, device)}
          >
            {action.label}
          </button>
        ))}
      </div>
    </div>
  );
};

const StatItem = ({ label, value, usage, color, tooltip }) => {
  return (
    <Tooltip title={tooltip} placement="top">
      <div className="device-card-stat">
        <div className="device-card-stat-header">
          <span className="device-card-stat-label">{label}</span>
          <span className="device-card-stat-value">{value}</span>
        </div>
        <Progress
          percent={usage}
          showInfo={false}
          strokeColor={color}
          trailColor="var(--color-bg-tertiary)"
          strokeWidth={6}
        />
      </div>
    </Tooltip>
  );
};

export default DeviceCard;
