import React from 'react';
import { WindowsOutlined, AppleOutlined, CloudServerOutlined, MoreOutlined } from '@ant-design/icons';
import { Dropdown, Progress, Tooltip } from 'antd';
import i18n from '../../../../locale/locale';
import '../Overview.css';

/**
 * DeviceListItem - List item view for device
 */
const DeviceListItem = ({ device, onAction }) => {
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
    { key: 'terminal', label: i18n.t('OVERVIEW.TERMINAL') },
    { key: 'desktop', label: i18n.t('OVERVIEW.DESKTOP') },
    { key: 'explorer', label: i18n.t('OVERVIEW.EXPLORER') },
    { key: 'procmgr', label: i18n.t('OVERVIEW.PROC_MANAGER') },
    { key: 'share', label: i18n.t('OVERVIEW.SHARE') },
  ];

  const moreActions = [
    { key: 'execute', label: i18n.t('OVERVIEW.EXECUTE') },
    { key: 'screenshot', label: i18n.t('OVERVIEW.SCREENSHOT') },
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
    <div className="overview-list-item">
      <div className="overview-list-col overview-list-col--hostname">
        <div className="overview-list-hostname">
          <span className="overview-list-icon">{getOsIcon(device.os)}</span>
          <span className="overview-list-hostname-text">{device.hostname || 'Unknown'}</span>
        </div>
      </div>

      <div className="overview-list-col overview-list-col--user">
        <span>{device.username || 'Unknown'}</span>
      </div>

      <div className="overview-list-col overview-list-col--os">
        <span>{device.os || 'Unknown'}</span>
      </div>

      <div className="overview-list-col overview-list-col--stats">
        <Tooltip title={`CPU: ${cpuUsage}%`}>
          <Progress
            percent={cpuUsage}
            showInfo={false}
            strokeColor={getUsageColor(cpuUsage)}
            trailColor="var(--color-bg-tertiary)"
            strokeWidth={8}
            style={{ width: '100%' }}
          />
        </Tooltip>
      </div>

      <div className="overview-list-col overview-list-col--stats">
        <Tooltip title={`RAM: ${ramUsage}%`}>
          <Progress
            percent={ramUsage}
            showInfo={false}
            strokeColor={getUsageColor(ramUsage)}
            trailColor="var(--color-bg-tertiary)"
            strokeWidth={8}
            style={{ width: '100%' }}
          />
        </Tooltip>
      </div>

      <div className="overview-list-col overview-list-col--stats">
        <Tooltip title={`Disk: ${diskUsage}%`}>
          <Progress
            percent={diskUsage}
            showInfo={false}
            strokeColor={getUsageColor(diskUsage)}
            trailColor="var(--color-bg-tertiary)"
            strokeWidth={8}
            style={{ width: '100%' }}
          />
        </Tooltip>
      </div>

      <div className="overview-list-col overview-list-col--network">
        <span className="overview-list-network">{formatNetworkIO(device)}</span>
      </div>

      <div className="overview-list-col overview-list-col--actions">
        <div className="overview-list-actions">
          {quickActions.map(action => (
            <button
              key={action.key}
              className="overview-list-action-link"
              onClick={() => onAction(action.key, device)}
            >
              {action.label}
            </button>
          ))}
          <Dropdown
            menu={{
              items: moreActions,
              onClick: ({ key }) => onAction(key, device),
            }}
            trigger={['click']}
            placement="bottomRight"
          >
            <button className="overview-list-more">
              <MoreOutlined />
            </button>
          </Dropdown>
        </div>
      </div>
    </div>
  );
};

export default DeviceListItem;
