import React, { useState } from 'react';
import { DeleteOutlined, ExclamationCircleOutlined, SortAscendingOutlined, SortDescendingOutlined } from '@ant-design/icons';
import { Popconfirm, Spin, Empty } from 'antd';
import i18n from '../../../../locale/locale';
import '../ProcessManager.css';

/**
 * ProcessTable - Table displaying process list with sorting and actions
 */
const ProcessTable = ({
  processes,
  loading,
  onKillProcess,
  sortBy,
  sortOrder,
  onSort,
}) => {
  const [killingPid, setKillingPid] = useState(null);

  const handleKillProcess = async (pid, name) => {
    setKillingPid(pid);
    await onKillProcess(pid, name);
    setKillingPid(null);
  };

  const renderSortIcon = (field) => {
    if (sortBy !== field) {
      return <span className="procmgr-sort-icon procmgr-sort-icon--inactive">⇅</span>;
    }
    return sortOrder === 'asc' ? (
      <SortAscendingOutlined className="procmgr-sort-icon" />
    ) : (
      <SortDescendingOutlined className="procmgr-sort-icon" />
    );
  };

  if (loading && processes.length === 0) {
    return (
      <div className="procmgr-loading">
        <Spin size="large" tip="Loading processes..." />
      </div>
    );
  }

  if (!loading && processes.length === 0) {
    return (
      <div className="procmgr-empty">
        <Empty description="No processes found" />
      </div>
    );
  }

  return (
    <div className="procmgr-table-container">
      <table className="procmgr-table">
        <thead className="procmgr-table-head">
          <tr>
            <th
              className="procmgr-table-header procmgr-table-header--sortable"
              onClick={() => onSort('name')}
            >
              <div className="procmgr-table-header-content">
                <span>{i18n.t('PROCMGR.PROCESS')}</span>
                {renderSortIcon('name')}
              </div>
            </th>
            <th
              className="procmgr-table-header procmgr-table-header--sortable procmgr-table-header--pid"
              onClick={() => onSort('pid')}
            >
              <div className="procmgr-table-header-content">
                <span>PID</span>
                {renderSortIcon('pid')}
              </div>
            </th>
            <th className="procmgr-table-header procmgr-table-header--actions">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="procmgr-table-body">
          {processes.map((proc) => (
            <tr key={proc.pid} className="procmgr-table-row">
              <td className="procmgr-table-cell procmgr-table-cell--name">
                <span className="procmgr-process-name" title={proc.name}>
                  {proc.name || 'Unknown'}
                </span>
              </td>
              <td className="procmgr-table-cell procmgr-table-cell--pid">
                <span className="procmgr-process-pid">{proc.pid}</span>
              </td>
              <td className="procmgr-table-cell procmgr-table-cell--actions">
                <Popconfirm
                  title={
                    <div>
                      <ExclamationCircleOutlined style={{ color: '#faad14', marginRight: 8 }} />
                      {i18n.t('PROCMGR.KILL_PROCESS_CONFIRM')}
                    </div>
                  }
                  description={
                    <div style={{ marginTop: 8 }}>
                      Process: <strong>{proc.name}</strong> (PID: {proc.pid})
                    </div>
                  }
                  onConfirm={() => handleKillProcess(proc.pid, proc.name)}
                  okText="Kill Process"
                  cancelText="Cancel"
                  okButtonProps={{ danger: true }}
                  disabled={killingPid === proc.pid}
                >
                  <button
                    className="procmgr-kill-button"
                    disabled={killingPid === proc.pid}
                    title={`Kill ${proc.name}`}
                  >
                    {killingPid === proc.pid ? (
                      <Spin size="small" />
                    ) : (
                      <>
                        <DeleteOutlined />
                        <span>Kill</span>
                      </>
                    )}
                  </button>
                </Popconfirm>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {loading && (
        <div className="procmgr-table-loading-overlay">
          <Spin size="small" />
        </div>
      )}
    </div>
  );
};

export default ProcessTable;
