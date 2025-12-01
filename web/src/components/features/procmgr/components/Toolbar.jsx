import React from 'react';
import { SearchOutlined, ReloadOutlined, CloseOutlined } from '@ant-design/icons';
import { IconButton } from '../../../shared';
import '../ProcessManager.css';

/**
 * Toolbar - Process Manager toolbar with search and actions
 */
const Toolbar = ({
  filterText,
  onFilterChange,
  onRefresh,
  onClose,
  loading,
}) => {
  const handleClearSearch = () => {
    onFilterChange('');
  };

  return (
    <div className="procmgr-toolbar">
      <div className="procmgr-toolbar-left">
        <div className="procmgr-search">
          <SearchOutlined className="procmgr-search-icon" />
          <input
            type="text"
            className="procmgr-search-input"
            placeholder="Search processes by name or PID..."
            value={filterText}
            onChange={(e) => onFilterChange(e.target.value)}
          />
          {filterText && (
            <button
              className="procmgr-search-clear"
              onClick={handleClearSearch}
              title="Clear search"
            >
              <CloseOutlined />
            </button>
          )}
        </div>
      </div>
      <div className="procmgr-toolbar-right">
        <IconButton
          icon={<ReloadOutlined spin={loading} />}
          onClick={onRefresh}
          disabled={loading}
          tooltip="Refresh process list"
        />
        <IconButton
          icon={<CloseOutlined />}
          onClick={onClose}
          tooltip="Close"
        />
      </div>
    </div>
  );
};

export default Toolbar;
