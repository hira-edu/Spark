import React from 'react';
import { SearchOutlined, AppstoreOutlined, UnorderedListOutlined, ReloadOutlined, PlusOutlined } from '@ant-design/icons';
import { IconButton } from '../../../shared';
import '../Overview.css';

/**
 * Toolbar - Overview toolbar with search, view toggle, and actions
 */
const Toolbar = ({
  searchText,
  onSearchChange,
  viewMode,
  onViewModeChange,
  onRefresh,
  onGenerate,
  loading,
  deviceCount,
}) => {
  return (
    <div className="overview-toolbar">
      <div className="overview-toolbar-left">
        <div className="overview-search">
          <SearchOutlined className="overview-search-icon" />
          <input
            type="text"
            className="overview-search-input"
            placeholder="Search devices by hostname, IP, OS..."
            value={searchText}
            onChange={(e) => onSearchChange(e.target.value)}
          />
        </div>
        <div className="overview-device-count">
          <span className="overview-device-count-number">{deviceCount}</span>
          <span className="overview-device-count-label">{deviceCount === 1 ? 'Device' : 'Devices'}</span>
        </div>
      </div>

      <div className="overview-toolbar-right">
        <div className="overview-view-toggle">
          <button
            className={`overview-view-button ${viewMode === 'grid' ? 'overview-view-button--active' : ''}`}
            onClick={() => onViewModeChange('grid')}
            title="Grid view"
          >
            <AppstoreOutlined />
          </button>
          <button
            className={`overview-view-button ${viewMode === 'list' ? 'overview-view-button--active' : ''}`}
            onClick={() => onViewModeChange('list')}
            title="List view"
          >
            <UnorderedListOutlined />
          </button>
        </div>

        <IconButton
          icon={<ReloadOutlined spin={loading} />}
          onClick={onRefresh}
          disabled={loading}
          tooltip="Refresh device list"
        />

        <button className="overview-generate-button" onClick={onGenerate}>
          <PlusOutlined />
          <span>Generate Client</span>
        </button>
      </div>
    </div>
  );
};

export default Toolbar;
