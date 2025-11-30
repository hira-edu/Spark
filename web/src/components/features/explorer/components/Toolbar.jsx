import React from 'react';
import { Input, Tooltip, Dropdown, Menu } from 'antd';
import {
  ArrowLeftOutlined,
  ArrowRightOutlined,
  ArrowUpOutlined,
  ReloadOutlined,
  HomeOutlined,
  AppstoreOutlined,
  UnorderedListOutlined,
  UploadOutlined,
  FolderAddOutlined,
  SortAscendingOutlined,
  SearchOutlined,
} from '@ant-design/icons';
import { IconButton } from '../../../shared';
import './Explorer.css';

const SORT_OPTIONS = [
  { key: 'name', label: 'Name' },
  { key: 'size', label: 'Size' },
  { key: 'time', label: 'Date Modified' },
  { key: 'type', label: 'Type' },
];

/**
 * Toolbar - File explorer toolbar with navigation, search, and view controls
 */
const Toolbar = ({
  path,
  breadcrumbs,
  onNavigate,
  onBack,
  onForward,
  onUp,
  onHome,
  onRefresh,
  canGoBack,
  canGoForward,
  viewMode,
  onViewModeChange,
  sortBy,
  onSortChange,
  searchQuery,
  onSearchChange,
  onUpload,
  onNewFolder,
}) => {
  const sortMenu = (
    <Menu
      selectedKeys={[sortBy]}
      onClick={({ key }) => onSortChange(key)}
    >
      {SORT_OPTIONS.map((opt) => (
        <Menu.Item key={opt.key}>{opt.label}</Menu.Item>
      ))}
    </Menu>
  );

  return (
    <div className="explorer-toolbar">
      <div className="explorer-toolbar-left">
        {/* Navigation buttons */}
        <div className="explorer-nav-buttons">
          <IconButton
            icon={<ArrowLeftOutlined />}
            tooltip="Back"
            onClick={onBack}
            disabled={!canGoBack}
            size="sm"
          />
          <IconButton
            icon={<ArrowRightOutlined />}
            tooltip="Forward"
            onClick={onForward}
            disabled={!canGoForward}
            size="sm"
          />
          <IconButton
            icon={<ArrowUpOutlined />}
            tooltip="Up"
            onClick={onUp}
            size="sm"
          />
          <IconButton
            icon={<HomeOutlined />}
            tooltip="Home"
            onClick={onHome}
            size="sm"
          />
          <IconButton
            icon={<ReloadOutlined />}
            tooltip="Refresh"
            onClick={onRefresh}
            size="sm"
          />
        </div>

        {/* Breadcrumb */}
        <div className="explorer-breadcrumb">
          {breadcrumbs.map((crumb, index) => (
            <React.Fragment key={index}>
              {index > 0 && <span className="explorer-breadcrumb-separator">/</span>}
              <button
                className="explorer-breadcrumb-item"
                onClick={() => onNavigate(crumb.path)}
              >
                {crumb.name}
              </button>
            </React.Fragment>
          ))}
        </div>
      </div>

      <div className="explorer-toolbar-right">
        {/* Search */}
        <Input
          className="explorer-search"
          placeholder="Search files..."
          prefix={<SearchOutlined />}
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          allowClear
          size="small"
        />

        <div className="explorer-toolbar-divider" />

        {/* View mode toggle */}
        <div className="explorer-view-toggle">
          <IconButton
            icon={<AppstoreOutlined />}
            tooltip="Grid view"
            onClick={() => onViewModeChange('grid')}
            active={viewMode === 'grid'}
            size="sm"
          />
          <IconButton
            icon={<UnorderedListOutlined />}
            tooltip="List view"
            onClick={() => onViewModeChange('list')}
            active={viewMode === 'list'}
            size="sm"
          />
        </div>

        {/* Sort dropdown */}
        <Dropdown overlay={sortMenu} trigger={['click']}>
          <IconButton
            icon={<SortAscendingOutlined />}
            tooltip="Sort by"
            size="sm"
          />
        </Dropdown>

        <div className="explorer-toolbar-divider" />

        {/* Actions */}
        <IconButton
          icon={<FolderAddOutlined />}
          tooltip="New folder"
          onClick={onNewFolder}
          size="sm"
        />
        <IconButton
          icon={<UploadOutlined />}
          tooltip="Upload files"
          onClick={onUpload}
          size="sm"
        />
      </div>
    </div>
  );
};

export default Toolbar;
