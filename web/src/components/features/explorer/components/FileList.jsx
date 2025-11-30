import React from 'react';
import FileIcon from './FileIcon';
import { formatSize } from '../../../../utils/utils';
import dayjs from 'dayjs';
import './Explorer.css';

/**
 * FileList - List view for files with sortable columns
 */
const FileList = ({
  files,
  selectedIds,
  onSelect,
  onOpen,
  onContextMenu,
  sortBy,
  sortOrder,
  onSort,
}) => {
  const handleClick = (e, file) => {
    e.stopPropagation();

    if (e.ctrlKey || e.metaKey) {
      // Toggle selection
      if (selectedIds.includes(file.name)) {
        onSelect(selectedIds.filter((id) => id !== file.name));
      } else {
        onSelect([...selectedIds, file.name]);
      }
    } else if (e.shiftKey && selectedIds.length > 0) {
      // Range selection
      const fileNames = files.map((f) => f.name);
      const lastSelected = selectedIds[selectedIds.length - 1];
      const lastIndex = fileNames.indexOf(lastSelected);
      const currentIndex = fileNames.indexOf(file.name);
      const start = Math.min(lastIndex, currentIndex);
      const end = Math.max(lastIndex, currentIndex);
      const rangeSelection = fileNames.slice(start, end + 1);
      onSelect([...new Set([...selectedIds, ...rangeSelection])]);
    } else {
      // Single selection
      onSelect([file.name]);
    }
  };

  const handleDoubleClick = (e, file) => {
    e.stopPropagation();
    onOpen(file);
  };

  const handleContextMenu = (e, file) => {
    e.preventDefault();
    e.stopPropagation();
    if (!selectedIds.includes(file.name)) {
      onSelect([file.name]);
    }
    onContextMenu(e, file);
  };

  const handleHeaderClick = (column) => {
    if (sortBy === column) {
      onSort(column, sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      onSort(column, 'asc');
    }
  };

  const getSortIndicator = (column) => {
    if (sortBy !== column) return null;
    return sortOrder === 'asc' ? ' ↑' : ' ↓';
  };

  return (
    <div
      className="file-list"
      onClick={() => onSelect([])}
    >
      {/* Header */}
      <div className="file-list-header">
        <div
          className="file-list-col file-list-col--name"
          onClick={() => handleHeaderClick('name')}
        >
          Name{getSortIndicator('name')}
        </div>
        <div
          className="file-list-col file-list-col--size"
          onClick={() => handleHeaderClick('size')}
        >
          Size{getSortIndicator('size')}
        </div>
        <div
          className="file-list-col file-list-col--modified"
          onClick={() => handleHeaderClick('time')}
        >
          Modified{getSortIndicator('time')}
        </div>
      </div>

      {/* Rows */}
      <div className="file-list-body">
        {files.map((file) => (
          <div
            key={file.name}
            className={`file-list-row ${selectedIds.includes(file.name) ? 'file-list-row--selected' : ''}`}
            onClick={(e) => handleClick(e, file)}
            onDoubleClick={(e) => handleDoubleClick(e, file)}
            onContextMenu={(e) => handleContextMenu(e, file)}
          >
            <div className="file-list-col file-list-col--name">
              <FileIcon file={file} size="sm" />
              <span className="file-list-name" title={file.name}>
                {file.name}
              </span>
            </div>
            <div className="file-list-col file-list-col--size">
              {file.type === 0 ? formatSize(file.size) : '--'}
            </div>
            <div className="file-list-col file-list-col--modified">
              {file.type === 0 && file.time
                ? dayjs.unix(file.time).format('YYYY-MM-DD HH:mm')
                : '--'}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default FileList;
