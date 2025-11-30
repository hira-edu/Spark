import React from 'react';
import FileIcon from './FileIcon';
import { formatSize } from '../../../../utils/utils';
import './Explorer.css';

/**
 * FileGrid - Grid view for files
 */
const FileGrid = ({
  files,
  selectedIds,
  onSelect,
  onOpen,
  onContextMenu,
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

  return (
    <div
      className="file-grid"
      onClick={() => onSelect([])}
    >
      {files.map((file) => (
        <div
          key={file.name}
          className={`file-grid-item ${selectedIds.includes(file.name) ? 'file-grid-item--selected' : ''}`}
          onClick={(e) => handleClick(e, file)}
          onDoubleClick={(e) => handleDoubleClick(e, file)}
          onContextMenu={(e) => handleContextMenu(e, file)}
        >
          <FileIcon file={file} size="lg" />
          <div className="file-grid-item-name" title={file.name}>
            {file.name}
          </div>
          {file.type === 0 && (
            <div className="file-grid-item-size">
              {formatSize(file.size)}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default FileGrid;
