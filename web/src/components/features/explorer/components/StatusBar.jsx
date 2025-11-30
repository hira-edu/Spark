import React from 'react';
import { formatSize } from '../../../../utils/utils';
import './Explorer.css';

/**
 * StatusBar - Bottom status bar showing file count and selection info
 */
const StatusBar = ({
  totalFiles,
  totalFolders,
  selectedCount,
  selectedSize,
  freeSpace,
  loading,
}) => {
  const getTotalText = () => {
    const parts = [];
    if (totalFolders > 0) {
      parts.push(`${totalFolders} folder${totalFolders !== 1 ? 's' : ''}`);
    }
    if (totalFiles > 0) {
      parts.push(`${totalFiles} file${totalFiles !== 1 ? 's' : ''}`);
    }
    return parts.join(', ') || 'Empty folder';
  };

  const getSelectionText = () => {
    if (selectedCount === 0) return null;
    return `${selectedCount} selected (${formatSize(selectedSize)})`;
  };

  return (
    <div className="explorer-statusbar">
      <div className="explorer-statusbar-left">
        {loading ? (
          <span className="explorer-statusbar-loading">Loading...</span>
        ) : (
          <span className="explorer-statusbar-count">{getTotalText()}</span>
        )}
      </div>

      <div className="explorer-statusbar-center">
        {getSelectionText() && (
          <span className="explorer-statusbar-selection">
            {getSelectionText()}
          </span>
        )}
      </div>

      <div className="explorer-statusbar-right">
        {freeSpace > 0 && (
          <span className="explorer-statusbar-space">
            {formatSize(freeSpace)} free
          </span>
        )}
      </div>
    </div>
  );
};

export default StatusBar;
