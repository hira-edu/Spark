import React, { useEffect, useRef } from 'react';
import {
  DownloadOutlined,
  DeleteOutlined,
  EditOutlined,
  CopyOutlined,
  ScissorOutlined,
  FileAddOutlined,
  FolderAddOutlined,
  PlayCircleOutlined,
  EyeOutlined,
} from '@ant-design/icons';
import './Explorer.css';

/**
 * ContextMenu - Right-click context menu for file operations
 */
const ContextMenu = ({
  visible,
  x,
  y,
  file,
  selectedCount,
  onClose,
  onDownload,
  onDelete,
  onRename,
  onCopy,
  onCut,
  onPaste,
  onNewFile,
  onNewFolder,
  onExecute,
  onPreview,
  canPaste,
}) => {
  const menuRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        onClose();
      }
    };

    const handleEscape = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    if (visible) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleEscape);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [visible, onClose]);

  if (!visible) return null;

  const isFile = file?.type === 0;
  const isFolder = file?.type === 1;
  const isDisk = file?.type === 2;
  const isMultiple = selectedCount > 1;
  const isParent = file?.name === '..';

  // Adjust position to keep menu in viewport
  const adjustedX = Math.min(x, window.innerWidth - 200);
  const adjustedY = Math.min(y, window.innerHeight - 300);

  return (
    <div
      ref={menuRef}
      className="context-menu"
      style={{ left: adjustedX, top: adjustedY }}
    >
      {/* File-specific actions */}
      {isFile && !isMultiple && !isParent && (
        <>
          <button className="context-menu-item" onClick={onPreview}>
            <EyeOutlined />
            <span>Preview</span>
          </button>
          <button className="context-menu-item" onClick={onExecute}>
            <PlayCircleOutlined />
            <span>Execute</span>
          </button>
          <div className="context-menu-divider" />
        </>
      )}

      {/* Download */}
      {!isDisk && !isParent && (
        <button className="context-menu-item" onClick={onDownload}>
          <DownloadOutlined />
          <span>Download{isMultiple ? ` (${selectedCount})` : ''}</span>
        </button>
      )}

      {/* Rename - only for single selection */}
      {!isMultiple && !isDisk && !isParent && (
        <button className="context-menu-item" onClick={onRename}>
          <EditOutlined />
          <span>Rename</span>
        </button>
      )}

      {/* Copy/Cut */}
      {!isDisk && !isParent && (
        <>
          <button className="context-menu-item" onClick={onCopy}>
            <CopyOutlined />
            <span>Copy</span>
          </button>
          <button className="context-menu-item" onClick={onCut}>
            <ScissorOutlined />
            <span>Cut</span>
          </button>
        </>
      )}

      {/* Paste - show if we have items in clipboard */}
      {canPaste && (
        <button className="context-menu-item" onClick={onPaste}>
          <CopyOutlined />
          <span>Paste</span>
        </button>
      )}

      <div className="context-menu-divider" />

      {/* Create new */}
      {!file && (
        <>
          <button className="context-menu-item" onClick={onNewFile}>
            <FileAddOutlined />
            <span>New File</span>
          </button>
          <button className="context-menu-item" onClick={onNewFolder}>
            <FolderAddOutlined />
            <span>New Folder</span>
          </button>
          <div className="context-menu-divider" />
        </>
      )}

      {/* Delete */}
      {!isDisk && !isParent && (
        <button className="context-menu-item context-menu-item--danger" onClick={onDelete}>
          <DeleteOutlined />
          <span>Delete{isMultiple ? ` (${selectedCount})` : ''}</span>
        </button>
      )}
    </div>
  );
};

export default ContextMenu;
