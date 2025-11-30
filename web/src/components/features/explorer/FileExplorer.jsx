import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { Modal, Input, message } from 'antd';
import { Toolbar, FileGrid, FileList, ContextMenu, StatusBar } from './components';
import { useFileSystem } from './hooks';
import i18n from '../../../locale/locale';
import './FileExplorer.css';

/**
 * FileExplorer - Main file explorer component
 */
const FileExplorer = ({
  device,
  onClose,
}) => {
  // File system hook
  const {
    files,
    loading,
    path,
    freeSpace,
    isWindows,
    separator,
    breadcrumbs,
    canGoBack,
    canGoForward,
    navigate,
    goBack,
    goForward,
    goUp,
    goHome,
    refresh,
    download,
    deleteFiles,
    createFolder,
    rename,
    listFiles,
  } = useFileSystem(device);

  // State
  const [viewMode, setViewMode] = useState('grid');
  const [sortBy, setSortBy] = useState('name');
  const [sortOrder, setSortOrder] = useState('asc');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIds, setSelectedIds] = useState([]);
  const [contextMenu, setContextMenu] = useState({ visible: false, x: 0, y: 0, file: null });
  const [newFolderModal, setNewFolderModal] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [renameModal, setRenameModal] = useState({ visible: false, file: null, name: '' });
  const [clipboard, setClipboard] = useState({ files: [], operation: null });

  // Load files on mount and device change
  useEffect(() => {
    if (device?.id) {
      listFiles('/');
    }
  }, [device?.id]);

  // Filter and sort files
  const displayFiles = useMemo(() => {
    let result = [...files];

    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter((file) =>
        file.name.toLowerCase().includes(query)
      );
    }

    // Sort files (keep parent directory ".." at top)
    result.sort((a, b) => {
      if (a.name === '..') return -1;
      if (b.name === '..') return 1;

      // Folders before files
      if (a.type !== b.type) {
        return b.type - a.type;
      }

      // Sort by selected field
      let comparison = 0;
      switch (sortBy) {
        case 'name':
          comparison = a.name.localeCompare(b.name);
          break;
        case 'size':
          comparison = (a.size || 0) - (b.size || 0);
          break;
        case 'time':
          comparison = (a.time || 0) - (b.time || 0);
          break;
        case 'type':
          const extA = a.name.split('.').pop() || '';
          const extB = b.name.split('.').pop() || '';
          comparison = extA.localeCompare(extB);
          break;
        default:
          break;
      }

      return sortOrder === 'desc' ? -comparison : comparison;
    });

    return result;
  }, [files, searchQuery, sortBy, sortOrder]);

  // Calculate selection stats
  const selectionStats = useMemo(() => {
    const selectedFiles = files.filter((f) => selectedIds.includes(f.name));
    return {
      count: selectedFiles.length,
      size: selectedFiles.reduce((sum, f) => sum + (f.size || 0), 0),
    };
  }, [files, selectedIds]);

  // Count files and folders
  const fileCounts = useMemo(() => {
    const regularFiles = files.filter((f) => f.type === 0 && f.name !== '..');
    const folders = files.filter((f) => f.type === 1 && f.name !== '..');
    return {
      files: regularFiles.length,
      folders: folders.length,
    };
  }, [files]);

  // Handle file open (double-click)
  const handleOpen = useCallback((file) => {
    if (file.name === '..') {
      goUp();
      return;
    }

    if (file.type === 1 || file.type === 2) {
      // Folder or disk
      const newPath = path === '/' || path === '\\'
        ? file.name + separator
        : path + file.name + separator;
      navigate(newPath);
      return;
    }

    // File - download it
    download(file.name);
  }, [path, separator, navigate, goUp, download]);

  // Handle context menu
  const handleContextMenu = useCallback((e, file) => {
    setContextMenu({
      visible: true,
      x: e.clientX,
      y: e.clientY,
      file,
    });
  }, []);

  // Close context menu
  const closeContextMenu = useCallback(() => {
    setContextMenu({ visible: false, x: 0, y: 0, file: null });
  }, []);

  // Handle download
  const handleDownload = useCallback(() => {
    closeContextMenu();
    download(selectedIds);
  }, [selectedIds, download, closeContextMenu]);

  // Handle delete
  const handleDelete = useCallback(() => {
    closeContextMenu();
    Modal.confirm({
      title: i18n.t('EXPLORER.DELETE_CONFIRM').replace('{0}', selectedIds.length > 1 ? 'items' : 'item'),
      onOk: () => {
        deleteFiles(selectedIds);
        setSelectedIds([]);
      },
    });
  }, [selectedIds, deleteFiles, closeContextMenu]);

  // Handle rename
  const handleRename = useCallback(() => {
    closeContextMenu();
    const file = files.find((f) => f.name === selectedIds[0]);
    if (file) {
      setRenameModal({ visible: true, file, name: file.name });
    }
  }, [selectedIds, files, closeContextMenu]);

  // Submit rename
  const submitRename = useCallback(() => {
    if (renameModal.name && renameModal.name !== renameModal.file.name) {
      rename(renameModal.file.name, renameModal.name);
    }
    setRenameModal({ visible: false, file: null, name: '' });
  }, [renameModal, rename]);

  // Handle copy
  const handleCopy = useCallback(() => {
    closeContextMenu();
    setClipboard({
      files: selectedIds.map((name) => path + name),
      operation: 'copy',
    });
    message.success('Copied to clipboard');
  }, [selectedIds, path, closeContextMenu]);

  // Handle cut
  const handleCut = useCallback(() => {
    closeContextMenu();
    setClipboard({
      files: selectedIds.map((name) => path + name),
      operation: 'cut',
    });
    message.success('Cut to clipboard');
  }, [selectedIds, path, closeContextMenu]);

  // Handle paste
  const handlePaste = useCallback(() => {
    closeContextMenu();
    // TODO: Implement paste functionality
    message.info('Paste not yet implemented');
  }, [closeContextMenu]);

  // Handle new folder
  const handleNewFolder = useCallback(() => {
    setNewFolderModal(true);
    setNewFolderName('New Folder');
  }, []);

  // Submit new folder
  const submitNewFolder = useCallback(() => {
    if (newFolderName) {
      createFolder(newFolderName);
    }
    setNewFolderModal(false);
    setNewFolderName('');
  }, [newFolderName, createFolder]);

  // Handle upload
  const handleUpload = useCallback(() => {
    // Create file input
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.onchange = (e) => {
      const files = e.target.files;
      if (files.length > 0) {
        // TODO: Implement file upload
        message.info(`Uploading ${files.length} file(s)...`);
      }
    };
    input.click();
  }, []);

  // Handle sort change
  const handleSortChange = useCallback((field) => {
    if (sortBy === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortOrder('asc');
    }
  }, [sortBy]);

  // Handle sort from list view
  const handleListSort = useCallback((field, order) => {
    setSortBy(field);
    setSortOrder(order);
  }, []);

  return (
    <div className="file-explorer">
      {/* Toolbar */}
      <Toolbar
        path={path}
        breadcrumbs={breadcrumbs}
        onNavigate={navigate}
        onBack={goBack}
        onForward={goForward}
        onUp={goUp}
        onHome={goHome}
        onRefresh={refresh}
        canGoBack={canGoBack}
        canGoForward={canGoForward}
        viewMode={viewMode}
        onViewModeChange={setViewMode}
        sortBy={sortBy}
        onSortChange={handleSortChange}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        onUpload={handleUpload}
        onNewFolder={handleNewFolder}
      />

      {/* File Content */}
      <div className="file-explorer-content">
        {viewMode === 'grid' ? (
          <FileGrid
            files={displayFiles}
            selectedIds={selectedIds}
            onSelect={setSelectedIds}
            onOpen={handleOpen}
            onContextMenu={handleContextMenu}
          />
        ) : (
          <FileList
            files={displayFiles}
            selectedIds={selectedIds}
            onSelect={setSelectedIds}
            onOpen={handleOpen}
            onContextMenu={handleContextMenu}
            sortBy={sortBy}
            sortOrder={sortOrder}
            onSort={handleListSort}
          />
        )}
      </div>

      {/* Status Bar */}
      <StatusBar
        totalFiles={fileCounts.files}
        totalFolders={fileCounts.folders}
        selectedCount={selectionStats.count}
        selectedSize={selectionStats.size}
        freeSpace={freeSpace}
        loading={loading}
      />

      {/* Context Menu */}
      <ContextMenu
        visible={contextMenu.visible}
        x={contextMenu.x}
        y={contextMenu.y}
        file={contextMenu.file}
        selectedCount={selectedIds.length}
        onClose={closeContextMenu}
        onDownload={handleDownload}
        onDelete={handleDelete}
        onRename={handleRename}
        onCopy={handleCopy}
        onCut={handleCut}
        onPaste={handlePaste}
        onNewFolder={handleNewFolder}
        canPaste={clipboard.files.length > 0}
      />

      {/* New Folder Modal */}
      <Modal
        title={i18n.t('EXPLORER.NEW_FOLDER')}
        open={newFolderModal}
        onOk={submitNewFolder}
        onCancel={() => setNewFolderModal(false)}
      >
        <Input
          value={newFolderName}
          onChange={(e) => setNewFolderName(e.target.value)}
          onPressEnter={submitNewFolder}
          autoFocus
        />
      </Modal>

      {/* Rename Modal */}
      <Modal
        title={i18n.t('EXPLORER.RENAME')}
        open={renameModal.visible}
        onOk={submitRename}
        onCancel={() => setRenameModal({ visible: false, file: null, name: '' })}
      >
        <Input
          value={renameModal.name}
          onChange={(e) => setRenameModal((prev) => ({ ...prev, name: e.target.value }))}
          onPressEnter={submitRename}
          autoFocus
        />
      </Modal>
    </div>
  );
};

export default FileExplorer;
