import { useState, useCallback } from 'react';
import { useCallback, useState } from 'react';
import { message } from 'antd';
import axios from 'axios';
import { request, translate, catchBlobReq, orderCompare } from '../../../../utils/utils';
import i18n from '../../../../locale/locale';

/**
 * useFileSystem - Hook for managing file system operations
 * @param {Object} device - The device to connect to
 */
export function useFileSystem(device) {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [path, setPath] = useState('/');
  const [history, setHistory] = useState(['/']);
  const [historyIndex, setHistoryIndex] = useState(0);
  const [freeSpace, setFreeSpace] = useState(0);

  const isWindows = device?.os?.toLowerCase().includes('windows');
  const separator = isWindows ? '\\' : '/';

  // Get parent path
  const getParentPath = useCallback((currentPath) => {
    if (!currentPath || currentPath === '/' || currentPath === '\\') {
      return '/';
    }
    // Handle Windows root (e.g., "C:\")
    if (isWindows && /^[A-Za-z]:[\\\/]?$/.test(currentPath)) {
      return '/';
    }
    const parts = currentPath.split(/[\/\\]/).filter(Boolean);
    if (parts.length <= 1) {
      return isWindows ? '/' : '/';
    }
    parts.pop();
    const parent = parts.join(separator);
    return isWindows ? parent + separator : '/' + parent;
  }, [isWindows, separator]);

  // Parse breadcrumbs from path
  const getBreadcrumbs = useCallback((currentPath) => {
    if (!currentPath || currentPath === '/') {
      return [{ name: 'Root', path: '/' }];
    }

    const crumbs = [{ name: 'Root', path: '/' }];
    const parts = currentPath.split(/[\/\\]/).filter(Boolean);

    let accumulated = isWindows ? '' : '/';
    parts.forEach((part) => {
      accumulated += (isWindows ? '' : '/') + part;
      if (isWindows) accumulated += separator;
      crumbs.push({ name: part, path: accumulated });
    });

    return crumbs;
  }, [isWindows, separator]);

  // List files in a directory
  const listFiles = useCallback(async (targetPath = '/') => {
    if (!device?.id) return;

    setLoading(true);
    setError(null);

    try {
      const response = await request(`/api/device/file/list`, {
        device: device.id,
        path: targetPath,
      });

      if (response.data?.code !== 0) {
        throw new Error(response.data?.msg || 'Failed to list files');
      }

      let fileList = response.data?.data?.files || [];

      // Sort files: folders first, then by name
      fileList.sort((a, b) => {
        if (a.type !== b.type) {
          return b.type - a.type; // Folders (1) before files (0)
        }
        return orderCompare(a.name, b.name);
      });

      // Add parent directory entry if not at root
      if (targetPath !== '/' && targetPath !== '\\') {
        fileList = [{ name: '..', type: 1, size: 0, time: 0 }, ...fileList];
      }

      setFiles(fileList);
      setPath(targetPath);
      setFreeSpace(response.data?.data?.freeSpace || 0);

      // Update history
      const newHistory = history.slice(0, historyIndex + 1);
      if (newHistory[newHistory.length - 1] !== targetPath) {
        newHistory.push(targetPath);
        setHistory(newHistory);
        setHistoryIndex(newHistory.length - 1);
      }
    } catch (err) {
      console.error('Failed to list files:', err);
      setError(err.message);
      message.error(translate(err.message) || i18n.t('COMMON.REQUEST_FAILED'));
    } finally {
      setLoading(false);
    }
  }, [device, history, historyIndex]);

  // Navigate to a path
  const navigate = useCallback((targetPath) => {
    listFiles(targetPath);
  }, [listFiles]);

  // Navigate back in history
  const goBack = useCallback(() => {
    if (historyIndex > 0) {
      const newIndex = historyIndex - 1;
      setHistoryIndex(newIndex);
      listFiles(history[newIndex]);
    }
  }, [history, historyIndex, listFiles]);

  // Navigate forward in history
  const goForward = useCallback(() => {
    if (historyIndex < history.length - 1) {
      const newIndex = historyIndex + 1;
      setHistoryIndex(newIndex);
      listFiles(history[newIndex]);
    }
  }, [history, historyIndex, listFiles]);

  // Navigate up to parent directory
  const goUp = useCallback(() => {
    const parentPath = getParentPath(path);
    listFiles(parentPath);
  }, [path, getParentPath, listFiles]);

  // Navigate to home/root
  const goHome = useCallback(() => {
    listFiles('/');
  }, [listFiles]);

  // Refresh current directory
  const refresh = useCallback(() => {
    listFiles(path);
  }, [path, listFiles]);

  // Download files
  const download = useCallback(async (fileNames) => {
    if (!device?.id) return;

    const names = Array.isArray(fileNames) ? fileNames : [fileNames];

    try {
      // Create form and submit
      const form = document.createElement('form');
      form.action = `/api/device/file/get`;
      form.method = 'POST';
      form.target = '_blank';

      // Add device ID
      const deviceInput = document.createElement('input');
      deviceInput.name = 'device';
      deviceInput.value = device.id;
      form.appendChild(deviceInput);

      // Add file paths
      names.forEach((name) => {
        const input = document.createElement('input');
        input.name = 'files';
        input.value = path + name;
        form.appendChild(input);
      });

      document.body.appendChild(form);
      form.submit();
      form.remove();
    } catch (err) {
      console.error('Download failed:', err);
      message.error(i18n.t('COMMON.REQUEST_FAILED'));
    }
  }, [device, path]);

  // Delete files
  const deleteFiles = useCallback(async (fileNames) => {
    if (!device?.id) return;

    const names = Array.isArray(fileNames) ? fileNames : [fileNames];

    try {
      const response = await request(`/api/device/file/remove`, {
        device: device.id,
        files: names.map((name) => path + name),
      });

      if (response.data?.code !== 0) {
        throw new Error(response.data?.msg || 'Failed to delete');
      }

      message.success(i18n.t('COMMON.SUCCESS'));
      refresh();
    } catch (err) {
      console.error('Delete failed:', err);
      message.error(translate(err.message) || i18n.t('COMMON.REQUEST_FAILED'));
    }
  }, [device, path, refresh]);

  // Create new folder
  const createFolder = useCallback(async (folderName) => {
    if (!device?.id) return;

    try {
      const response = await request(`/api/device/file/mkdir`, {
        device: device.id,
        path: path + folderName,
      });

      if (response.data?.code !== 0) {
        throw new Error(response.data?.msg || 'Failed to create folder');
      }

      message.success(i18n.t('COMMON.SUCCESS'));
      refresh();
    } catch (err) {
      console.error('Create folder failed:', err);
      message.error(translate(err.message) || i18n.t('COMMON.REQUEST_FAILED'));
    }
  }, [device, path, refresh]);

  // Rename file/folder
  const rename = useCallback(async (oldName, newName) => {
    if (!device?.id) return;

    try {
      const response = await request(`/api/device/file/move`, {
        device: device.id,
        src: path + oldName,
        dst: path + newName,
      });

      if (response.data?.code !== 0) {
        throw new Error(response.data?.msg || 'Failed to rename');
      }

      message.success(i18n.t('COMMON.SUCCESS'));
      refresh();
    } catch (err) {
      console.error('Rename failed:', err);
      message.error(translate(err.message) || i18n.t('COMMON.REQUEST_FAILED'));
    }
  }, [device, path, refresh]);

  const movePath = useCallback(async (src, dst) => {
    if (!device?.id) return;
    const response = await request(`/api/device/file/move`, {
      device: device.id,
      src,
      dst,
    });
    if (response.data?.code !== 0) {
      throw new Error(response.data?.msg || 'Failed to move');
    }
  }, [device]);

  const copyPath = useCallback(async (src, dst) => {
    if (!device?.id) return;
    const response = await request(`/api/device/file/copy`, {
      device: device.id,
      src,
      dst,
    });
    if (response.data?.code !== 0) {
      throw new Error(response.data?.msg || 'Failed to copy');
    }
  }, [device]);

  const uploadFiles = useCallback(async (fileList, targetPath = path) => {
    if (!device?.id) return;
    const list = Array.from(fileList || []);
    for (const f of list) {
      const name = f?.name ? String(f.name) : '';
      if (!name) continue;
      const url = `/api/device/file/upload?device=${encodeURIComponent(device.id)}&path=${encodeURIComponent(targetPath)}&file=${encodeURIComponent(name)}`;
      const res = await axios.post(url, f, {
        headers: {
          'Content-Type': f?.type || 'application/octet-stream',
        },
        maxBodyLength: Infinity,
      });
      if (res?.data?.code !== 0) {
        throw new Error(res?.data?.msg || `Upload failed: ${name}`);
      }
    }
  }, [device, path]);

  return {
    files,
    loading,
    error,
    path,
    freeSpace,
    isWindows,
    separator,
    breadcrumbs: getBreadcrumbs(path),
    canGoBack: historyIndex > 0,
    canGoForward: historyIndex < history.length - 1,
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
    movePath,
    copyPath,
    uploadFiles,
    listFiles,
    getParentPath,
  };
}

export default useFileSystem;
