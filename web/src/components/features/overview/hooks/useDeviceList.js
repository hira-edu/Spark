import { useState, useEffect, useCallback, useRef } from 'react';
import { request } from '../../../../utils/utils';
import { message } from 'antd';

/**
 * useDeviceList - Hook to manage device list fetching and operations
 */
const VIEW_MODE_KEY = 'overviewViewMode';

const getInitialViewMode = () => {
  if (typeof window === 'undefined') return 'list';
  const saved = window.localStorage.getItem(VIEW_MODE_KEY);
  return saved === 'grid' || saved === 'list' ? saved : 'list';
};

const useDeviceList = () => {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchText, setSearchText] = useState('');
  const [viewMode, setViewMode] = useState(getInitialViewMode); // 'grid' or 'list' (default list)
  const [sortBy, setSortBy] = useState('hostname');
  const refreshIntervalRef = useRef(null);

  // Persist view mode so user choice sticks across sessions
  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(VIEW_MODE_KEY, viewMode);
  }, [viewMode]);

  // Fetch device list
  const fetchDevices = useCallback(async () => {
    setLoading(true);
    try {
      const res = await request('/api/device/list');
      const data = res.data;

      if (data.code === 0) {
        let result = [];
        for (const uuid in data.data) {
          let temp = data.data[uuid];
          temp.conn = uuid;
          result.push(temp);
        }

        // Expand nested objects
        for (let i = 0; i < result.length; i++) {
          for (const k in result[i]) {
            if (typeof result[i][k] === 'object' && result[i][k] !== null) {
              for (const key in result[i][k]) {
                result[i][k + '_' + key] = result[i][k][key];
              }
            }
          }
        }

        // Sort devices
        result = result.sort((first, second) => {
          let firstEl = (first[sortBy] || '').toString().toUpperCase();
          let secondEl = (second[sortBy] || '').toString().toUpperCase();
          if (firstEl < secondEl) return -1;
          if (firstEl > secondEl) return 1;
          return 0;
        });

        setDevices(result);
      }
    } catch (error) {
      console.error('Failed to fetch devices:', error);
      message.error('Failed to fetch device list');
    } finally {
      setLoading(false);
    }
  }, [sortBy]);

  // Filter devices based on search text
  const getFilteredDevices = useCallback(() => {
    if (!searchText) return devices;

    const lowerSearch = searchText.toLowerCase();
    return devices.filter(device => {
      return (
        device.hostname?.toLowerCase().includes(lowerSearch) ||
        device.username?.toLowerCase().includes(lowerSearch) ||
        device.os?.toLowerCase().includes(lowerSearch) ||
        device.lan?.includes(lowerSearch) ||
        device.wan?.includes(lowerSearch)
      );
    });
  }, [devices, searchText]);

  // Auto-refresh
  const startAutoRefresh = useCallback((interval = 3000) => {
    stopAutoRefresh();
    refreshIntervalRef.current = setInterval(() => {
      fetchDevices();
    }, interval);
  }, [fetchDevices]);

  const stopAutoRefresh = useCallback(() => {
    if (refreshIntervalRef.current) {
      clearInterval(refreshIntervalRef.current);
      refreshIntervalRef.current = null;
    }
  }, []);

  // Initial fetch and cleanup
  useEffect(() => {
    fetchDevices();
    startAutoRefresh(3000);

    return () => {
      stopAutoRefresh();
    };
  }, [fetchDevices, startAutoRefresh, stopAutoRefresh]);

  return {
    devices: getFilteredDevices(),
    allDevices: devices,
    loading,
    searchText,
    setSearchText,
    viewMode,
    setViewMode,
    sortBy,
    setSortBy,
    fetchDevices,
    startAutoRefresh,
    stopAutoRefresh,
  };
};

export default useDeviceList;
