import { useState, useEffect, useCallback, useRef } from 'react';
import { request } from '../../../../utils/utils';
import { message } from 'antd';
import i18n from '../../../../locale/locale';

/**
 * useProcessList - Hook to manage process list fetching and operations
 */
const useProcessList = (device) => {
  const [processes, setProcesses] = useState([]);
  const [loading, setLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [sortBy, setSortBy] = useState('pid');
  const [sortOrder, setSortOrder] = useState('desc');
  const [filterText, setFilterText] = useState('');
  const refreshIntervalRef = useRef(null);

  // Fetch process list
  const fetchProcesses = useCallback(async () => {
    if (!device?.id) return;

    setLoading(true);
    try {
      const res = await request('/api/device/process/list', { device: device.id });
      const data = res.data;

      if (data.code === 0 && data.data?.processes) {
        setProcesses(data.data.processes);
        setLastUpdate(Date.now());
      } else {
        message.error(i18n.t('PROCMGR.FETCH_FAILED'));
        setProcesses([]);
      }
    } catch (error) {
      message.error(i18n.t('PROCMGR.FETCH_ERROR'));
      setProcesses([]);
    } finally {
      setLoading(false);
    }
  }, [device?.id]);

  // Kill process
  const killProcess = useCallback(async (pid, processName) => {
    if (!device?.id) return false;

    try {
      const res = await request('/api/device/process/kill', {
        pid: pid,
        device: device.id,
      });
      const data = res.data;

      if (data.code === 0) {
        message.success(i18n.t('PROCMGR.KILL_PROCESS_SUCCESSFULLY'));
        // Refresh process list after killing
        fetchProcesses();
        return true;
      } else {
        message.error(data.msg || i18n.t('PROCMGR.KILL_PROCESS_FAILED'));
        return false;
      }
    } catch (error) {
      message.error(i18n.t('PROCMGR.KILL_PROCESS_ERROR'));
      return false;
    }
  }, [device?.id, fetchProcesses]);

  // Sort processes
  const getSortedProcesses = useCallback(() => {
    let sorted = [...processes];

    // Apply filter
    if (filterText) {
      const lowerFilter = filterText.toLowerCase();
      sorted = sorted.filter(
        (proc) =>
          proc.name?.toLowerCase().includes(lowerFilter) ||
          String(proc.pid).includes(lowerFilter)
      );
    }

    // Apply sort
    sorted.sort((a, b) => {
      let aVal = a[sortBy];
      let bVal = b[sortBy];

      // Handle string comparison
      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = bVal?.toLowerCase() || '';
      }

      if (sortOrder === 'asc') {
        return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
      } else {
        return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
      }
    });

    return sorted;
  }, [processes, sortBy, sortOrder, filterText]);

  // Toggle sort
  const toggleSort = useCallback((field) => {
    setSortBy((prev) => {
      if (prev === field) {
        setSortOrder((order) => (order === 'asc' ? 'desc' : 'asc'));
        return prev;
      } else {
        setSortOrder('desc');
        return field;
      }
    });
  }, []);

  // Auto-refresh
  const startAutoRefresh = useCallback((interval = 5000) => {
    stopAutoRefresh();
    refreshIntervalRef.current = setInterval(() => {
      fetchProcesses();
    }, interval);
  }, [fetchProcesses]);

  const stopAutoRefresh = useCallback(() => {
    if (refreshIntervalRef.current) {
      clearInterval(refreshIntervalRef.current);
      refreshIntervalRef.current = null;
    }
  }, []);

  // Initial fetch and cleanup
  useEffect(() => {
    if (device?.id) {
      fetchProcesses();
      startAutoRefresh(5000); // Refresh every 5 seconds
    }

    return () => {
      stopAutoRefresh();
    };
  }, [device?.id, fetchProcesses, startAutoRefresh, stopAutoRefresh]);

  return {
    processes: getSortedProcesses(),
    loading,
    lastUpdate,
    sortBy,
    sortOrder,
    filterText,
    setFilterText,
    fetchProcesses,
    killProcess,
    toggleSort,
    startAutoRefresh,
    stopAutoRefresh,
  };
};

export default useProcessList;
