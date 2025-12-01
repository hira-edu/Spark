import React from 'react';
import { Header, Toolbar, ProcessTable } from './components';
import { useProcessList } from './hooks';
import './ProcessManager.css';

/**
 * ProcessManager - Main component for process management with modern UI
 */
const ProcessManager = ({ device, onClose }) => {
  const {
    processes,
    loading,
    lastUpdate,
    sortBy,
    sortOrder,
    filterText,
    setFilterText,
    fetchProcesses,
    killProcess,
    toggleSort,
  } = useProcessList(device);

  if (!device) {
    return null;
  }

  return (
    <div className="procmgr-panel">
      {/* Toolbar */}
      <Toolbar
        filterText={filterText}
        onFilterChange={setFilterText}
        onRefresh={fetchProcesses}
        onClose={onClose}
        loading={loading}
      />

      {/* Header */}
      <Header
        device={device}
        processCount={processes.length}
        lastUpdate={lastUpdate}
      />

      {/* Process Table */}
      <ProcessTable
        processes={processes}
        loading={loading}
        onKillProcess={killProcess}
        sortBy={sortBy}
        sortOrder={sortOrder}
        onSort={toggleSort}
      />
    </div>
  );
};

export default ProcessManager;
