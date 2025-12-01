import React, { useEffect, useState } from 'react';
import { Image, message, Modal } from 'antd';
import { QuestionCircleOutlined } from '@ant-design/icons';
import { Toolbar, DeviceGrid } from './components';
import { useDeviceList } from './hooks';
import { request, catchBlobReq } from '../../../utils/utils';
import i18n from '../../../locale/locale';
import './Overview.css';

// Lazy load modals
let ComponentMap = {
  Generate: null,
  Explorer: null,
  Terminal: null,
  ProcMgr: null,
  Desktop: null,
  Execute: null,
  Share: null,
  Audio: null,
  Webcam: null,
};

/**
 * OverviewDashboard - Main dashboard component with modern design
 */
const OverviewDashboard = () => {
  const {
    devices,
    loading,
    searchText,
    setSearchText,
    viewMode,
    setViewMode,
    fetchDevices,
    stopAutoRefresh,
    startAutoRefresh,
  } = useDeviceList();

  const [execute, setExecute] = useState(false);
  const [desktop, setDesktop] = useState(false);
  const [procMgr, setProcMgr] = useState(false);
  const [explorer, setExplorer] = useState(false);
  const [generate, setGenerate] = useState(false);
  const [terminal, setTerminal] = useState(false);
  const [share, setShare] = useState(false);
  const [audio, setAudio] = useState(false);
  const [webcam, setWebcam] = useState(false);
  const [screenBlob, setScreenBlob] = useState('');

  // Load component dynamically
  const loadComponent = (component, callback) => {
    let element = null;
    component = component.toLowerCase();
    Object.keys(ComponentMap).forEach(k => {
      if (k.toLowerCase() === component.toLowerCase()) {
        element = k;
      }
    });
    if (!element) return;
    if (ComponentMap[element] === null) {
      import('../../../components/' + component + '/' + component).then((m) => {
        ComponentMap[element] = m.default;
        callback();
      });
    } else {
      callback();
    }
  };

  // Stop auto-refresh when any modal is open
  useEffect(() => {
    if (!execute && !desktop && !procMgr && !explorer && !generate && !terminal && !share && !audio && !webcam) {
      startAutoRefresh(3000);
    } else {
      stopAutoRefresh();
    }
  }, [execute, desktop, procMgr, explorer, generate, terminal, share, audio, webcam, startAutoRefresh, stopAutoRefresh]);

  // Handle device actions
  const handleDeviceAction = (action, device) => {
    const hooksMap = {
      terminal: setTerminal,
      explorer: setExplorer,
      generate: setGenerate,
      procmgr: setProcMgr,
      execute: setExecute,
      desktop: setDesktop,
      share: setShare,
      audio: setAudio,
      webcam: setWebcam,
    };

    if (hooksMap[action]) {
      loadComponent(action, () => {
        hooksMap[action](device);
      });
      return;
    }

    if (action === 'screenshot') {
      request('/api/device/screenshot/get', { device: device.id }, {}, {
        responseType: 'blob'
      }).then(res => {
        if ((res.data.type ?? '').substring(0, 5) === 'image') {
          if (screenBlob.length > 0) {
            URL.revokeObjectURL(screenBlob);
          }
          setScreenBlob(URL.createObjectURL(res.data));
        }
      }).catch(catchBlobReq);
      return;
    }

    // Confirm dangerous actions
    Modal.confirm({
      title: i18n.t('OVERVIEW.OPERATION_CONFIRM').replace('{0}', i18n.t('OVERVIEW.' + action.toUpperCase())),
      icon: <QuestionCircleOutlined />,
      onOk() {
        request('/api/device/' + action, { device: device.id }).then(res => {
          let data = res.data;
          if (data.code === 0) {
            message.success(i18n.t('OVERVIEW.OPERATION_SUCCESS'));
            fetchDevices();
          }
        });
      }
    });
  };

  const handleGenerate = () => {
    loadComponent('generate', () => {
      setGenerate(true);
    });
  };

  return (
    <div className="overview-dashboard">
      {/* Screenshot Preview */}
      <Image
        preview={{
          visible: !!screenBlob,
          src: screenBlob,
          onVisibleChange: () => {
            URL.revokeObjectURL(screenBlob);
            setScreenBlob('');
          }
        }}
      />

      {/* Modals */}
      {ComponentMap.Generate && (
        <ComponentMap.Generate
          visible={generate}
          onVisibleChange={setGenerate}
        />
      )}
      {ComponentMap.Execute && (
        <ComponentMap.Execute
          visible={execute}
          device={execute}
          onCancel={setExecute.bind(null, false)}
        />
      )}
      {ComponentMap.Explorer && (
        <ComponentMap.Explorer
          open={explorer}
          device={explorer}
          onCancel={setExplorer.bind(null, false)}
        />
      )}
      {ComponentMap.ProcMgr && (
        <ComponentMap.ProcMgr
          open={procMgr}
          device={procMgr}
          onCancel={setProcMgr.bind(null, false)}
        />
      )}
      {ComponentMap.Desktop && (
        <ComponentMap.Desktop
          open={desktop}
          device={desktop}
          onCancel={setDesktop.bind(null, false)}
        />
      )}
      {ComponentMap.Terminal && (
        <ComponentMap.Terminal
          open={terminal}
          device={terminal}
          onCancel={setTerminal.bind(null, false)}
        />
      )}
      {ComponentMap.Share && (
        <ComponentMap.Share
          open={!!share}
          onClose={() => setShare(false)}
          devices={devices}
        />
      )}
      {ComponentMap.Audio && (
        <ComponentMap.Audio
          open={audio}
          device={audio}
          onCancel={setAudio.bind(null, false)}
        />
      )}
      {ComponentMap.Webcam && (
        <ComponentMap.Webcam
          open={webcam}
          device={webcam}
          onCancel={setWebcam.bind(null, false)}
        />
      )}

      {/* Toolbar */}
      <Toolbar
        searchText={searchText}
        onSearchChange={setSearchText}
        viewMode={viewMode}
        onViewModeChange={setViewMode}
        onRefresh={fetchDevices}
        onGenerate={handleGenerate}
        loading={loading}
        deviceCount={devices.length}
      />

      {/* Device Grid */}
      <DeviceGrid
        devices={devices}
        loading={loading}
        viewMode={viewMode}
        onDeviceAction={handleDeviceAction}
      />
    </div>
  );
};

export default OverviewDashboard;
