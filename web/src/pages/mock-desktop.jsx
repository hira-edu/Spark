import React, { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import DesktopViewer from '../components/features/desktop/DesktopViewer';
import './mock-desktop.css';

const MockDesktopPage = () => {
  const [params] = useSearchParams();
  const deviceId = params.get('device') || 'mock-device';
  const hostname = params.get('name') || `Mock - ${deviceId}`;
  const allowControl = params.get('control') !== 'false';
  const shareToken = params.get('token') || null;
  const shareSecret = params.get('secret') || null;

  const device = useMemo(() => ({
    id: deviceId,
    hostname,
    owner: 'Mock',
  }), [deviceId, hostname]);

  return (
    <div className="mock-desktop-page">
      <DesktopViewer
        device={device}
        shareToken={shareToken}
        shareSecret={shareSecret}
        allowControl={allowControl}
        onClose={() => {}}
      />
    </div>
  );
};

export default MockDesktopPage;
