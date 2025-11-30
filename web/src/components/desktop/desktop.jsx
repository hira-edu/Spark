import React from 'react';
import { Modal } from 'antd';
import { DesktopViewer } from '../features/desktop';
import i18n from '../../locale/locale';
import './desktop.modal.css';

const title = i18n.t('DESKTOP.TITLE');

/**
 * DesktopModal - Modal wrapper for the new DesktopViewer component
 * Maintains compatibility with the existing API
 */
function DesktopModal(props) {
  const { open, device, onCancel, shareToken, allowControl = true } = props;

  if (!open || !device) {
    return null;
  }

  return (
    <Modal
      title={`${title} - ${device.hostname || 'Unknown'}`}
      open={open}
      onCancel={onCancel}
      footer={null}
      width="90vw"
      style={{ top: 20 }}
      bodyStyle={{ padding: 0, height: 'calc(90vh - 55px)', overflow: 'hidden' }}
      destroyOnClose
      maskClosable={false}
      className="desktop-modal"
    >
      <div className="desktop-modal-content">
        <DesktopViewer
          device={device}
          shareToken={shareToken}
          allowControl={allowControl}
          onClose={onCancel}
        />
      </div>
    </Modal>
  );
}

export default DesktopModal;
