import React from 'react';
import { Modal } from 'antd';
import { DesktopViewer } from '../features/desktop';
import './desktop.modal.css';

/**
 * DesktopModal - Modal wrapper for the new DesktopViewer component
 * Maintains compatibility with the existing API
 */
function DesktopModal(props) {
  const { open, device, onCancel, shareToken, shareSecret, allowControl = true } = props;

  if (!open || !device) {
    return null;
  }

  return (
    <Modal
      open={open}
      onCancel={onCancel}
      footer={null}
      width="90vw"
      style={{ top: 20 }}
      bodyStyle={{ padding: 0, height: '90vh', overflow: 'hidden' }}
      destroyOnClose
      maskClosable={false}
      className="desktop-modal"
      closable={false}
      focusTriggerAfterClose={false}
    >
      <div className="desktop-modal-content">
        <DesktopViewer
          device={device}
          shareToken={shareToken}
          shareSecret={shareSecret}
          allowControl={allowControl}
          onClose={onCancel}
        />
      </div>
    </Modal>
  );
}

export default DesktopModal;
