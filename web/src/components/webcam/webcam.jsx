import React from 'react';
import { Modal } from 'antd';
import { WebcamPanel } from '../features/webcam';
import './webcam.modal.css';

/**
 * WebcamModal - Modal wrapper for the WebcamPanel component
 * Maintains compatibility with the existing API
 */
function WebcamModal(props) {
  const { open, device, onCancel } = props;

  if (!open || !device) {
    return null;
  }

  return (
    <Modal
      open={open}
      onCancel={onCancel}
      footer={null}
      width="85vw"
      style={{ top: 30 }}
      bodyStyle={{ padding: 0, height: '85vh', overflow: 'hidden' }}
      destroyOnClose
      maskClosable={false}
      className="webcam-modal"
      closable={false}
      focusTriggerAfterClose={false}
    >
      <div className="webcam-modal-content">
        <WebcamPanel
          device={device}
          onClose={onCancel}
        />
      </div>
    </Modal>
  );
}

export default WebcamModal;
