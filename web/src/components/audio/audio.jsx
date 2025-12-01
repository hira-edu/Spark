import React from 'react';
import { Modal } from 'antd';
import { AudioPanel } from '../features/audio';
import './audio.modal.css';

/**
 * AudioModal - Modal wrapper for the AudioPanel component
 * Maintains compatibility with the existing API
 */
function AudioModal(props) {
  const { open, device, onCancel } = props;

  if (!open || !device) {
    return null;
  }

  return (
    <Modal
      open={open}
      onCancel={onCancel}
      footer={null}
      width="80vw"
      style={{ top: 40 }}
      bodyStyle={{ padding: 0, height: '80vh', overflow: 'hidden' }}
      destroyOnClose
      maskClosable={false}
      className="audio-modal"
      closable={false}
      focusTriggerAfterClose={false}
    >
      <div className="audio-modal-content">
        <AudioPanel
          device={device}
          onClose={onCancel}
        />
      </div>
    </Modal>
  );
}

export default AudioModal;
