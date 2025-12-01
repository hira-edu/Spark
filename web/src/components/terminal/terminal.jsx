import React from 'react';
import { Modal } from 'antd';
import { TerminalPanel } from '../features/terminal';
import './terminal.modal.css';

/**
 * TerminalModal - Modal wrapper for the new TerminalPanel component
 * Maintains compatibility with the existing API
 */
function TerminalModal(props) {
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
      className="terminal-modal"
      closable={false}
      focusTriggerAfterClose={false}
    >
      <div className="terminal-modal-content">
        <TerminalPanel
          device={device}
          onClose={onCancel}
        />
      </div>
    </Modal>
  );
}

export default TerminalModal;
