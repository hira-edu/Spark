import React from 'react';
import { Modal } from 'antd';
import { ProcessManager } from '../features/procmgr';
import './procmgr.modal.css';

/**
 * ProcessMgr - Modal wrapper for the new ProcessManager component
 * Maintains compatibility with the existing API
 */
function ProcessMgr(props) {
  const { open, device, onCancel } = props;

  if (!open || !device) {
    return null;
  }

  return (
    <Modal
      open={open}
      onCancel={onCancel}
      footer={null}
      width="70vw"
      style={{ top: 40 }}
      bodyStyle={{ padding: 0, height: '75vh', overflow: 'hidden' }}
      destroyOnClose
      maskClosable={false}
      className="procmgr-modal"
      closable={false}
      focusTriggerAfterClose={false}
    >
      <div className="procmgr-modal-content">
        <ProcessManager device={device} onClose={onCancel} />
      </div>
    </Modal>
  );
}

export default ProcessMgr;