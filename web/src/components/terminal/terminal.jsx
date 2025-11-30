import React from 'react';
import { Modal } from 'antd';
import { TerminalPanel } from '../features/terminal';
import i18n from '../../locale/locale';
import './terminal.modal.css';

const title = i18n.t('TERMINAL.TITLE');

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
      title={`${title} - ${device.hostname || 'Unknown'}`}
      open={open}
      onCancel={onCancel}
      footer={null}
      width="80vw"
      style={{ top: 40 }}
      bodyStyle={{ padding: 0, height: 'calc(80vh - 55px)', overflow: 'hidden' }}
      destroyOnClose
      maskClosable={false}
      className="terminal-modal"
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
