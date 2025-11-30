import React from 'react';
import { Modal } from 'antd';
import { FileExplorer } from '../features/explorer';
import i18n from '../../locale/locale';
import './explorer.modal.css';

const title = i18n.t('EXPLORER.TITLE');

/**
 * ExplorerModal - Modal wrapper for the new FileExplorer component
 * Maintains compatibility with the existing API
 */
function ExplorerModal(props) {
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
      className="explorer-modal"
    >
      <div className="explorer-modal-content">
        <FileExplorer
          device={device}
          onClose={onCancel}
        />
      </div>
    </Modal>
  );
}

export default ExplorerModal;
