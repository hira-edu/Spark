import React, { forwardRef } from 'react';
import { Tag } from 'antd';
import { VideoCameraOutlined } from '@ant-design/icons';
import i18n from '../../../../locale/locale';
import './WebcamViewer.css';

/**
 * WebcamViewer - Canvas-based webcam video viewer
 */
export const WebcamViewer = forwardRef(({ frameData, resolution, isRecording }, ref) => {
  return (
    <div className="webcam-viewer">
      <canvas
        ref={ref}
        className="webcam-viewer-canvas"
      />

      {/* Overlays */}
      <div className="webcam-viewer-overlay">
        {/* Resolution badge */}
        {resolution && (
          <div className="webcam-viewer-resolution">
            {resolution}
          </div>
        )}

        {/* Recording indicator */}
        {isRecording && (
          <div className="webcam-viewer-recording">
            <Tag color="red" icon={<VideoCameraOutlined />} className="webcam-viewer-recording-tag">
              {i18n.t('WEBCAM.RECORDING')}
            </Tag>
          </div>
        )}

        {/* No frame indicator */}
        {!frameData && (
          <div className="webcam-viewer-no-frame">
            <VideoCameraOutlined style={{ fontSize: 48, color: 'rgba(59, 130, 246, 0.3)' }} />
            <div>{i18n.t('WEBCAM.WAITING_FOR_FRAMES')}</div>
          </div>
        )}
      </div>
    </div>
  );
});

WebcamViewer.displayName = 'WebcamViewer';
