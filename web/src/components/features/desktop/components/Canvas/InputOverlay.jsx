import React from 'react';
import './Canvas.css';

/**
 * InputOverlay - Shows pointer lock indicator and connection overlays
 */
const InputOverlay = ({ pointerLocked, status, onReconnect }) => {
  // Pointer lock indicator
  if (pointerLocked) {
    return (
      <div className="pointer-lock-indicator">
        <span>Press ESC to release cursor</span>
      </div>
    );
  }

  // Connection status overlays
  if (status !== 'connected') {
    return (
      <div className="connection-overlay">
        {status === 'connecting' && (
          <>
            <div className="connection-overlay-spinner" />
            <span className="connection-overlay-text">Connecting...</span>
          </>
        )}
        {status === 'reconnecting' && (
          <>
            <div className="connection-overlay-spinner" />
            <span className="connection-overlay-text">Reconnecting...</span>
          </>
        )}
        {status === 'disconnected' && (
          <>
            <span className="connection-overlay-text">Disconnected</span>
            <button
              className="connection-overlay-button"
              onClick={onReconnect}
            >
              Reconnect
            </button>
          </>
        )}
        {status === 'error' && (
          <>
            <span className="connection-overlay-text connection-overlay-text--error">
              Connection failed
            </span>
            <button
              className="connection-overlay-button"
              onClick={onReconnect}
            >
              Retry
            </button>
          </>
        )}
      </div>
    );
  }

  return null;
};

export default InputOverlay;
