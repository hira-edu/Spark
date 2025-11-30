import React, { forwardRef, useCallback } from 'react';
import './Canvas.css';

/**
 * DesktopCanvas - The canvas element that displays the remote desktop
 * Uses forwardRef to allow parent components to access the canvas element
 */
const DesktopCanvas = forwardRef(({
  pointerLocked = false,
  onCanvasClick,
  onMouseMove,
  onMouseDown,
  onMouseUp,
  onWheel,
  className = '',
}, ref) => {
  const handleClick = useCallback((e) => {
    if (onCanvasClick) {
      onCanvasClick(e);
    }
  }, [onCanvasClick]);

  return (
    <div className={`desktop-canvas-wrapper ${className}`}>
      <canvas
        ref={ref}
        className="desktop-canvas"
        tabIndex={0}
        onClick={handleClick}
        onMouseMove={onMouseMove}
        onMouseDown={onMouseDown}
        onMouseUp={onMouseUp}
        onWheel={onWheel}
        onContextMenu={(e) => e.preventDefault()}
      />
    </div>
  );
});

DesktopCanvas.displayName = 'DesktopCanvas';

export default DesktopCanvas;
