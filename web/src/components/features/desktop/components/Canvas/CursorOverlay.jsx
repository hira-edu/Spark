import React, { useEffect, useRef } from 'react';

// Maximum cursor size to prevent memory issues with malformed data
const MAX_CURSOR_SIZE = 256;

/**
 * CursorOverlay - Renders the remote cursor as an overlay on the canvas
 * Displays the actual remote cursor appearance (arrow, hand, I-beam, etc.)
 */
const CursorOverlay = ({ cursor, canvasRect, containerRect, scale = 1 }) => {
  const canvasRef = useRef(null);

  // Convert base64 RGBA data to canvas image
  useEffect(() => {
    // Validate cursor dimensions
    if (!cursor.visible || !cursor.data || cursor.width <= 0 || cursor.height <= 0) {
      return;
    }
    // Reject oversized cursors to prevent memory exhaustion
    if (cursor.width > MAX_CURSOR_SIZE || cursor.height > MAX_CURSOR_SIZE) {
      console.warn('Cursor too large, ignoring:', cursor.width, 'x', cursor.height);
      return;
    }

    const canvas = canvasRef.current;
    if (!canvas) return;

    // Set canvas size to cursor dimensions (unscaled)
    canvas.width = cursor.width;
    canvas.height = cursor.height;

    try {
      const binaryString = atob(cursor.data);
      const bytes = new Uint8ClampedArray(binaryString.length);
      for (let i = 0; i < binaryString.length; i += 1) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      const imageData = new ImageData(bytes, cursor.width, cursor.height);
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.putImageData(imageData, 0, 0);
      }
    } catch (err) {
      console.error('Failed to render cursor:', err);
    }
  }, [cursor.data, cursor.width, cursor.height, cursor.hash, cursor.visible]);

  // Don't render if cursor is not visible, no geometry, or invalid dimensions
  if (!cursor.visible || !cursor.data || !canvasRect ||
      cursor.width <= 0 || cursor.height <= 0 ||
      cursor.width > MAX_CURSOR_SIZE || cursor.height > MAX_CURSOR_SIZE) {
    return null;
  }

  // Calculate cursor position relative to canvas
  const renderScale = Number.isFinite(scale) && scale > 0 ? scale : 1;
  const containerLeft = containerRect ? containerRect.left : 0;
  const containerTop = containerRect ? containerRect.top : 0;
  const canvasOffsetX = canvasRect.left - containerLeft;
  const canvasOffsetY = canvasRect.top - containerTop;
  const x = (cursor.x - cursor.hotX) * renderScale + canvasOffsetX;
  const y = (cursor.y - cursor.hotY) * renderScale + canvasOffsetY;

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        left: `${x}px`,
        top: `${y}px`,
        width: `${cursor.width * renderScale}px`,
        height: `${cursor.height * renderScale}px`,
        pointerEvents: 'none',
        zIndex: 10000,
        imageRendering: 'pixelated',
      }}
    />
  );
};

export default CursorOverlay;
