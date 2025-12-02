import React, { useEffect, useRef } from 'react';

/**
 * CursorOverlay - Renders the remote cursor as an overlay on the canvas
 * Displays the actual remote cursor appearance (arrow, hand, I-beam, etc.)
 */
const CursorOverlay = ({ cursor, canvasRect, scale = 1 }) => {
  const canvasRef = useRef(null);

  // Convert base64 RGBA data to canvas image
  useEffect(() => {
    if (!cursor.visible || !cursor.data || cursor.width === 0 || cursor.height === 0) {
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

  // Don't render if cursor is not visible or no geometry
  if (!cursor.visible || !cursor.data || !canvasRect) {
    return null;
  }

  // Calculate cursor position relative to canvas
  const renderScale = Number.isFinite(scale) && scale > 0 ? scale : 1;
  const x = (cursor.x - cursor.hotX) * renderScale + canvasRect.left;
  const y = (cursor.y - cursor.hotY) * renderScale + canvasRect.top;

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
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
