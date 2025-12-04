import React, { useEffect, useRef } from 'react';

// Maximum cursor size to prevent memory issues with malformed data
const MAX_CURSOR_SIZE = 256;

/**
 * Convert pixel data from various formats to RGBA for canvas rendering.
 * Supports: rgba (default), argb32, bgra
 */
function convertToRGBA(bytes, format) {
  const fmt = (format || 'rgba').toLowerCase();

  // rgba is the native canvas format - no conversion needed
  if (fmt === 'rgba' || fmt === 'rgba32') {
    return bytes;
  }

  const result = new Uint8ClampedArray(bytes.length);

  if (fmt === 'argb32' || fmt === 'argb') {
    // ARGB32: [A, R, G, B] → RGBA: [R, G, B, A]
    for (let i = 0; i < bytes.length; i += 4) {
      result[i] = bytes[i + 1];     // R
      result[i + 1] = bytes[i + 2]; // G
      result[i + 2] = bytes[i + 3]; // B
      result[i + 3] = bytes[i];     // A
    }
  } else if (fmt === 'bgra' || fmt === 'bgra32') {
    // BGRA: [B, G, R, A] → RGBA: [R, G, B, A]
    for (let i = 0; i < bytes.length; i += 4) {
      result[i] = bytes[i + 2];     // R
      result[i + 1] = bytes[i + 1]; // G
      result[i + 2] = bytes[i];     // B
      result[i + 3] = bytes[i + 3]; // A
    }
  } else {
    // Unknown format, assume rgba
    return bytes;
  }

  return result;
}

/**
 * CursorOverlay - Renders the remote cursor as an overlay on the canvas
 * Displays the actual remote cursor appearance (arrow, hand, I-beam, etc.)
 */
const CursorOverlay = ({ cursor, canvasRect, containerRect, scale = 1 }) => {
  const canvasRef = useRef(null);

  // Convert base64 data to canvas image with format support
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
      const rawBytes = new Uint8ClampedArray(binaryString.length);
      for (let i = 0; i < binaryString.length; i += 1) {
        rawBytes[i] = binaryString.charCodeAt(i);
      }

      // Convert to RGBA based on format field
      const rgbaBytes = convertToRGBA(rawBytes, cursor.format);
      const imageData = new ImageData(rgbaBytes, cursor.width, cursor.height);
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.putImageData(imageData, 0, 0);
      }
    } catch (err) {
      console.error('Failed to render cursor:', err);
    }
  }, [cursor.data, cursor.width, cursor.height, cursor.hash, cursor.visible, cursor.format]);

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
