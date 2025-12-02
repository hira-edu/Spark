import { useState, useEffect, useCallback, useRef } from 'react';

const INPUT_FLUSH_MS = 16; // 60 FPS
const INPUT_BUFFER_LIMIT = 32;

/**
 * useInputCapture - Hook for capturing mouse and keyboard input
 * @param {React.RefObject} canvasRef - Reference to the canvas element
 * @param {Object} options - Options for input capture
 */
export function useInputCapture(canvasRef, options = {}) {
  const {
    enabled = false,
    mouseEnabled = true,
    keyboardEnabled = true,
    onInput = () => {},
  } = options;

  const [pointerLocked, setPointerLocked] = useState(false);
  const inputBufferRef = useRef([]);
  const inputTimerRef = useRef(null);
  const focusedRef = useRef(false);
  const releasePointerLock = useCallback(() => {
    if (document.pointerLockElement) {
      document.exitPointerLock?.();
    }
  }, []);

  // Clamp value between min and max
  const clamp = (val, min, max) => Math.max(min, Math.min(max, val));

  // Queue an input event
  const queueInput = useCallback((event) => {
    if (!enabled) return;
    const buffer = inputBufferRef.current;

    // Coalesce high-frequency move/scroll events to the latest sample
    if (event?.type === 'move' || event?.type === 'scroll') {
      for (let i = buffer.length - 1; i >= 0; i -= 1) {
        if (buffer[i].type === event.type) {
          buffer[i] = event;
          return;
        }
      }
    }

    if (buffer.length >= INPUT_BUFFER_LIMIT) {
      buffer.shift();
    }
    buffer.push(event);
  }, [enabled]);

  // Flush the input buffer
  const flushBuffer = useCallback(() => {
    if (!enabled || inputBufferRef.current.length === 0) return;
    onInput([...inputBufferRef.current]);
    inputBufferRef.current = [];
  }, [enabled, onInput]);

  // Handle mouse move
  const handleMouseMove = useCallback((e) => {
    if (!enabled || !mouseEnabled) return;
    const canvas = canvasRef.current;
    if (!canvas) return;

    const locked = document.pointerLockElement === canvas;
    if (locked) {
      const dx = Math.trunc(e.movementX);
      const dy = Math.trunc(e.movementY);
      if (dx !== 0 || dy !== 0) {
        queueInput({ type: 'move', deltaX: dx, deltaY: dy });
      }
      return;
    }

    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return;

    const x = clamp(
      Math.round(((e.clientX - rect.left) / rect.width) * canvas.width),
      0,
      canvas.width - 1
    );
    const y = clamp(
      Math.round(((e.clientY - rect.top) / rect.height) * canvas.height),
      0,
      canvas.height - 1
    );
    queueInput({ type: 'move', x, y });
  }, [enabled, mouseEnabled, canvasRef, queueInput]);

  // Handle mouse down
  const handleMouseDown = useCallback((e) => {
    if (!enabled || !mouseEnabled) return;
    focusedRef.current = true;
    const buttons = ['left', 'middle', 'right'];
    queueInput({
      type: 'button',
      button: buttons[e.button] || 'left',
      down: true,
    });
  }, [enabled, mouseEnabled, queueInput]);

  // Handle mouse up
  const handleMouseUp = useCallback((e) => {
    if (!enabled || !mouseEnabled) return;
    const buttons = ['left', 'middle', 'right'];
    queueInput({
      type: 'button',
      button: buttons[e.button] || 'left',
      down: false,
    });
  }, [enabled, mouseEnabled, queueInput]);

  // Handle mouse leave
  const handleMouseLeave = useCallback(() => {
    const canvas = canvasRef.current;
    if (document.pointerLockElement !== canvas) {
      focusedRef.current = false;
    }
  }, [canvasRef]);

  // Handle wheel
  const handleWheel = useCallback((e) => {
    if (!enabled || !mouseEnabled) return;
    e.preventDefault();
    queueInput({
      type: 'scroll',
      deltaX: Math.trunc(e.deltaX),
      deltaY: Math.trunc(e.deltaY),
    });
  }, [enabled, mouseEnabled, queueInput]);

  // Handle key down
  const handleKeyDown = useCallback((e) => {
    if (!enabled || !keyboardEnabled) return;
    const canvas = canvasRef.current;
    if (!focusedRef.current && document.pointerLockElement !== canvas) return;

    e.preventDefault();
    queueInput({
      type: 'key',
      key: e.key,
      keyCode: e.keyCode || e.which || 0,
      down: true,
    });
  }, [enabled, keyboardEnabled, canvasRef, queueInput]);

  // Handle key up
  const handleKeyUp = useCallback((e) => {
    if (!enabled || !keyboardEnabled) return;
    const canvas = canvasRef.current;
    if (!focusedRef.current && document.pointerLockElement !== canvas) return;

    e.preventDefault();
    queueInput({
      type: 'key',
      key: e.key,
      keyCode: e.keyCode || e.which || 0,
      down: false,
    });
  }, [enabled, keyboardEnabled, canvasRef, queueInput]);

  // Handle pointer lock change
  const handlePointerLockChange = useCallback(() => {
    // Always treat as unlocked to keep cursor visible
    releasePointerLock();
    focusedRef.current = false;
    setPointerLocked(false);
  }, [releasePointerLock]);

  // Handle pointer lock error
  const handlePointerLockError = useCallback(() => {
    setPointerLocked(false);
  }, []);

  // Request pointer lock
  const requestPointerLock = useCallback(() => {
    // Intentionally disabled to keep cursor visible
    return;
  }, [canvasRef, enabled]);

  // Exit pointer lock
  const exitPointerLock = useCallback(() => {
    if (document.pointerLockElement) {
      document.exitPointerLock?.();
    }
  }, []);

  // Attach event listeners
  useEffect(() => {
    if (!enabled) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    // Ensure any stale pointer lock from previous sessions is cleared
    releasePointerLock();

    // Attach canvas events
    canvas.addEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('mousedown', handleMouseDown);
    canvas.addEventListener('mouseup', handleMouseUp);
    canvas.addEventListener('mouseleave', handleMouseLeave);
    canvas.addEventListener('wheel', handleWheel, { passive: false });

    // Attach window/document events
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('keyup', handleKeyUp);
    document.addEventListener('pointerlockchange', handlePointerLockChange);
    document.addEventListener('pointerlockerror', handlePointerLockError);

    // Start flush timer
    inputTimerRef.current = setInterval(flushBuffer, INPUT_FLUSH_MS);

    return () => {
      // Cleanup canvas events
      canvas.removeEventListener('mousemove', handleMouseMove);
      canvas.removeEventListener('mousedown', handleMouseDown);
      canvas.removeEventListener('mouseup', handleMouseUp);
      canvas.removeEventListener('mouseleave', handleMouseLeave);
      canvas.removeEventListener('wheel', handleWheel);

      // Cleanup window/document events
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('keyup', handleKeyUp);
      document.removeEventListener('pointerlockchange', handlePointerLockChange);
      document.removeEventListener('pointerlockerror', handlePointerLockError);

      // Clear timer
      if (inputTimerRef.current) {
        clearInterval(inputTimerRef.current);
        inputTimerRef.current = null;
      }

      // Exit pointer lock
      releasePointerLock();

      // Clear buffer
      inputBufferRef.current = [];
      focusedRef.current = false;
    };
  }, [
    enabled,
    canvasRef,
    handleMouseMove,
    handleMouseDown,
    handleMouseUp,
    handleMouseLeave,
    handleWheel,
    handleKeyDown,
    handleKeyUp,
    handlePointerLockChange,
    handlePointerLockError,
    flushBuffer,
    releasePointerLock,
  ]);

  return {
    pointerLocked,
    requestPointerLock,
    exitPointerLock,
  };
}

export default useInputCapture;
