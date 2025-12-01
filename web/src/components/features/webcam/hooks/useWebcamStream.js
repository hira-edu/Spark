import { useState, useCallback, useRef, useEffect } from 'react';
import { request } from '../../../../utils/utils';

/**
 * useWebcamStream - Hook for managing webcam streaming from remote device
 */
const useWebcamStream = (device, canvasRef) => {
  const [status, setStatus] = useState('disconnected'); // disconnected, connecting, streaming
  const [devices, setDevices] = useState([]);
  const [frameData, setFrameData] = useState(null);
  const [currentResolution, setCurrentResolution] = useState('640x480');
  const [stats, setStats] = useState({
    framesReceived: 0,
    bytesReceived: 0,
    fps: 0,
    latency: 0,
    duration: 0,
  });

  const wsRef = useRef(null);
  const startTimeRef = useRef(null);
  const streamUuidRef = useRef(null);
  const lastFrameTimeRef = useRef(0);
  const fpsCounterRef = useRef({ frames: 0, lastUpdate: Date.now() });

  // Fetch available webcam devices from remote
  const fetchDevices = useCallback(async () => {
    if (!device?.id) return;

    try {
      const res = await request('/api/device/webcam/devices', {
        device: device.id,
      });

      if (res.data?.code === 0 && res.data?.data) {
        setDevices(res.data.data.devices || []);
      }
    } catch (err) {
      console.error('Failed to fetch webcam devices:', err);
      setDevices([]);
    }
  }, [device?.id]);

  // Draw frame to canvas
  const drawFrame = useCallback((imageData) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const img = new Image();

    img.onload = () => {
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0);
      setCurrentResolution(`${img.width}x${img.height}`);
    };

    // imageData is base64 JPEG
    img.src = `data:image/jpeg;base64,${imageData}`;
  }, [canvasRef]);

  // Start webcam stream
  const startStream = useCallback(async (devicePath, quality, fps, width, height) => {
    if (!device?.id || wsRef.current) {
      return;
    }

    setStatus('connecting');

    // Generate unique stream UUID
    const streamUuid = `webcam-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    streamUuidRef.current = streamUuid;
    startTimeRef.current = Date.now();

    // Reset stats
    setStats({
      framesReceived: 0,
      bytesReceived: 0,
      fps: 0,
      latency: 0,
      duration: 0,
    });

    // Connect WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/webcam/connect?device=${device.id}`;

    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('Webcam WebSocket connected');

      // Send start command
      ws.send(JSON.stringify({
        act: 'WEBCAM_SELECT',
        data: {
          uuid: streamUuid,
          device: devicePath,
          quality,
          fps,
          width,
          height,
        },
      }));

      setStatus('streaming');
    };

    ws.onmessage = (event) => {
      try {
        // Parse message (could be text or binary)
        if (typeof event.data === 'string') {
          const msg = JSON.parse(event.data);

          // Handle control messages
          if (msg.act === 'WEBCAM_ERROR') {
            console.error('Webcam error from server:', msg.data);
            setStatus('error');
          } else if (msg.act === 'WEBCAM_DEVICES') {
            setDevices(msg.data.devices || []);
          } else if (msg.act === 'WEBCAM_FRAME') {
            // Frame data in JSON format (base64 JPEG)
            const frameTimestamp = msg.data.timestamp || Date.now();
            const latency = Date.now() - frameTimestamp;
            const byteLength = msg.data.data ? msg.data.data.length : 0;

            // Update FPS counter
            const now = Date.now();
            fpsCounterRef.current.frames++;
            if (now - fpsCounterRef.current.lastUpdate >= 1000) {
              const fps = fpsCounterRef.current.frames;
              fpsCounterRef.current = { frames: 0, lastUpdate: now };

              setStats(prev => ({
                ...prev,
                fps,
              }));
            }

            // Update stats
            setStats(prev => ({
              ...prev,
              framesReceived: prev.framesReceived + 1,
              bytesReceived: prev.bytesReceived + byteLength,
              latency,
              duration: (Date.now() - startTimeRef.current) / 1000,
            }));

            // Draw frame
            if (msg.data.data) {
              setFrameData(msg.data.data);
              drawFrame(msg.data.data);
            }

            lastFrameTimeRef.current = Date.now();
          }
        }
      } catch (err) {
        console.error('Failed to process webcam message:', err);
      }
    };

    ws.onerror = (error) => {
      console.error('Webcam WebSocket error:', error);
      setStatus('error');
    };

    ws.onclose = () => {
      console.log('Webcam WebSocket closed');
      setStatus('disconnected');
      wsRef.current = null;
    };
  }, [device?.id, canvasRef, drawFrame]);

  // Stop webcam stream
  const stopStream = useCallback(() => {
    if (wsRef.current) {
      // Send stop command
      if (wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          act: 'WEBCAM_STOP',
          data: {
            uuid: streamUuidRef.current,
          },
        }));
      }

      wsRef.current.close();
      wsRef.current = null;
    }

    setStatus('disconnected');
    setFrameData(null);
    streamUuidRef.current = null;
    startTimeRef.current = null;
  }, []);

  // Update stream configuration
  const updateConfig = useCallback((config) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        act: 'WEBCAM_CONFIG',
        data: {
          uuid: streamUuidRef.current,
          ...config,
        },
      }));
    }
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stopStream();
    };
  }, [stopStream]);

  return {
    status,
    devices,
    frameData,
    stats,
    currentResolution,
    fetchDevices,
    startStream,
    stopStream,
    updateConfig,
  };
};

export default useWebcamStream;
