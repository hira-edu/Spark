import { useState, useCallback, useRef, useEffect } from 'react';
import { request } from '../../../../utils/utils';

/**
 * useAudioStream - Hook for managing audio streaming from remote device
 */
const useAudioStream = (device) => {
  const [status, setStatus] = useState('disconnected'); // disconnected, connecting, streaming
  const [devices, setDevices] = useState([]);
  const [audioData, setAudioData] = useState(null);
  const [stats, setStats] = useState({
    packetsReceived: 0,
    bytesReceived: 0,
    duration: 0,
    sampleRate: 48000,
    channels: 1,
    codec: 'Opus',
  });

  const wsRef = useRef(null);
  const audioContextRef = useRef(null);
  const startTimeRef = useRef(null);
  const streamUuidRef = useRef(null);

  // Fetch available audio devices from remote
  const fetchDevices = useCallback(async () => {
    if (!device?.id) return;

    try {
      const res = await request('/api/device/audio/devices', {
        device: device.id,
      });

      if (res.data?.code === 0 && res.data?.data) {
        setDevices(res.data.data.devices || []);
      }
    } catch (err) {
      console.error('Failed to fetch audio devices:', err);
      setDevices([]);
    }
  }, [device?.id]);

  // Initialize WebAudio context
  const initAudioContext = useCallback(() => {
    if (!audioContextRef.current) {
      audioContextRef.current = new (window.AudioContext || window.webkitAudioContext)({
        sampleRate: 48000,
      });
    }

    // Resume if suspended
    if (audioContextRef.current.state === 'suspended') {
      audioContextRef.current.resume();
    }
  }, []);

  // Start audio stream
  const startStream = useCallback(async (deviceIndex) => {
    if (!device?.id || wsRef.current) {
      return;
    }

    setStatus('connecting');
    initAudioContext();

    // Generate unique stream UUID
    const streamUuid = `audio-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    streamUuidRef.current = streamUuid;
    startTimeRef.current = Date.now();

    // Reset stats
    setStats({
      packetsReceived: 0,
      bytesReceived: 0,
      duration: 0,
      sampleRate: 48000,
      channels: 1,
      codec: 'Opus',
    });

    // Connect WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/audio/connect?device=${device.id}`;

    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('Audio WebSocket connected');

      // Send start command
      ws.send(JSON.stringify({
        act: 'AUDIO_SELECT',
        data: {
          uuid: streamUuid,
          device: deviceIndex,
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
          if (msg.act === 'AUDIO_ERROR') {
            console.error('Audio error from server:', msg.data);
            setStatus('error');
          } else if (msg.act === 'AUDIO_DEVICES') {
            setDevices(msg.data.devices || []);
          }
        } else if (event.data instanceof ArrayBuffer) {
          // Handle binary audio data
          const audioBuffer = event.data;
          const byteLength = audioBuffer.byteLength;

          // Update stats
          setStats(prev => ({
            ...prev,
            packetsReceived: prev.packetsReceived + 1,
            bytesReceived: prev.bytesReceived + byteLength,
            duration: (Date.now() - startTimeRef.current) / 1000,
          }));

          // Store audio data for visualizer
          setAudioData(new Uint8Array(audioBuffer));

          // Decode and play audio (if using Opus decoder)
          // For now, just store the data
          // TODO: Implement Opus decoding and playback via Web Audio API
        }
      } catch (err) {
        console.error('Failed to process audio message:', err);
      }
    };

    ws.onerror = (error) => {
      console.error('Audio WebSocket error:', error);
      setStatus('error');
    };

    ws.onclose = () => {
      console.log('Audio WebSocket closed');
      setStatus('disconnected');
      wsRef.current = null;
    };
  }, [device?.id, initAudioContext]);

  // Stop audio stream
  const stopStream = useCallback(() => {
    if (wsRef.current) {
      // Send stop command
      if (wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          act: 'AUDIO_STOP',
          data: {
            uuid: streamUuidRef.current,
          },
        }));
      }

      wsRef.current.close();
      wsRef.current = null;
    }

    setStatus('disconnected');
    setAudioData(null);
    streamUuidRef.current = null;
    startTimeRef.current = null;
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stopStream();

      if (audioContextRef.current) {
        audioContextRef.current.close();
        audioContextRef.current = null;
      }
    };
  }, [stopStream]);

  return {
    status,
    devices,
    audioData,
    stats,
    fetchDevices,
    startStream,
    stopStream,
  };
};

export default useAudioStream;
