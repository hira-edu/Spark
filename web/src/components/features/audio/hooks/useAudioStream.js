import { useState, useCallback, useRef, useEffect } from 'react';
import { getBaseURL } from '../../../../utils/utils';

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
  const decoderRef = useRef(null);
  const nextPlayTimeRef = useRef(0);
  const tsRef = useRef(0);

  const decodeAndPlay = useCallback((packet) => {
    const ctx = audioContextRef.current;
    const decoder = decoderRef.current;
    if (!ctx || !decoder || !packet || packet.byteLength === 0) return;

    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }

    try {
      const ts = tsRef.current;
      tsRef.current += 20_000; // 20ms in microseconds (best-effort)

      const chunk = new EncodedAudioChunk({
        type: 'key',
        timestamp: ts,
        data: packet,
      });
      decoder.decode(chunk);
    } catch (_) {
      // Ignore decode errors; decoder state may vary across browsers.
    }
  }, []);

  // Fetch available audio devices from remote via active WS session.
  const fetchDevices = useCallback(async () => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ act: 'AUDIO_LIST' }));
  }, []);

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

    // Initialize WebCodecs Opus decoder when available.
    if (!decoderRef.current && typeof AudioDecoder !== 'undefined') {
      const ctx = audioContextRef.current;
      const decoder = new AudioDecoder({
        output: (audio) => {
          try {
            const frames = audio.numberOfFrames;
            const channels = audio.numberOfChannels;
            const sampleRate = audio.sampleRate;
            const buf = ctx.createBuffer(channels, frames, sampleRate);

            for (let ch = 0; ch < channels; ch += 1) {
              const plane = new Float32Array(frames);
              audio.copyTo(plane, { planeIndex: ch });
              buf.getChannelData(ch).set(plane);
            }
            audio.close();

            const src = ctx.createBufferSource();
            src.buffer = buf;
            src.connect(ctx.destination);

            const now = ctx.currentTime;
            if (!nextPlayTimeRef.current || nextPlayTimeRef.current < now) {
              nextPlayTimeRef.current = now + 0.03;
            }
            src.start(nextPlayTimeRef.current);
            nextPlayTimeRef.current += buf.duration;
          } catch (_) {
            try { audio.close(); } catch (_) {}
          }
        },
        error: () => {},
      });

      try {
        decoder.configure({ codec: 'opus', sampleRate: 48000, numberOfChannels: 1 });
        decoderRef.current = decoder;
        tsRef.current = 0;
      } catch (_) {
        try { decoder.close(); } catch (_) {}
      }
    }
  }, []);

  // Start audio stream
  const startStream = useCallback(async (deviceIndex) => {
    if (!device?.id || wsRef.current) {
      return;
    }

    setStatus('connecting');
    initAudioContext();

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
    const ws = new WebSocket(getBaseURL(true, `api/device/audio?device=${device.id}`));
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      // Send select/start command
      ws.send(JSON.stringify({ act: 'AUDIO_SELECT', data: { device: deviceIndex } }));
      setStatus('streaming');
    };

    ws.onmessage = (event) => {
      try {
        if (typeof event.data === 'string') {
          const msg = JSON.parse(event.data);
          if (msg.act === 'AUDIO_LIST' && msg.code === 0) {
            setDevices(msg?.data?.devices || []);
          }
          if (msg.act === 'AUDIO_ERROR') {
            setStatus('error');
          }
          return;
        }

        if (event.data instanceof ArrayBuffer) {
          const buf = new Uint8Array(event.data);
          const isMagic = buf.length >= 6 && buf[0] === 34 && buf[1] === 22 && buf[2] === 19 && buf[3] === 17 && buf[4] === 23 && buf[5] === 5;
          if (isMagic) {
            const txt = new TextDecoder().decode(buf.slice(6));
            const msg = JSON.parse(txt);
            if (msg.act === 'AUDIO_LIST' && msg.code === 0) {
              setDevices(msg?.data?.devices || []);
            }
            return;
          }

          // Raw Opus packet
          const byteLength = buf.byteLength;
          setStats(prev => ({
            ...prev,
            packetsReceived: prev.packetsReceived + 1,
            bytesReceived: prev.bytesReceived + byteLength,
            duration: (Date.now() - startTimeRef.current) / 1000,
          }));
          setAudioData(buf);
          decodeAndPlay(buf);
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
        wsRef.current.send(JSON.stringify({ act: 'AUDIO_STOP' }));
      }

      wsRef.current.close();
      wsRef.current = null;
    }

    setStatus('disconnected');
    setAudioData(null);
    startTimeRef.current = null;
    nextPlayTimeRef.current = 0;
    tsRef.current = 0;
    if (decoderRef.current) {
      try { decoderRef.current.close(); } catch (_) {}
      decoderRef.current = null;
    }
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
