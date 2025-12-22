import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

const DEFAULT_ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' },
];

function iceServersKey(iceServers) {
  if (!Array.isArray(iceServers) || iceServers.length === 0) return '';
  const normalized = iceServers
    .filter(Boolean)
    .map((s) => {
      const urlsRaw = s.urls;
      const urls = Array.isArray(urlsRaw) ? urlsRaw : (urlsRaw ? [urlsRaw] : []);
      return {
        urls: urls.map(String).sort(),
        username: s.username ? String(s.username) : '',
        credential: s.credential ? String(s.credential) : '',
        credentialType: s.credentialType ? String(s.credentialType) : '',
      };
    });
  try {
    return JSON.stringify(normalized);
  } catch (_) {
    return String(Date.now());
  }
}

function preferH264Codec(transceiver) {
  // Prefer H.264 but keep other codecs available for fallback.
  preferCodec(transceiver, 'h264');
}

function preferCodec(transceiver, codecName) {
  if (!transceiver || typeof transceiver.setCodecPreferences !== 'function') return;
  if (typeof RTCRtpReceiver === 'undefined' || typeof RTCRtpReceiver.getCapabilities !== 'function') return;

  const capabilities = RTCRtpReceiver.getCapabilities('video');
  const codecs = capabilities?.codecs || [];
  if (!Array.isArray(codecs) || codecs.length === 0) return;

  const normalized = codecName.toLowerCase();
  const mimeType = `video/${normalized}`;
  const preferred = codecs.filter((c) => (c?.mimeType || '').toLowerCase() === mimeType);
  if (preferred.length === 0) {
    console.warn(`[WebRTC] codec ${codecName} not available in browser`);
    return;
  }

  // Put preferred codec first, then others
  const others = codecs.filter((c) => (c?.mimeType || '').toLowerCase() !== mimeType);
  try {
    transceiver.setCodecPreferences([...preferred, ...others]);
    console.log(`[WebRTC] codec preference set to ${codecName}`);
  } catch (err) {
    console.warn(`[WebRTC] setCodecPreferences failed:`, err);
  }
}

export function useDesktopWebRTC({
  enabled = true,
  allowControl = true,
  sendSignal = null,
  iceServers = null,
  onTileData = null, // Callback for tile data received via WebRTC data channel
  onFallback = null, // Callback when encoder fallback occurs
} = {}) {
  const videoRef = useRef(null);
  const pcRef = useRef(null);
  const dcRef = useRef(null);
  const tilesDcRef = useRef(null); // Desktop-tiles data channel
  const iceKeyRef = useRef('');
  const pendingIceRef = useRef([]);
  const perfStatsRef = useRef({ lastCaptureTs: 0, samples: [] });
  const startingRef = useRef(false); // Guard against concurrent start() calls
  const onTileDataRef = useRef(onTileData); // Ref to avoid stale closures
  const onFallbackRef = useRef(onFallback); // Ref for fallback callback
  const preferredCodecRef = useRef('h264'); // Current codec preference

  const [status, setStatus] = useState('off'); // off | connecting | connected | failed
  const [controlChannel, setControlChannel] = useState(null);
  const [tilesChannel, setTilesChannel] = useState(null); // Tiles data channel state
  const [hasVideo, setHasVideo] = useState(false);
  const [videoFps, setVideoFps] = useState(0);
  const [latencyMs, setLatencyMs] = useState(0);
  const [displayMode, setDisplayMode] = useState('webrtc'); // webrtc | tiles

  // Keep refs updated
  useEffect(() => {
    onTileDataRef.current = onTileData;
  }, [onTileData]);
  useEffect(() => {
    onFallbackRef.current = onFallback;
  }, [onFallback]);

  // FPS tracking via requestVideoFrameCallback
  const fpsCountRef = useRef(0);
  const fpsIntervalRef = useRef(null);
  const fpsCallbackRef = useRef(null);

  const effectiveIceServers = useMemo(() => {
    if (Array.isArray(iceServers) && iceServers.length > 0) return iceServers;
    return DEFAULT_ICE_SERVERS;
  }, [iceServers]);
  const effectiveIceKey = useMemo(() => iceServersKey(effectiveIceServers), [effectiveIceServers]);

  const stop = useCallback(() => {
    setStatus('off');
    setHasVideo(false);
    setControlChannel(null);
    setTilesChannel(null);
    setLatencyMs(0);
    setDisplayMode('webrtc');
    perfStatsRef.current = { lastCaptureTs: 0, samples: [] };
    iceKeyRef.current = '';
    pendingIceRef.current = [];
    startingRef.current = false; // Allow restart after stop
    preferredCodecRef.current = 'h264'; // Reset codec preference

    const dc = dcRef.current;
    dcRef.current = null;
    if (dc) {
      try { dc.close(); } catch (_) {}
    }

    const tilesDc = tilesDcRef.current;
    tilesDcRef.current = null;
    if (tilesDc) {
      try { tilesDc.close(); } catch (_) {}
    }

    const pc = pcRef.current;
    pcRef.current = null;
    if (pc) {
      try { pc.close(); } catch (_) {}
    }

    const video = videoRef.current;
    if (video && video.srcObject) {
      video.srcObject = null;
    }
  }, []);

  const start = useCallback(async () => {
    console.log('[WebRTC] start called', { enabled, hasSendSignal: !!sendSignal, existingPC: !!pcRef.current, starting: startingRef.current });
    if (!enabled) return;
    if (typeof RTCPeerConnection === 'undefined') return;
    if (!sendSignal) return;
    if (pcRef.current) return;
    // Prevent concurrent start() calls - use ref to guard against React effect re-runs
    if (startingRef.current) {
      console.log('[WebRTC] start already in progress, skipping');
      return;
    }
    startingRef.current = true;

    setStatus('connecting');
    setHasVideo(false);

    console.log('[WebRTC] creating PeerConnection');
    const pc = new RTCPeerConnection({ iceServers: effectiveIceServers });
    pcRef.current = pc;
    iceKeyRef.current = effectiveIceKey;

    const transceiver = pc.addTransceiver('video', { direction: 'recvonly' });
    preferH264Codec(transceiver);

    // Offerer-created data channel so SDP includes m=application.
    const dc = pc.createDataChannel('desktop-input', { ordered: true });
    dcRef.current = dc;
    dc.onopen = () => setControlChannel(dc);
    dc.onclose = () => {
      if (dcRef.current === dc) {
        dcRef.current = null;
      }
      setControlChannel(null);
    };
    dc.onerror = () => {};

    // Data channel handler (receives perf-metadata and desktop-tiles from server)
    pc.ondatachannel = (e) => {
      const { channel } = e;
      if (!channel) return;
      console.log(`[WebRTC] ondatachannel: ${channel.label}`);

      // Handle perf-metadata channel
      if (channel.label === 'perf-metadata') {
        channel.onmessage = (msg) => {
          try {
            const { captureTs } = JSON.parse(msg.data);
            if (typeof captureTs === 'number' && captureTs > 0) {
              perfStatsRef.current.lastCaptureTs = captureTs;
            }
          } catch (err) {
            console.error(`[PERF] onmessage error: ${err.message}`);
          }
        };
        return;
      }

      // Handle desktop-tiles channel (low-latency tile delivery)
      if (channel.label === 'desktop-tiles') {
        channel.binaryType = 'arraybuffer';
        tilesDcRef.current = channel;
        setTilesChannel(channel);

        channel.onmessage = (msg) => {
          // Forward tile data to callback
          if (onTileDataRef.current && msg.data) {
            try {
              onTileDataRef.current(msg.data);
            } catch (err) {
              console.error(`[TILES] onmessage error: ${err.message}`);
            }
          }
        };

        channel.onclose = () => {
          if (tilesDcRef.current === channel) {
            tilesDcRef.current = null;
          }
          setTilesChannel(null);
        };

        channel.onerror = (err) => {
          console.error(`[TILES] channel error:`, err);
        };
        return;
      }
    };

    pc.onicecandidate = (e) => {
      if (!e.candidate) return;
      sendSignal({
        act: 'DESKTOP_WEBRTC_ICE',
        data: {
          candidate: e.candidate.candidate,
          sdpMid: e.candidate.sdpMid,
          mLine: e.candidate.sdpMLineIndex,
        },
      });
    };

    pc.onconnectionstatechange = () => {
      const state = pc.connectionState;
      console.log('[WebRTC] connectionState:', state);
      if (state === 'connected') {
        setStatus('connected');
        return;
      }
      if (state === 'failed') {
        setStatus('failed');
        stop();
      }
      if (state === 'closed' || state === 'disconnected') {
        stop();
      }
    };

    pc.ontrack = (e) => {
      console.log('[WebRTC] ontrack fired', { kind: e.track?.kind, id: e.track?.id, readyState: e.track?.readyState });
      const video = videoRef.current;
      if (!video) {
        console.warn('[WebRTC] ontrack: no video element');
        return;
      }
      const stream = e.streams && e.streams[0] ? e.streams[0] : new MediaStream([e.track]);
      if (video.srcObject !== stream) {
        video.srcObject = stream;
        console.log('[WebRTC] set video.srcObject');
      }
      const tryPlay = () => {
        const p = video.play?.();
        if (p && typeof p.catch === 'function') {
          p.catch((err) => console.warn('[WebRTC] play failed:', err.message));
        }
      };
      video.onloadedmetadata = () => {
        console.log('[WebRTC] video loadedmetadata', { w: video.videoWidth, h: video.videoHeight });
        setHasVideo(true);
        tryPlay();
      };
      video.onplaying = () => {
        console.log('[WebRTC] video playing');
        setHasVideo(true);
      };
      tryPlay();
    };

    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      console.log('[WebRTC] sending offer, sdp length:', offer.sdp?.length);
      await sendSignal({
        act: 'DESKTOP_WEBRTC_OFFER',
        data: {
          sdp: offer.sdp,
          type: offer.type,
          role: allowControl ? 'viewer' : 'viewer_readonly',
        },
      });
      console.log('[WebRTC] offer sent');
    } catch (err) {
      console.error('[WebRTC] offer failed:', err);
      stop();
    }
  }, [allowControl, effectiveIceKey, effectiveIceServers, enabled, sendSignal, stop]);

  // If ICE servers change while connecting and ICE has already failed,
  // restart with the new config (e.g., TURN credentials arrived).
  // Do NOT restart if ICE is still "checking" - let the current attempt complete.
  // This prevents double-offer race conditions when config arrives during active negotiation.
  useEffect(() => {
    const pc = pcRef.current;
    if (!pc) return;
    // Already connected - no need to restart
    if (pc.connectionState === 'connected') return;
    // Only restart if ICE actually failed - checking/new means connection may still succeed
    if (pc.iceConnectionState !== 'failed' && pc.iceConnectionState !== 'disconnected') return;
    // ICE key changed and ICE failed - restart with new config
    if (iceKeyRef.current && iceKeyRef.current !== effectiveIceKey) {
      stop();
      start();
    }
  }, [effectiveIceKey, start, stop]);

  // Initiate SDP renegotiation with a different codec preference
  const initiateRenegotiation = useCallback(async (codec) => {
    const pc = pcRef.current;
    if (!pc || !sendSignal) {
      console.warn('[WebRTC] cannot renegotiate: no PC or sendSignal');
      return;
    }

    console.log(`[WebRTC] initiating renegotiation for codec: ${codec}`);
    preferredCodecRef.current = codec;

    try {
      // Find the video transceiver and update codec preferences
      const transceivers = pc.getTransceivers();
      const videoTransceiver = transceivers.find(t => t.receiver?.track?.kind === 'video');
      if (videoTransceiver) {
        preferCodec(videoTransceiver, codec);
      }

      // Create and send a new offer
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      console.log('[WebRTC] sending renegotiation offer for', codec);
      await sendSignal({
        act: 'DESKTOP_WEBRTC_OFFER',
        data: {
          sdp: offer.sdp,
          type: offer.type,
          role: allowControl ? 'viewer' : 'viewer_readonly',
          renegotiate: true,
          codec: codec,
        },
      });
    } catch (err) {
      console.error('[WebRTC] renegotiation failed:', err);
    }
  }, [allowControl, sendSignal]);

  // Switch to tiles-only display mode (disable video track)
  const switchToTilesMode = useCallback(() => {
    console.log('[WebRTC] switching to tiles mode');
    setDisplayMode('tiles');
    setHasVideo(false);

    // Stop the video track but keep the PC for data channels
    const video = videoRef.current;
    if (video && video.srcObject) {
      const stream = video.srcObject;
      stream.getVideoTracks().forEach(track => {
        console.log('[WebRTC] stopping video track:', track.id);
        track.stop();
      });
      video.srcObject = null;
    }

    // Notify parent component
    if (onFallbackRef.current) {
      onFallbackRef.current({ mode: 'tiles', reason: 'encoder_fallback' });
    }
  }, []);

  const handleSignalMessage = useCallback((msg) => {
    const pc = pcRef.current;
    console.log('[WebRTC] handleSignalMessage', { act: msg?.act, hasPC: !!pc, hasSdp: !!msg?.data?.sdp });
    if (!pc || !msg) {
      console.warn('[WebRTC] handleSignalMessage: no PC or msg');
      return;
    }

    const act = msg.act;
    const code = msg.code;
    if (code && code !== 0 && (act === 'DESKTOP_WEBRTC_ANSWER' || act === 'DESKTOP_WEBRTC_ICE')) {
      console.warn('[WebRTC] signal error:', code, msg.msg);
      stop();
      return;
    }

    const data = msg.data || msg;
    if (act === 'DESKTOP_WEBRTC_ANSWER' && data?.sdp) {
      console.log('[WebRTC] received answer, sdp length:', data.sdp?.length);
      if (pc.signalingState !== 'have-local-offer') {
        console.warn('[WebRTC] ignoring answer in signaling state:', pc.signalingState);
        return;
      }
      pc.setRemoteDescription({ type: data.type || 'answer', sdp: data.sdp })
        .then(() => {
          console.log('[WebRTC] remote description set');
          const pending = pendingIceRef.current;
          if (pending.length) {
            pendingIceRef.current = [];
            pending.forEach((candidate) => {
              pc.addIceCandidate(candidate)
                .catch((err) => console.error('[WebRTC] addIceCandidate failed:', err));
            });
          }
        })
        .catch((err) => console.error('[WebRTC] setRemoteDescription failed:', err));
      return;
    }
    if (act === 'DESKTOP_WEBRTC_ICE' && data?.candidate) {
      console.log('[WebRTC] adding ICE candidate');
      const candidate = {
        candidate: data.candidate,
        sdpMid: data.sdpMid,
        sdpMLineIndex: data.mLine ?? data.sdpMLineIndex,
      };
      if (!pc.remoteDescription) {
        pendingIceRef.current.push(candidate);
        return;
      }
      pc.addIceCandidate(candidate)
        .catch((err) => console.error('[WebRTC] addIceCandidate failed:', err));
      return;
    }

    // Handle encoder fallback: codec switch required (e.g., NVENC -> VP8)
    if (act === 'CODEC_SWITCH_REQUIRED') {
      const toCodec = data?.to_codec || data?.codec || 'vp8';
      console.log(`[WebRTC] server requested codec switch to: ${toCodec}`);

      // Notify parent about the fallback
      if (onFallbackRef.current) {
        onFallbackRef.current({ mode: 'codec_switch', codec: toCodec, reason: data?.reason });
      }

      // Initiate renegotiation with the new codec
      initiateRenegotiation(toCodec);
      return;
    }

    // Handle transport fallback: switch to tiles mode (encoder completely failed)
    if (act === 'TRANSPORT_FALLBACK') {
      console.log('[WebRTC] server requested transport fallback to tiles');
      switchToTilesMode();
      return;
    }
  }, [stop, initiateRenegotiation, switchToTilesMode]);

  useEffect(() => {
    if (!enabled) {
      stop();
    }
  }, [enabled, stop]);

  // FPS and latency tracking effect
  useEffect(() => {
    if (!hasVideo) {
      setVideoFps(0);
      setLatencyMs(0);
      return;
    }

    const video = videoRef.current;
    if (!video) {
      setVideoFps(0);
      setLatencyMs(0);
      return;
    }

    // Expose perf stats on window for e2e tests
    window.__rocketPerfMetrics = perfStatsRef.current;

    fpsCountRef.current = 0;
    perfStatsRef.current.samples = [];

    if (typeof video.requestVideoFrameCallback === 'function') {
      const countFrame = () => {
        fpsCountRef.current++;
        const now = Date.now();
        const captureTs = perfStatsRef.current.lastCaptureTs;
        if (captureTs > 0) {
          const latency = now - captureTs;
          if (latency >= 0 && latency < 10000) {
            if (perfStatsRef.current.samples.length < 10) {
              console.log(`[PERF] latency sample: ${latency} (now=${now}, capture=${captureTs})`);
            }
            perfStatsRef.current.samples.push(latency);
            setLatencyMs(latency);
          }
        }
        fpsCallbackRef.current = video.requestVideoFrameCallback(countFrame);
      };
      fpsCallbackRef.current = video.requestVideoFrameCallback(countFrame);
    }

    fpsIntervalRef.current = setInterval(() => {
      setVideoFps(fpsCountRef.current);
      fpsCountRef.current = 0;
    }, 1000);

    return () => {
      if (fpsIntervalRef.current) {
        clearInterval(fpsIntervalRef.current);
        fpsIntervalRef.current = null;
      }
      if (fpsCallbackRef.current && video && typeof video.cancelVideoFrameCallback === 'function') {
        try {
          video.cancelVideoFrameCallback(fpsCallbackRef.current);
        } catch (_) {}
      }
      fpsCallbackRef.current = null;
      fpsCountRef.current = 0;
      perfStatsRef.current = { lastCaptureTs: 0, samples: [] };
      if (window.__rocketPerfMetrics === perfStatsRef.current) {
        delete window.__rocketPerfMetrics;
      }
    };
  }, [hasVideo]);

  return {
    videoRef,
    status,
    hasVideo,
    isActive: status === 'connected' && hasVideo,
    controlChannel,
    tilesChannel, // WebRTC data channel for low-latency tile delivery
    videoFps,
    latencyMs,
    perfStats: perfStatsRef.current,
    displayMode, // 'webrtc' | 'tiles' - current display mode
    start,
    stop,
    handleSignalMessage,
    initiateRenegotiation, // For manual codec switching if needed
  };
}
