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
  if (!transceiver || typeof transceiver.setCodecPreferences !== 'function') return;
  if (typeof RTCRtpReceiver === 'undefined' || typeof RTCRtpReceiver.getCapabilities !== 'function') return;

  const capabilities = RTCRtpReceiver.getCapabilities('video');
  const codecs = capabilities?.codecs || [];
  if (!Array.isArray(codecs) || codecs.length === 0) return;

  const h264 = codecs.filter((c) => (c?.mimeType || '').toLowerCase() === 'video/h264');
  if (h264.length === 0) return;

  const rest = codecs.filter((c) => (c?.mimeType || '').toLowerCase() !== 'video/h264');
  try {
    transceiver.setCodecPreferences([...h264, ...rest]);
  } catch (_) {
    // Codec preference is best-effort; ignore browsers that reject custom ordering.
  }
}

export function useDesktopWebRTC({
  enabled = true,
  allowControl = true,
  sendSignal = null,
  iceServers = null,
} = {}) {
  const videoRef = useRef(null);
  const pcRef = useRef(null);
  const dcRef = useRef(null);
  const iceKeyRef = useRef('');

  const [status, setStatus] = useState('off'); // off | connecting | connected | failed
  const [controlChannel, setControlChannel] = useState(null);
  const [hasVideo, setHasVideo] = useState(false);
  const [videoFps, setVideoFps] = useState(0);

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
    iceKeyRef.current = '';

    const dc = dcRef.current;
    dcRef.current = null;
    if (dc) {
      try { dc.close(); } catch (_) {}
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
    if (!enabled) return;
    if (typeof RTCPeerConnection === 'undefined') return;
    if (!sendSignal) return;
    if (pcRef.current) return;

    setStatus('connecting');
    setHasVideo(false);

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
      const video = videoRef.current;
      if (!video) return;
      const stream = e.streams && e.streams[0] ? e.streams[0] : new MediaStream([e.track]);
      if (video.srcObject !== stream) {
        video.srcObject = stream;
      }
      const tryPlay = () => {
        const p = video.play?.();
        if (p && typeof p.catch === 'function') {
          p.catch(() => {});
        }
      };
      video.onloadedmetadata = () => {
        setHasVideo(true);
        tryPlay();
      };
      video.onplaying = () => setHasVideo(true);
      tryPlay();
    };

    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendSignal({
        act: 'DESKTOP_WEBRTC_OFFER',
        data: {
          sdp: offer.sdp,
          type: offer.type,
          role: allowControl ? 'viewer' : 'viewer_readonly',
        },
      });
    } catch (err) {
      stop();
    }
  }, [allowControl, effectiveIceKey, effectiveIceServers, enabled, sendSignal, stop]);

  // If ICE servers arrive late (e.g., TURN credentials), restart an in-progress
  // connection attempt so the new config can actually be applied.
  useEffect(() => {
    const pc = pcRef.current;
    if (!pc) return;
    if (pc.connectionState === 'connected') return;
    if (iceKeyRef.current && iceKeyRef.current !== effectiveIceKey) {
      stop();
      start();
    }
  }, [effectiveIceKey, start, stop]);

  const handleSignalMessage = useCallback((msg) => {
    const pc = pcRef.current;
    if (!pc || !msg) return;

    const act = msg.act;
    const code = msg.code;
    if (code && code !== 0 && (act === 'DESKTOP_WEBRTC_ANSWER' || act === 'DESKTOP_WEBRTC_ICE')) {
      stop();
      return;
    }

    const data = msg.data || msg;
    if (act === 'DESKTOP_WEBRTC_ANSWER' && data?.sdp) {
      pc.setRemoteDescription({ type: data.type || 'answer', sdp: data.sdp }).catch(() => {});
      return;
    }
    if (act === 'DESKTOP_WEBRTC_ICE' && data?.candidate) {
      pc.addIceCandidate({
        candidate: data.candidate,
        sdpMid: data.sdpMid,
        sdpMLineIndex: data.mLine ?? data.sdpMLineIndex,
      }).catch(() => {});
    }
  }, [stop]);

  useEffect(() => {
    if (!enabled) {
      stop();
    }
  }, [enabled, stop]);

  // FPS tracking effect using requestVideoFrameCallback
  useEffect(() => {
    if (!hasVideo) {
      setVideoFps(0);
      return;
    }

    const video = videoRef.current;
    if (!video) {
      setVideoFps(0);
      return;
    }

    // Reset counter
    fpsCountRef.current = 0;

    // Use requestVideoFrameCallback if available (modern browsers)
    if (typeof video.requestVideoFrameCallback === 'function') {
      const countFrame = () => {
        fpsCountRef.current++;
        fpsCallbackRef.current = video.requestVideoFrameCallback(countFrame);
      };
      fpsCallbackRef.current = video.requestVideoFrameCallback(countFrame);
    }

    // Report FPS every second
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
    };
  }, [hasVideo]);

  return {
    videoRef,
    status,
    hasVideo,
    isActive: status === 'connected' && hasVideo,
    controlChannel,
    videoFps,
    start,
    stop,
    handleSignalMessage,
  };
}
