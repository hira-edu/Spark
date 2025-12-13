import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

const DEFAULT_ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' },
];

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

  const [status, setStatus] = useState('off'); // off | connecting | connected | failed
  const [controlChannel, setControlChannel] = useState(null);
  const [hasVideo, setHasVideo] = useState(false);

  const effectiveIceServers = useMemo(() => {
    if (Array.isArray(iceServers) && iceServers.length > 0) return iceServers;
    return DEFAULT_ICE_SERVERS;
  }, [iceServers]);

  const stop = useCallback(() => {
    setStatus('off');
    setHasVideo(false);
    setControlChannel(null);

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
  }, [allowControl, effectiveIceServers, enabled, sendSignal, stop]);

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

  return {
    videoRef,
    status,
    hasVideo,
    isActive: status === 'connected' && hasVideo,
    controlChannel,
    start,
    stop,
    handleSignalMessage,
  };
}

