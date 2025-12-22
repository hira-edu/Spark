import React, {useEffect, useMemo, useRef, useState} from 'react';
import {Alert, Button, Card, Space, Spin, Tag, message} from 'antd';
import {ReloadOutlined, VideoCameraOutlined} from '@ant-design/icons';
import {decrypt, encrypt, getBaseURL, hex2ua, str2ua, translate} from "../utils/utils";
import i18n from "../locale/locale";

const defaultIceServers = [
	{urls: 'stun:stun.l.google.com:19302'},
	{urls: 'stun:stun.cloudflare.com:3478'},
];

const MAGIC_PREFIX = [34, 22, 19, 17];
const SERVICE_IDS = [20, 21];
const SERVICE_OP_LENGTH = 2; // service + op
const EVENT_ID_LENGTH = 16;
const FRAME_META_LENGTH = 8; // frameSeq(4) + chunkIndex(2) + chunkTotal(2)
const LEGACY_FRAME_HEADER_LENGTH = MAGIC_PREFIX.length + SERVICE_OP_LENGTH + EVENT_ID_LENGTH; // 22 bytes
const FRAME_HEADER_LENGTH = LEGACY_FRAME_HEADER_LENGTH + FRAME_META_LENGTH; // 30 bytes
const JSON_BODY_OFFSET = MAGIC_PREFIX.length + SERVICE_OP_LENGTH; // 6 bytes

function preferH264Codec(transceiver) {
	if (!transceiver || typeof transceiver.setCodecPreferences !== 'function') return;
	if (typeof RTCRtpReceiver === 'undefined' || typeof RTCRtpReceiver.getCapabilities !== 'function') return;

	const caps = RTCRtpReceiver.getCapabilities('video');
	const codecs = caps?.codecs || [];
	if (!Array.isArray(codecs) || codecs.length === 0) return;

	const h264 = codecs.filter((c) => (c?.mimeType || '').toLowerCase() === 'video/h264');
	if (h264.length === 0) return;

	const rest = codecs.filter((c) => (c?.mimeType || '').toLowerCase() !== 'video/h264');
	try {
		transceiver.setCodecPreferences([...h264, ...rest]);
	} catch (_) {
		// Best-effort only.
	}
}

function Guest() {
	const canvasRef = useRef(null);
	const videoRef = useRef(null);
	const wsRef = useRef(null);
	const headerLenRef = useRef(FRAME_HEADER_LENGTH);
	const messageQueueRef = useRef(Promise.resolve());
	const secretRef = useRef(null);
	const pcRef = useRef(null);
	const dcRef = useRef(null);
	const iceServersRef = useRef(defaultIceServers);
	const inputBufferRef = useRef([]);
	const inputTimerRef = useRef(null);
	const inputAttachedRef = useRef(false);
	const inputActiveRef = useRef(false);
	const focusRef = useRef(false);
	const allowControlRef = useRef(false);
	// Toast spam prevention: track last toast to avoid duplicates within 3 seconds
	const lastToastRef = useRef({ at: 0, msg: '' });

	// Show toast with spam prevention (same message within 3s is suppressed)
	const showToast = (type, msg) => {
		const now = Date.now();
		const last = lastToastRef.current;
		if (last.msg === msg && now - last.at < 3000) return;
		lastToastRef.current = { at: now, msg };
		if (type === 'warning') message.warning(msg);
		else if (type === 'error') message.error(msg);
		else if (type === 'success') message.success(msg);
		else message.info(msg);
	};

	const handleMouseLeave = () => { focusRef.current = false; };
	const handleCanvasFocus = () => { focusRef.current = true; };
	const handleCanvasBlur = () => { focusRef.current = false; };

	const [share, setShare] = useState(null);
	const [status, setStatus] = useState('idle');
	const [error, setError] = useState('');
	const [viewOnly, setViewOnly] = useState(true);
	const [controlEnabled, setControlEnabled] = useState(false);
	const [webrtcState, setWebrtcState] = useState('off');
	const [webrtcEnabled, setWebrtcEnabled] = useState(true);
	const [iceLabel, setIceLabel] = useState('default');
	const [resolution, setResolution] = useState('0x0');

	const token = useMemo(() => new URLSearchParams(window.location.search).get('token') || '', []);

	useEffect(() => {
		if (!token) {
			setError('Missing token');
			return;
		}
		validateToken();
		return () => cleanupAll();
	}, [token]);

	useEffect(() => {
		if (status === 'connecting' && share) {
			startSession();
		}
	}, [status, share]);

	useEffect(() => {
		const enabled = !viewOnly;
		setControlEnabled(enabled);
		allowControlRef.current = enabled;
		if (!enabled) {
			stopInput();
		} else if (status === 'streaming') {
			startInput();
		}
	}, [viewOnly]);

	async function validateToken() {
		setStatus('validating');
		try {
			const res = await fetch(`/api/share/validate?token=${encodeURIComponent(token)}`);
			const data = await res.json();
			if (data.code !== 0) {
				throw new Error(data.msg || 'Invalid token');
			}
			setShare(data.data.share);
			setViewOnly(!!data.data.share?.viewOnly);
			await loadIceConfig();
			setStatus('connecting');
		} catch (e) {
			console.error(e);
			setError(e.message || 'Unable to validate token');
			setStatus('error');
		}
	}

	async function loadIceConfig() {
		try {
			const res = await fetch(`/api/share/ice?token=${encodeURIComponent(token)}`);
			const body = await res.json();
			if (body?.data?.ice) {
				const ice = body.data.ice;
				const headerServers = Array.isArray(ice.ice_servers) ? ice.ice_servers : [];
				if (headerServers.length > 0) {
					iceServersRef.current = headerServers;
					setIceLabel(headerServers.map((s) => Array.isArray(s.urls) ? s.urls.join(',') : s.urls).join(', '));
					return;
				}

				const legacyServers = [];
				(ice.stun || []).forEach((url) => legacyServers.push({urls: url}));
				(ice.turn || []).forEach((url) => legacyServers.push({urls: url}));
				if (legacyServers.length > 0) {
					iceServersRef.current = legacyServers;
					setIceLabel(legacyServers.map((s) => Array.isArray(s.urls) ? s.urls.join(',') : s.urls).join(', '));
					return;
				}
			}
		} catch (err) {
			console.warn('guest ICE fallback', err);
		}
		iceServersRef.current = defaultIceServers;
		setIceLabel('default');
	}

	function cleanupAll() {
		stopInput();
		stopWebRTC();
		if (wsRef.current) {
			try { wsRef.current.close(); } catch (_) {}
		}
		wsRef.current = null;
	}

	function startSession() {
		const canvas = canvasRef.current;
		if (!canvas || !share) return;
		const secretHex = typeof share.secret === 'string' ? share.secret.trim() : '';
		const secretBytes = secretHex ? hex2ua(secretHex) : null;
		if (!secretHex || !secretBytes || secretBytes.length === 0) {
			setError('Share secret missing. Please regenerate the link.');
			setStatus('error');
			return;
		}
		setResolution('0x0');
		stopInput();
		stopWebRTC();
		if (wsRef.current) {
			wsRef.current.close();
		}
		secretRef.current = secretBytes;
		const ctx = canvas.getContext('2d', {alpha: false});
		ctx.imageSmoothingEnabled = false;
		const ws = new WebSocket(getBaseURL(true, `api/share/desktop?token=${encodeURIComponent(token)}&secret=${encodeURIComponent(secretHex.toLowerCase())}`));
		ws.binaryType = 'arraybuffer';
		messageQueueRef.current = Promise.resolve();
		wsRef.current = ws;
		ws.onopen = () => {
			setStatus('streaming');
			sendData({act: 'DESKTOP_SHOT'});
			if (allowControlRef.current) {
				startInput();
			}
			if (webrtcEnabled) {
				startWebRTC();
			}
		};
		ws.onmessage = (e) => {
			messageQueueRef.current = messageQueueRef.current
				.then(() => parseBlocks(e.data, canvas, ctx))
				.catch(() => {});
		};
		ws.onclose = () => {
			stopInput();
			stopWebRTC();
			setStatus('disconnected');
		};
		ws.onerror = (e) => {
			console.error(e);
			stopInput();
			stopWebRTC();
			setStatus('error');
		};
	}

	async function parseBlocks(raw, canvas, canvasCtx) {
		if (!canvas || !canvasCtx || !raw) return;

		let buffer = null;
		if (raw instanceof ArrayBuffer) {
			buffer = raw;
		} else if (raw?.arrayBuffer) {
			buffer = await raw.arrayBuffer();
		}
		if (!buffer) return;

		const bytes = new Uint8Array(buffer);
		if (bytes.length < JSON_BODY_OFFSET) return;
		for (let i = 0; i < MAGIC_PREFIX.length; i++) {
			if (bytes[i] !== MAGIC_PREFIX[i]) return;
		}
		const service = bytes[4];
		if (!SERVICE_IDS.includes(service)) return;

		const op = bytes[5];
		if (webrtcState === 'connected' && op !== 2 && op !== 3) {
			return;
		}

		if (op === 3) {
			await handleJSON(bytes.slice(JSON_BODY_OFFSET));
			return;
		}

		if (bytes.length < LEGACY_FRAME_HEADER_LENGTH) return;
		const view = new DataView(buffer);

		let headerLen = headerLenRef.current || FRAME_HEADER_LENGTH;
		const tryResolutionHeader = (candidateLen) => {
			if (bytes.length < candidateLen + 6) return false;
			const bodyLength = view.getUint16(candidateLen, false);
			return bodyLength === 4 && candidateLen + 2 + bodyLength <= bytes.length;
		};

		const hasPlausibleV2Meta = () => {
			if (bytes.length < FRAME_HEADER_LENGTH) return false;
			const chunkIndex = view.getUint16(LEGACY_FRAME_HEADER_LENGTH + 4, false);
			const chunkTotal = view.getUint16(LEGACY_FRAME_HEADER_LENGTH + 6, false);
			if (chunkTotal === 0 || chunkTotal > 4096) return false;
			if (chunkIndex >= chunkTotal) return false;
			return true;
		};

		const isPlausibleBlockHeader = (candidateOffset) => {
			if (bytes.length < candidateOffset + 12) return false;
			const bodyLen = view.getUint16(candidateOffset, false);
			const imageType = view.getUint16(candidateOffset + 2, false);
			const bw = view.getUint16(candidateOffset + 8, false);
			const bh = view.getUint16(candidateOffset + 10, false);
			if (bodyLen < 10) return false;
			if (candidateOffset + 2 + bodyLen > bytes.length) return false;
			if (imageType > 16) return false;
			if (bw === 0 || bh === 0) return false;
			if (bw > 8192 || bh > 8192) return false;
			return true;
		};

		if (op === 2) {
			if (tryResolutionHeader(FRAME_HEADER_LENGTH)) {
				headerLen = FRAME_HEADER_LENGTH;
			} else if (tryResolutionHeader(LEGACY_FRAME_HEADER_LENGTH)) {
				headerLen = LEGACY_FRAME_HEADER_LENGTH;
			} else {
				return;
			}
			headerLenRef.current = headerLen;
		} else if (op === 0 || op === 1) {
			const v2Candidate = bytes.length >= FRAME_HEADER_LENGTH && hasPlausibleV2Meta() && isPlausibleBlockHeader(FRAME_HEADER_LENGTH);
			const legacyCandidate = isPlausibleBlockHeader(LEGACY_FRAME_HEADER_LENGTH);
			if (v2Candidate && !legacyCandidate) {
				headerLen = FRAME_HEADER_LENGTH;
			} else if (legacyCandidate && !v2Candidate) {
				headerLen = LEGACY_FRAME_HEADER_LENGTH;
			} else if (v2Candidate) {
				headerLen = FRAME_HEADER_LENGTH;
			} else if (legacyCandidate) {
				headerLen = LEGACY_FRAME_HEADER_LENGTH;
			} else {
				return;
			}
			headerLenRef.current = headerLen;
		}

		if (bytes.length < headerLen) return;
		const payloadOffset = headerLen;

		if (op === 2) {
			const bodyLength = view.getUint16(payloadOffset + 0, false);
			if (bodyLength < 4 || payloadOffset + 2 + bodyLength > view.byteLength) {
				return;
			}
			const width = view.getUint16(payloadOffset + 2, false);
			const height = view.getUint16(payloadOffset + 4, false);
			if (width === 0 || height === 0) return;
			if (canvas.width !== width || canvas.height !== height) {
				canvas.width = width;
				canvas.height = height;
				canvasCtx.imageSmoothingEnabled = false;
			}
			setResolution(`${width}x${height}`);
			return;
		}

		let offset = payloadOffset;
		while (offset + 12 <= view.byteLength) {
			const bl = view.getUint16(offset + 0, false); // body length
			const it = view.getUint16(offset + 2, false); // image type
			const dx = view.getUint16(offset + 4, false); // image block x
			const dy = view.getUint16(offset + 6, false); // image block y
			const bw = view.getUint16(offset + 8, false); // image block width
			const bh = view.getUint16(offset + 10, false); // image block height
			const il = bl - 10; // image length
			const dataStart = offset + 12;
			const dataEnd = dataStart + il;
			if (il < 0 || dataEnd > view.byteLength) {
				break;
			}
			updateImage(bytes.subarray(dataStart, dataEnd), it, dx, dy, bw, bh, canvasCtx);
			offset = dataEnd;
		}
	}

	function updateImage(data, it, dx, dy, bw, bh, canvasCtx) {
		if (!data || data.byteLength === 0) return;
		if (it === 0) {
			const clamped = new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength);
			canvasCtx.putImageData(new ImageData(clamped, bw, bh), dx, dy, 0, 0, bw, bh);
			return;
		}
		createImageBitmap(new Blob([data]), {
			premultiplyAlpha: 'none',
			colorSpaceConversion: 'none'
		}).then((ib) => {
			canvasCtx.drawImage(ib, 0, 0, ib.width || bw, ib.height || bh, dx, dy, bw, bh);
			if (typeof ib.close === 'function') {
				ib.close();
			}
		}).catch(() => {});
	}

	async function handleJSON(ab) {
		const secret = secretRef.current;
		if (!secret) return;
		let data;
		try {
			const decrypted = await decrypt(ab, secret);
			data = JSON.parse(decrypted);
		} catch (_) {
			return;
		}
		try {
			if (data?.act === 'DESKTOP_WEBRTC_ANSWER') {
				if (data.code && data.code !== 0) {
					showToast('warning', data.msg ? translate(data.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
					stopWebRTC();
					return;
				}
				handleRTCAnswer(data.data || data);
				return;
			}
			if (data?.act === 'DESKTOP_WEBRTC_ICE') {
				if (data.code && data.code !== 0) {
					return;
				}
				handleRTCCandidate(data.data || data);
				return;
			}
			if (data?.act === 'DESKTOP_INPUT' && data.code && data.code !== 0) {
				showToast('warning', data.msg ? translate(data.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
				return;
			}
			if (data?.act === 'WARN') {
				showToast('warning', data.msg ? translate(data.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
				return;
			}
			if (data?.act === 'QUIT') {
				showToast('warning', data.msg ? translate(data.msg) : i18n.t('DESKTOP.SESSION_CLOSED'));
				setStatus('disconnected');
				cleanupAll();
			}
		} catch (_) {
			// ignore malformed payloads
		}
	}

	async function sendData(body) {
		const ws = wsRef.current;
		if (!ws || ws.readyState !== WebSocket.OPEN || !secretRef.current) {
			return;
		}

		const encrypted = await encrypt(str2ua(JSON.stringify(body)), secretRef.current);
		const payload = encrypted instanceof Uint8Array ? encrypted : new Uint8Array(encrypted);
		const buffer = new Uint8Array(payload.length + 8);

		buffer.set(new Uint8Array([34, 22, 19, 17, 20, 3]), 0);
		buffer.set(new Uint8Array([payload.length >> 8, payload.length & 0xFF]), 6);
		buffer.set(payload, 8);
		ws.send(buffer);
	}

	async function startWebRTC() {
		const ws = wsRef.current;
		if (!ws || ws.readyState !== WebSocket.OPEN) {
			return;
		}
		stopWebRTC();
		setWebrtcState('connecting');
		const pc = new RTCPeerConnection({iceServers: iceServersRef.current});
		pcRef.current = pc;

		const transceiver = pc.addTransceiver('video', {direction: 'recvonly'});
		preferH264Codec(transceiver);

		// Offerer-created data channel so the SDP includes m=application.
		const dc = pc.createDataChannel('desktop-input', {ordered: true});
		dcRef.current = dc;
		dc.onclose = () => {
			if (dcRef.current === dc) {
				dcRef.current = null;
			}
		};
		dc.onerror = (err) => console.error('guest data channel', err);

		pc.onicecandidate = (e) => {
			if (e.candidate) {
				sendData({
					act: 'DESKTOP_WEBRTC_ICE',
					data: {
						candidate: e.candidate.candidate,
						sdpMid: e.candidate.sdpMid,
						mLine: e.candidate.sdpMLineIndex
					}
				});
			}
		};
		pc.onconnectionstatechange = () => {
			const state = pc.connectionState;
			if (state === 'connected') {
				setWebrtcState('connected');
				sendData({act: 'DESKTOP_CONFIG', data: {transport: 'webrtc'}});
			}
			if (state === 'failed' || state === 'disconnected' || state === 'closed') {
				stopWebRTC();
			}
		};
		pc.ontrack = (e) => {
			const target = videoRef.current;
			if (!target) return;
			const stream = e.streams && e.streams[0] ? e.streams[0] : new MediaStream([e.track]);
			if (target.srcObject !== stream) {
				target.srcObject = stream;
				const p = target.play?.();
				if (p && typeof p.catch === 'function') {
					p.catch(() => {});
				}
			}
		};

		try {
			const offer = await pc.createOffer();
			await pc.setLocalDescription(offer);
			await sendData({
				act: 'DESKTOP_WEBRTC_OFFER',
				data: {
					sdp: offer.sdp,
					type: offer.type,
					role: 'guest'
				}
			});
		} catch (err) {
			console.error('guest offer failed', err);
			stopWebRTC();
		}
	}

	function stopWebRTC() {
		setWebrtcState('off');
		sendData({act: 'DESKTOP_CONFIG', data: {transport: 'tiles'}});
		if (dcRef.current) {
			try { dcRef.current.close(); } catch (_) {}
		}
		if (pcRef.current) {
			try { pcRef.current.close(); } catch (_) {}
		}
		dcRef.current = null;
		pcRef.current = null;
		if (videoRef.current && videoRef.current.srcObject) {
			videoRef.current.srcObject = null;
		}
	}

	function handleRTCAnswer(data) {
		if (!pcRef.current || !data?.sdp) return;
		pcRef.current.setRemoteDescription({
			type: data.type || 'answer',
			sdp: data.sdp
		}).catch((err) => console.error('guest set answer failed', err));
	}

	function handleRTCCandidate(data) {
		if (!pcRef.current || !data?.candidate) return;
		pcRef.current.addIceCandidate({
			candidate: data.candidate,
			sdpMid: data.sdpMid,
			sdpMLineIndex: data.mLine ?? data.sdpMLineIndex
		}).catch((err) => console.error('guest add ice failed', err));
	}

	function queueInput(event) {
		if (!allowControlRef.current || !inputActiveRef.current) return;
		const buffer = inputBufferRef.current;
		if (buffer.length >= 32) {
			buffer.shift();
		}
		buffer.push(event);
	}

	function flushInputBuffer() {
		if (!allowControlRef.current || !inputActiveRef.current) {
			return;
		}
		const buffer = inputBufferRef.current;
		if (buffer.length === 0) return;
		if (dcRef.current && dcRef.current.readyState === 'open') {
			try {
				dcRef.current.send(JSON.stringify({events: buffer}));
				inputBufferRef.current = [];
				return;
			} catch (err) {
				console.warn('guest data channel send failed', err);
			}
		}
		sendData({act: 'DESKTOP_INPUT', data: {events: buffer}});
		inputBufferRef.current = [];
	}

	function startInput() {
		const canvas = canvasRef.current;
		if (!canvas || inputAttachedRef.current) return;
		inputActiveRef.current = true;
		canvas.addEventListener('mousemove', handleMouseMove);
		canvas.addEventListener('mousedown', handleMouseDown);
		canvas.addEventListener('mouseup', handleMouseUp);
		canvas.addEventListener('wheel', handleWheel, {passive: false});
		canvas.addEventListener('mouseleave', handleMouseLeave);
		canvas.addEventListener('focus', handleCanvasFocus);
		canvas.addEventListener('blur', handleCanvasBlur);
		window.addEventListener('keydown', handleKeyDown);
		window.addEventListener('keyup', handleKeyUp);
		inputAttachedRef.current = true;
		if (!inputTimerRef.current) {
			inputTimerRef.current = setInterval(flushInputBuffer, 16);
		}
	}

	function stopInput() {
		const canvas = canvasRef.current;
		inputActiveRef.current = false;
		inputBufferRef.current = [];
		if (canvas && inputAttachedRef.current) {
			canvas.removeEventListener('mousemove', handleMouseMove);
			canvas.removeEventListener('mousedown', handleMouseDown);
			canvas.removeEventListener('mouseup', handleMouseUp);
			canvas.removeEventListener('wheel', handleWheel, {passive: false});
			canvas.removeEventListener('mouseleave', handleMouseLeave);
			canvas.removeEventListener('focus', handleCanvasFocus);
			canvas.removeEventListener('blur', handleCanvasBlur);
		}
		window.removeEventListener('keydown', handleKeyDown);
		window.removeEventListener('keyup', handleKeyUp);
		inputAttachedRef.current = false;
		if (inputTimerRef.current) {
			clearInterval(inputTimerRef.current);
			inputTimerRef.current = null;
		}
	}

	function handleMouseMove(e) {
		if (!allowControlRef.current || !inputActiveRef.current) return;
		const canvas = canvasRef.current;
		if (!canvas) return;
		const rect = canvas.getBoundingClientRect();
		if (!rect.width || !rect.height) return;
		const x = clamp(Math.round(((e.clientX - rect.left) / rect.width) * canvas.width), 0, canvas.width - 1);
		const y = clamp(Math.round(((e.clientY - rect.top) / rect.height) * canvas.height), 0, canvas.height - 1);
		queueInput({type: 'move', x, y});
	}

	function handleMouseDown(e) {
		if (!allowControlRef.current || !inputActiveRef.current) return;
		focusRef.current = true;
		const buttons = ['left', 'middle', 'right'];
		queueInput({type: 'button', button: buttons[e.button] || 'left', down: true});
	}

	function handleMouseUp(e) {
		if (!allowControlRef.current || !inputActiveRef.current) return;
		const buttons = ['left', 'middle', 'right'];
		queueInput({type: 'button', button: buttons[e.button] || 'left', down: false});
	}

	function handleWheel(e) {
		if (!allowControlRef.current || !inputActiveRef.current) return;
		e.preventDefault();
		queueInput({
			type: 'scroll',
			deltaX: Math.trunc(e.deltaX),
			deltaY: Math.trunc(e.deltaY)
		});
	}

	function handleKeyDown(e) {
		if (!allowControlRef.current || !inputActiveRef.current || !focusRef.current) return;
		e.preventDefault();
		queueInput({type: 'key', key: e.key, keyCode: e.keyCode || e.which || 0, down: true});
	}

	function handleKeyUp(e) {
		if (!allowControlRef.current || !inputActiveRef.current || !focusRef.current) return;
		e.preventDefault();
		queueInput({type: 'key', key: e.key, keyCode: e.keyCode || e.which || 0, down: false});
	}

	function clamp(val, min, max) {
		if (val < min) return min;
		if (val > max) return max;
		return val;
	}

	if (!token) {
		return <Alert type='error' message='Token missing' />;
	}

	return (
		<div style={{maxWidth: 1200, margin: '20px auto', padding: '0 12px'}}>
			<Card
				title='Guest Desktop'
				extra={(
					<Space>
						{share && <Tag color='blue'>{share.device}</Tag>}
						<Tag color={viewOnly ? 'gold' : 'green'}>
							{viewOnly ? (i18n.t('COMMON.READ_ONLY') || 'View-only') : (i18n.t('COMMON.CONTROL') || 'Control enabled')}
						</Tag>
					</Space>
				)}
			>
				{error && <Alert type='error' message={error} style={{marginBottom: 12}} />}
				{!error && status === 'validating' && <Spin tip='Validating token...' />}
				<div style={{position: 'relative', minHeight: 420}}>
					<video
						ref={videoRef}
						style={{
							position: 'absolute',
							inset: 0,
							width: '100%',
							height: '100%',
							objectFit: 'contain',
							pointerEvents: 'none',
							display: webrtcState === 'connected' ? 'block' : 'none',
							background: '#000'
						}}
						muted
						playsInline
						autoPlay
					/>
					<canvas
						ref={canvasRef}
						tabIndex={0}
						style={{
							width: '100%',
							height: '100%',
							background: '#0f131a',
							visibility: webrtcState === 'connected' ? 'hidden' : 'visible'
						}}
					/>
				</div>
				<div style={{marginTop: 12, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap'}}>
					<Tag color={status === 'streaming' ? 'green' : status === 'error' ? 'red' : 'orange'}>
						{status}
					</Tag>
					<Tag color={webrtcState === 'connected' ? 'green' : webrtcState === 'connecting' ? 'blue' : 'default'}>
						WebRTC: {webrtcState}
					</Tag>
					<Tag color='default'>ICE: {iceLabel}</Tag>
					<Tag color='default'>Res: {resolution}</Tag>
					<Button
						icon={<ReloadOutlined />}
						onClick={startSession}
						disabled={!share}
					>
						{i18n.t('COMMON.REFRESH')}
					</Button>
					<Button
						icon={<VideoCameraOutlined />}
						type={webrtcState === 'connected' ? 'primary' : 'default'}
						onClick={() => {
							setWebrtcEnabled((prev) => {
								const next = !prev;
								if (!next) {
									stopWebRTC();
								} else if (status === 'streaming') {
									startWebRTC();
								}
								return next;
							});
						}}
					>
						{webrtcState === 'connected' ? 'Disable WebRTC' : 'Enable WebRTC'}
					</Button>
					<Button
						disabled={viewOnly}
						type={controlEnabled ? 'primary' : 'default'}
						onClick={() => {
							if (viewOnly) return;
							setControlEnabled((prev) => {
								const next = !prev;
								allowControlRef.current = next;
								if (next && status === 'streaming') {
									startInput();
								} else {
									stopInput();
								}
								return next;
							});
						}}
					>
						{controlEnabled ? (i18n.t('COMMON.CONTROL') || 'Control on') : (i18n.t('COMMON.READ_ONLY') || 'Control off')}
					</Button>
				</div>
			</Card>
		</div>
	);
}

export default Guest;
