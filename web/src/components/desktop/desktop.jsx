import React, {useCallback, useEffect, useRef, useState} from 'react';
import {encrypt, decrypt, formatSize, genRandHex, getBaseURL, translate, str2ua, hex2ua, ua2hex} from "../../utils/utils";
import i18n from "../../locale/locale";
import DraggableModal from "../modal";
import {Alert, Button, Modal, message, Select, Switch} from "antd";
import {FullscreenOutlined, ReloadOutlined} from "@ant-design/icons";

let ws = null;
let ctx = null;
let conn = false;
let canvas = null;
let secret = null;
let ticker = 0;
let frames = 0;
let bytes = 0;
let ticks = 0;
let title = i18n.t('DESKTOP.TITLE');
function ScreenModal(props) {
	const [resolution, setResolution] = useState('0x0');
	const [bandwidth, setBandwidth] = useState(0);
	const [fps, setFps] = useState(0);
	const [caps, setCaps] = useState(null);
	const [policyState, setPolicyState] = useState(null);
	const [webrtcSignal, setWebrtcSignal] = useState(null);
	const [webrtcState, setWebrtcState] = useState('idle');
	const [webrtcError, setWebrtcError] = useState(null);
	const [webrtcOptIn, setWebrtcOptIn] = useState(true);
	const [agentStats, setAgentStats] = useState(null);
	const [monitors, setMonitors] = useState([]);
	const [selectedMonitor, setSelectedMonitor] = useState(null);
	const [monitorLoading, setMonitorLoading] = useState(false);
	const [qualityPresets, setQualityPresets] = useState([]);
	const [qualityKey, setQualityKey] = useState(null);
	const [qualityLoading, setQualityLoading] = useState(false);
	const [controlEnabled, setControlEnabled] = useState(false);
	const [controlConsentGiven, setControlConsentGiven] = useState(false);
	const [pointerLockSupported, setPointerLockSupported] = useState(false);
	const [pointerLockActive, setPointerLockActive] = useState(false);
	const [clipboardLoading, setClipboardLoading] = useState(false);
	const [clipboardAvailable, setClipboardAvailable] = useState(false);
	const [clipboardSyncEnabled, setClipboardSyncEnabled] = useState(true);
	const [secureHotkeyLoading, setSecureHotkeyLoading] = useState(false);
	const [secureHotkeyDropdownKey, setSecureHotkeyDropdownKey] = useState(0);
	const [policyAlerts, setPolicyAlerts] = useState([]);
	const [policyIssueFlags, setPolicyIssueFlags] = useState({});
	const [forceInputLoading, setForceInputLoading] = useState(false);
	const [forceCaptureLoading, setForceCaptureLoading] = useState(false);
	const pcRef = useRef(null);
	const webrtcVideoRef = useRef(null);
	const webrtcOfferSentRef = useRef(false);
	const dataChannelRef = useRef(null);
	const getPolicyBlockMessage = () => i18n.t('DESKTOP.CONTROL_DISABLED_POLICY') || 'Remote input disabled by policy.';
	const lastMoveRef = useRef(null);
	const moveFrame = useRef(null);
	const pointerVirtualRef = useRef(null);
	const lastCoordsRef = useRef(null);
	const canvasRef = useCallback((e) => {
		if (e && props.open && !conn && !canvas) {
			secret = hex2ua(genRandHex(32));
			canvas = e;
			initCanvas(canvas);
			construct(canvas);
			pointerVirtualRef.current = null;
			lastCoordsRef.current = null;
		}
	}, [props]);
useEffect(() => {
	if (!props.open) {
			teardownWebRTC();
			if (typeof document !== 'undefined' && document.pointerLockElement && document.pointerLockElement === canvas) {
				document.exitPointerLock().catch(() => {});
			}
			setClipboardSyncEnabled(true);
			setSecureHotkeyLoading(false);
			setSecureHotkeyDropdownKey((prev) => prev + 1);
			setControlConsentGiven(false);
			setCaps(null);
			setPolicyState(null);
			setWebrtcSignal(null);
			setWebrtcState('idle');
			setWebrtcError(null);
			setWebrtcOptIn(true);
			setMonitors([]);
			setSelectedMonitor(null);
			setMonitorLoading(false);
			setQualityPresets([]);
			setQualityKey(null);
			setQualityLoading(false);
			setAgentStats(null);
			setPolicyAlerts([]);
			setPolicyIssueFlags({});
			setForceInputLoading(false);
			setForceCaptureLoading(false);
			canvas = null;
			if (ws && conn) {
				clearInterval(ticker);
				ws.close();
				conn = false;
			}
	}
}, [props.open]);

useEffect(() => {
	if (typeof document === 'undefined') return;
	setPointerLockSupported(typeof document.body?.requestPointerLock === 'function');
}, []);

useEffect(() => {
	if (!props.open || !webrtcAvailable || !webrtcOptIn) {
		teardownWebRTC();
		return;
	}
	let cancelled = false;
	(async () => {
		try {
			await startWebRTCSession();
		} catch (err) {
			if (!cancelled) {
				teardownWebRTC(err?.message || 'WebRTC initialization failed.');
			}
		}
	})();
	return () => {
		cancelled = true;
	};
}, [props.open, webrtcAvailable, webrtcOptIn]);

useEffect(() => {
	if (typeof document === 'undefined' || !canvas) return;
	const handleChange = () => {
		const locked = document.pointerLockElement === canvas;
		setPointerLockActive(locked);
		if (!locked) {
			pointerVirtualRef.current = lastCoordsRef.current;
		} else if (!pointerVirtualRef.current && canvas) {
			pointerVirtualRef.current = lastCoordsRef.current || {x: canvas.width / 2, y: canvas.height / 2};
		}
	};
	const handleError = () => {
		setPointerLockActive(false);
		message.error(i18n.t('DESKTOP.POINTER_LOCK_FAILED') || 'Pointer lock failed.');
	};
	document.addEventListener('pointerlockchange', handleChange);
	document.addEventListener('pointerlockerror', handleError);
	return () => {
		document.removeEventListener('pointerlockchange', handleChange);
		document.removeEventListener('pointerlockerror', handleError);
	};
}, [canvas]);

useEffect(() => {
	if (!canvas || !controlEnabled) return;
		const handleMouseDown = (evt) => {
			evt.preventDefault();
			const payload = buildPointerPayload(evt, {action: 'down', button: evt.button});
			if (!payload) return;
			lastMoveRef.current = payload;
			sendInputEvent(payload);
		};
		const handleMouseUp = (evt) => {
			evt.preventDefault();
			const payload = buildPointerPayload(evt, {action: 'up', button: evt.button});
			if (!payload) return;
			sendInputEvent(payload);
		};
		const handleMouseMove = (evt) => {
			if (!controlEnabled) return;
			const payload = buildPointerPayload(evt, {action: 'move'});
			if (!payload) return;
			lastMoveRef.current = payload;
			if (!moveFrame.current) {
				moveFrame.current = requestAnimationFrame(() => {
					if (lastMoveRef.current) {
						sendInputEvent(lastMoveRef.current);
					}
					lastMoveRef.current = null;
					moveFrame.current = null;
				});
			}
		};
		const handleWheel = (evt) => {
			evt.preventDefault();
			const payload = buildPointerPayload(evt, {
				action: 'wheel',
				deltaY: evt.deltaY,
				normalizeOptions: {skipMovementUpdate: true}
			});
			if (!payload) return;
			sendInputEvent(payload);
		};
		canvas.addEventListener('mousedown', handleMouseDown);
		canvas.addEventListener('mouseup', handleMouseUp);
		canvas.addEventListener('mousemove', handleMouseMove);
		canvas.addEventListener('wheel', handleWheel, {passive: false});
		return () => {
			canvas.removeEventListener('mousedown', handleMouseDown);
			canvas.removeEventListener('mouseup', handleMouseUp);
			canvas.removeEventListener('mousemove', handleMouseMove);
			canvas.removeEventListener('wheel', handleWheel);
			if (moveFrame.current) {
				cancelAnimationFrame(moveFrame.current);
				moveFrame.current = null;
			}
			lastMoveRef.current = null;
	};
}, [canvas, controlEnabled]);

useEffect(() => {
	if (!controlEnabled) return;
	const blockedTags = ['INPUT', 'TEXTAREA', 'SELECT'];
	const handleKey = (evt) => {
		if (!controlEnabled) return;
		const target = evt.target;
		if (target && blockedTags.includes(target.tagName)) {
			return;
		}
		evt.preventDefault();
		evt.stopPropagation();
		sendInputEvent({
			type: 'keyboard',
			action: evt.type === 'keydown' ? 'down' : 'up',
			key: evt.key,
			code: evt.code,
			keyCode: evt.keyCode,
			altKey: evt.altKey,
			ctrlKey: evt.ctrlKey,
			shiftKey: evt.shiftKey,
			metaKey: evt.metaKey,
			repeat: evt.repeat,
			location: evt.location,
			timestamp: Date.now()
		});
	};
	window.addEventListener('keydown', handleKey, true);
	window.addEventListener('keyup', handleKey, true);
	return () => {
		window.removeEventListener('keydown', handleKey, true);
		window.removeEventListener('keyup', handleKey, true);
	};
}, [controlEnabled]);

useEffect(() => {
	if (typeof document === 'undefined') return;
	if (!controlEnabled && document.pointerLockElement === canvas) {
		document.exitPointerLock().catch(() => {});
	}
}, [controlEnabled]);

	useEffect(() => {
		if (!policyState) return;
		if (policyState.inputEnabled === false && controlEnabled) {
			setControlEnabled(false);
			message.info(getPolicyBlockMessage());
		}
	}, [policyState, controlEnabled]);

useEffect(() => {
	if (typeof document === 'undefined') return;
	if (!controlEnabled && document.pointerLockElement === canvas) {
		document.exitPointerLock().catch(() => {});
	}
}, [controlEnabled]);

	function initCanvas() {
		if (!canvas) return;
		ctx = canvas.getContext('2d', {alpha: false});
		ctx.imageSmoothingEnabled = false;
	}
	function construct() {
		if (ctx !== null) {
			if (ws !== null && conn) {
				ws.close();
			}
			ws = new WebSocket(getBaseURL(true, `api/device/desktop?device=${props.device.id}&secret=${ua2hex(secret)}`));
			ws.binaryType = 'arraybuffer';
			ws.onopen = () => {
				conn = true;
				requestMonitors();
			}
			ws.onmessage = (e) => {
				parseBlocks(e.data, canvas, ctx);
			};
			ws.onclose = () => {
				if (conn) {
					conn = false;
					message.warn(i18n.t('COMMON.DISCONNECTED'));
				}
			};
			ws.onerror = (e) => {
				console.error(e);
				if (conn) {
					conn = false;
					message.warn(i18n.t('COMMON.DISCONNECTED'));
				} else {
					message.warn(i18n.t('COMMON.CONNECTION_FAILED'));
				}
			};
			clearInterval(ticker);
			ticker = setInterval(() => {
				setBandwidth(bytes);
				setFps(frames);
				bytes = 0;
				frames = 0;
				ticks++;
				if (ticks > 10 && conn) {
					ticks = 0;
					sendData({
						act: 'DESKTOP_PING'
					});
				}
			}, 1000);
		}
	}
	function fullScreen() {
		canvas.requestFullscreen().catch(console.error);
	}
	function refresh() {
		if (canvas && props.open) {
			if (!conn) {
				initCanvas(canvas);
				construct(canvas);
			} else {
				sendData({
					act: 'DESKTOP_SHOT'
				});
			}
		}
	}

	function requestMonitors() {
		if (!conn) return;
		setMonitorLoading(true);
		sendData({
			act: 'DESKTOP_MONITORS'
		});
	}

	function handleMonitorChange(value) {
		if (!conn) return;
		setMonitorLoading(true);
		setSelectedMonitor(value);
		sendData({
			act: 'DESKTOP_SET_MONITOR',
			index: value
		});
	}

	function handleQualityChange(value) {
		if (!conn) return;
		setQualityLoading(true);
		setQualityKey(value);
		sendData({
			act: 'DESKTOP_SET_QUALITY',
			preset: value
		});
	}

	function toggleControl() {
		if (policyState && policyState.inputEnabled === false) {
			message.warning(getPolicyBlockMessage());
			return;
		}
		if (!controlEnabled && !controlConsentGiven) {
			showControlConsentDialog();
			return;
		}
		const next = !controlEnabled;
		updateControlState(next);
	}

	function showControlConsentDialog() {
		Modal.confirm({
			title: i18n.t('DESKTOP.CONTROL_CONSENT_TITLE') || 'Enable Remote Control?',
			content: i18n.t('DESKTOP.CONTROL_CONSENT_DESC') || 'Remote input lets you move the mouse and type on the remote device. Only continue if you have authorization.',
			okText: i18n.t('DESKTOP.CONTROL_CONSENT_OK') || 'Enable Control',
			cancelText: i18n.t('COMMON.CANCEL') || 'Cancel',
			onOk: () => {
				setControlConsentGiven(true);
				updateControlState(true);
			},
		});
	}

	function updateControlState(next) {
		setControlEnabled(next);
		sendData({
			act: 'DESKTOP_CONTROL',
			enabled: next
		});
		if (next) {
			message.success(i18n.t('DESKTOP.CONTROL_ENABLED') || 'Control enabled');
		} else {
			message.info(i18n.t('DESKTOP.CONTROL_DISABLED') || 'Control disabled');
		}
	}

	function sendInputEvent(payload) {
		if (!conn || !controlEnabled) return;
		sendData({
			act: 'DESKTOP_INPUT',
			payload
		});
	}

	function normalizeCoords(evt, options = {}) {
		if (!canvas) return null;
		const doc = typeof document !== 'undefined' ? document : null;
		const rect = canvas.getBoundingClientRect();
		const scaleX = canvas.width / rect.width;
		const scaleY = canvas.height / rect.height;
		const locked = !!doc && doc.pointerLockElement === canvas;
		if (locked) {
			if (!pointerVirtualRef.current) {
				pointerVirtualRef.current = lastCoordsRef.current || {x: canvas.width / 2, y: canvas.height / 2};
			}
			if (!options.skipMovementUpdate) {
				const moveX = typeof evt.movementX === 'number' ? evt.movementX : 0;
				const moveY = typeof evt.movementY === 'number' ? evt.movementY : 0;
				pointerVirtualRef.current = {
					x: clamp(pointerVirtualRef.current.x + moveX * scaleX, 0, canvas.width),
					y: clamp(pointerVirtualRef.current.y + moveY * scaleY, 0, canvas.height),
				};
			}
			const lockedX = Math.round(pointerVirtualRef.current.x);
			const lockedY = Math.round(pointerVirtualRef.current.y);
			lastCoordsRef.current = {x: lockedX, y: lockedY};
			return {x: lockedX, y: lockedY};
		}
		const x = clamp((evt.clientX - rect.left) * scaleX, 0, canvas.width);
		const y = clamp((evt.clientY - rect.top) * scaleY, 0, canvas.height);
		const coords = {x: Math.round(x), y: Math.round(y)};
		lastCoordsRef.current = coords;
		pointerVirtualRef.current = coords;
		return coords;
	}

	function clamp(value, min, max) {
		return Math.max(min, Math.min(max, value));
	}

	function buildPointerPayload(evt, overrides = {}) {
		const normalizeOptions = overrides.normalizeOptions || {};
		const coords = normalizeCoords(evt, normalizeOptions);
		if (!coords) return null;
		const buttonValue = typeof overrides.button === 'number' ? overrides.button : evt.button;
		const clicksOverride = overrides.clicks;
		return {
			type: 'mouse',
			action: overrides.action || 'move',
			button: typeof buttonValue === 'number' ? buttonValue : 0,
			buttons: typeof evt.buttons === 'number' ? evt.buttons : 0,
			clicks: typeof clicksOverride === 'number' ? clicksOverride : (typeof evt.detail === 'number' && evt.detail > 0 ? evt.detail : 1),
			deltaY: typeof overrides.deltaY === 'number' ? overrides.deltaY : (typeof evt.deltaY === 'number' ? evt.deltaY : 0),
			x: coords.x,
			y: coords.y,
			altKey: !!evt.altKey,
			ctrlKey: !!evt.ctrlKey,
			shiftKey: !!evt.shiftKey,
			metaKey: !!evt.metaKey,
			timestamp: Date.now(),
		};
	}

	function togglePointerLock() {
		if (!pointerLockSupported || !canvas) return;
		if (typeof document === 'undefined') return;
		if (document.pointerLockElement === canvas) {
			document.exitPointerLock().catch(() => {});
		} else {
			canvas.requestPointerLock();
		}
	}

	function handleSecureHotkeySelect(value) {
		if (!value || secureHotkeyLoading || !controlEnabled) return;
		sendSecureHotkeyRequest(value);
		setSecureHotkeyDropdownKey((prev) => prev + 1);
	}

	function sendSecureHotkeyRequest(sequence) {
		if (!conn) return;
		setSecureHotkeyLoading(true);
		sendData({
			act: 'DESKTOP_SECURE_HOTKEY',
			sequence
		});
	}

	function policyIssueCopy(flags) {
		const copy = {};
		Object.keys(flags || {}).forEach((key) => {
			copy[key] = {...flags[key]};
		});
		return copy;
	}

	function dismissPolicyAlert(id) {
		if (!id) return;
		setPolicyAlerts((prev) => prev.filter((alert) => alert.id !== id));
	}

	function dismissPolicyIssue(category) {
		if (!category) return;
		setPolicyIssueFlags((prev) => {
			if (!prev || !prev[category]) return prev;
			const next = policyIssueCopy(prev);
			next[category].active = false;
			next[category].dismissedAt = Date.now();
			return next;
		});
	}

	function activatePolicyIssue(category, timestamp) {
		if (!category) return;
		setPolicyIssueFlags((prev) => {
			const next = policyIssueCopy(prev || {});
			next[category] = {
				...(next[category] || {}),
				active: true,
				timestamp: timestamp || Date.now(),
			};
			return next;
		});
	}

	function getPolicyIssueContent(category) {
		const key = String(category || '').toLowerCase();
		if (key === 'display_protection') {
			return {
				type: 'warning',
				title: i18n.t('DESKTOP.POLICY_DISPLAY_PROTECTION') || 'Remote app is hiding the screen.',
				description: i18n.t('DESKTOP.POLICY_DISPLAY_PROTECTION_DESC') || 'Local screen privacy (SetWindowDisplayAffinity) is hiding the session. Request Force Capture or have the remote user relax the policy.',
			};
		}
		if (key === 'input_block') {
			return {
				type: 'error',
				title: i18n.t('DESKTOP.POLICY_INPUT_BLOCKED') || 'Remote input blocked by policy.',
				description: i18n.t('DESKTOP.POLICY_INPUT_BLOCKED_DESC') || 'Local controls (BlockInput/filter drivers) are rejecting keyboard/mouse events. Use Force Input if authorized or continue in view-only mode.',
			};
		}
		return {
			type: 'info',
			title: i18n.t('DESKTOP.POLICY_ALERT_GENERIC') || 'Desktop policy alert',
			description: '',
		};
	}

	function handlePolicyAlert(packet) {
		const payload = packet?.data || packet || {};
		const timestamp = typeof payload.timestamp === 'number' ? payload.timestamp : Date.now();
		const funcName = payload.func || payload.function || '';
		const severity = (payload.severity || payload.level || '').toString().toLowerCase();
		let alertType = 'warning';
		if (severity === 'error' || severity === 'critical' || severity === 'danger') {
			alertType = 'error';
		} else if (severity === 'info' || severity === 'information') {
			alertType = 'info';
		} else if (severity === 'success' || severity === 'ok') {
			alertType = 'success';
		}
		const detailParts = [];
		if (payload.detail) {
			detailParts.push(String(payload.detail));
		}
		if (payload.pid) {
			detailParts.push(`PID: ${payload.pid}`);
		}
		if (payload.user) {
			detailParts.push(`User: ${payload.user}`);
		}
		if (payload.sid) {
			detailParts.push(`SID: ${payload.sid}`);
		}
			if (payload.session) {
				detailParts.push(`Session: ${payload.session}`);
			}
			if (payload.category) {
				detailParts.push(`Category: ${payload.category}`);
			}
			if (payload.source) {
				detailParts.push(`Source: ${payload.source}`);
			}
		if (timestamp) {
			try {
				detailParts.push(new Date(timestamp).toLocaleTimeString());
			} catch (_) {}
		}
		if (payload.category) {
			activatePolicyIssue(String(payload.category), timestamp);
		}
		const label = payload.message || payload.msg || (funcName ? `${funcName} blocked by native policy` : (i18n.t('DESKTOP.POLICY_ALERT_GENERIC') || 'Desktop policy alert'));
		const entry = {
			id: `${payload.desktop || 'desktop'}-${timestamp}-${genRandHex(6)}`,
			message: label,
			description: detailParts.length ? detailParts.join(' • ') : null,
			type: alertType,
			timestamp,
		};
		setPolicyAlerts((prev) => {
			const next = [entry, ...prev];
			return next.slice(0, 4);
		});
		const notify = alertType === 'error' ? message.error : (alertType === 'info' ? message.info : (alertType === 'success' ? message.success : message.warning));
		notify(label);
	}

	function handlePolicyForceResponse(packet) {
		setForceInputLoading(false);
		setForceCaptureLoading(false);
		if (packet?.code && packet.code !== 0) {
			message.error(packet?.msg || i18n.t('COMMON.UNKNOWN_ERROR') || 'Policy override failed.');
			return;
		}
		const payload = packet?.data || {};
		const notices = [];
		if (typeof payload.forceInput === 'boolean') {
			notices.push(payload.forceInput ? (i18n.t('DESKTOP.POLICY_FORCE_INPUT_ON') || 'Force input enabled.') : (i18n.t('DESKTOP.POLICY_FORCE_INPUT_OFF') || 'Force input disabled.'));
		}
		if (typeof payload.forceCapture === 'boolean') {
			notices.push(payload.forceCapture ? (i18n.t('DESKTOP.POLICY_FORCE_CAPTURE_ON') || 'Force capture enabled.') : (i18n.t('DESKTOP.POLICY_FORCE_CAPTURE_OFF') || 'Force capture disabled.'));
		}
		const fallback = i18n.t('DESKTOP.POLICY_FORCE_APPLIED') || 'Policy overrides updated.';
		message.success(notices.length ? notices.join(' | ') : fallback);
	}

	function requestPolicyForce(kind, nextValue) {
		if (!policyState || !policyState.connectionId) {
			message.info(i18n.t('DESKTOP.POLICY_OVERRIDE_UNAVAILABLE') || 'Policy overrides unavailable.');
			return;
		}
		if (!conn) {
			message.warn(i18n.t('COMMON.DISCONNECTED') || 'Session disconnected');
			return;
		}
		if (typeof nextValue !== 'boolean') {
			return;
		}
		const payload = {act: 'DESKTOP_POLICY_FORCE'};
		if (kind === 'input') {
			payload.forceInput = nextValue;
			setForceInputLoading(true);
		} else if (kind === 'capture') {
			payload.forceCapture = nextValue;
			setForceCaptureLoading(true);
		} else {
			return;
		}
		sendData(payload);
	}

	function toggleClipboardSync() {
		if (!clipboardAvailable) {
			message.info(i18n.t('DESKTOP.CLIPBOARD_UNAVAILABLE') || 'Clipboard sync unavailable on this device.');
			return;
		}
		setClipboardSyncEnabled((prev) => !prev);
	}

	function toggleWebRTCOptIn(checked) {
		setWebrtcOptIn(checked);
		if (!checked) {
			teardownWebRTC();
			message.info(i18n.t('DESKTOP.WEBRTC_DISABLED') || 'WebRTC beta disabled for this session.');
		} else if (props.open && webrtcAvailable) {
			startWebRTCSession().catch(() => {
				/* error surfaced inside startWebRTCSession */
			});
		}
	}

	function buildPeerConnectionConfig() {
		const config = {};
		if (caps?.webrtc?.config) {
			return caps.webrtc.config;
		}
		if (Array.isArray(caps?.webrtc?.iceServers)) {
			config.iceServers = caps.webrtc.iceServers;
			return config;
		}
		if (typeof window !== 'undefined') {
			if (window.SPARK_WEBRTC_PEER_CONFIG) {
				return window.SPARK_WEBRTC_PEER_CONFIG;
			}
			if (window.SPARK_WEBRTC_ICE) {
				try {
					const servers = typeof window.SPARK_WEBRTC_ICE === 'string'
						? JSON.parse(window.SPARK_WEBRTC_ICE)
						: window.SPARK_WEBRTC_ICE;
					if (Array.isArray(servers)) {
						return {iceServers: servers};
					}
				} catch (err) {
					console.warn('Failed to parse SPARK_WEBRTC_ICE', err);
				}
			}
		}
		return config;
	}

	async function startWebRTCSession() {
		if (!webrtcAvailable || pcRef.current || webrtcOfferSentRef.current) {
			return;
		}
		if (typeof window === 'undefined' || typeof window.RTCPeerConnection !== 'function') {
			setWebrtcError(i18n.t('DESKTOP.WEBRTC_BROWSER_UNSUPPORTED') || 'Browser does not support WebRTC.');
			return;
		}
		const pc = new RTCPeerConnection(buildPeerConnectionConfig());
		pcRef.current = pc;
		webrtcOfferSentRef.current = true;
		setWebrtcState('connecting');
		setWebrtcError(null);
		setWebrtcSignal({kind: 'offer', timestamp: Date.now()});
		pc.ontrack = (event) => {
			if (!webrtcVideoRef.current) {
				return;
			}
			const [stream] = event.streams || [];
			if (stream) {
				webrtcVideoRef.current.srcObject = stream;
			} else if (event.track) {
				const mediaStream = new MediaStream([event.track]);
				webrtcVideoRef.current.srcObject = mediaStream;
			}
		};
		pc.onicecandidate = (event) => {
			if (event.candidate) {
				sendWebRTCSignal('candidate', {
					candidate: event.candidate.candidate,
					sdpMid: event.candidate.sdpMid,
					sdpMLineIndex: event.candidate.sdpMLineIndex,
				});
			}
		};
		pc.onconnectionstatechange = () => {
			setWebrtcState(pc.connectionState);
			if (pc.connectionState === 'connected') {
				setWebrtcSignal({kind: 'connected', timestamp: Date.now()});
			}
			if (pc.connectionState === 'failed') {
				setWebrtcError(i18n.t('DESKTOP.WEBRTC_FAILED') || 'WebRTC connection failed.');
			}
			if (pc.connectionState === 'closed' || pc.connectionState === 'failed' || pc.connectionState === 'disconnected') {
				webrtcOfferSentRef.current = false;
			}
		};
		pc.ondatachannel = (event) => {
			const channel = event?.channel;
			if (!channel || channel.label !== 'spark-diff') {
				return;
			}
			dataChannelRef.current = channel;
			channel.binaryType = 'arraybuffer';
			channel.onopen = () => {
				setWebrtcState('datachannel-open');
			};
			channel.onclose = () => {
				dataChannelRef.current = null;
				setWebrtcState((prev) => (prev === 'datachannel-open' ? 'connected' : prev));
			};
			channel.onerror = (evt) => {
				const errMsg = evt?.message || i18n.t('DESKTOP.WEBRTC_DATA_ERROR') || 'WebRTC data channel error.';
				setWebrtcError(errMsg);
				message.error(errMsg);
			};
			channel.onmessage = (evt) => {
				if (evt?.data) {
					handleWebRTCFrame(evt.data);
				}
			};
		};
		try {
			const offer = await pc.createOffer({
				offerToReceiveVideo: true,
				offerToReceiveAudio: false,
			});
			await pc.setLocalDescription(offer);
			sendWebRTCSignal('offer', {
				type: offer.type,
				sdp: offer.sdp,
			});
		} catch (err) {
			teardownWebRTC(err?.message || 'WebRTC initialization failed.');
			throw err;
		}
	}

	function teardownWebRTC(errorMessage) {
		webrtcOfferSentRef.current = false;
		if (dataChannelRef.current) {
			try {
				dataChannelRef.current.close();
			} catch (_) {
				// ignore
			}
			dataChannelRef.current = null;
		}
		if (pcRef.current) {
			try {
				pcRef.current.ontrack = null;
				pcRef.current.onicecandidate = null;
				pcRef.current.onconnectionstatechange = null;
				pcRef.current.close();
			} catch (err) {
				// ignore
			}
			pcRef.current = null;
		}
		if (webrtcVideoRef.current) {
			webrtcVideoRef.current.srcObject = null;
		}
		if (errorMessage) {
			setWebrtcError(errorMessage);
			setWebrtcState('error');
		} else if (!webrtcAvailable) {
			setWebrtcState('idle');
			setWebrtcError(null);
		}
	}

	function sendWebRTCSignal(kind, payload) {
		if (!conn) {
			return;
		}
		sendData({
			act: 'DESKTOP_WEBRTC_SIGNAL',
			kind,
			payload,
		});
	}

	function updateQualityState(payload) {
		if (!payload) {
			setQualityPresets([]);
			setQualityKey(null);
			setQualityLoading(false);
			return;
		}
		if (Array.isArray(payload.presets)) {
			setQualityPresets(payload.presets);
		}
		if (payload.selected) {
			setQualityKey(payload.selected);
		}
		setQualityLoading(false);
	}

	function handleWebRTCFrame(data) {
		if (!canvas || !ctx) {
			return;
		}
		let buffer = data;
		if (buffer instanceof Blob) {
			buffer.arrayBuffer().then((arr) => parseBlocks(arr, canvas, ctx));
			return;
		}
		if (buffer && buffer.data instanceof ArrayBuffer) {
			buffer = buffer.data;
		}
		if (!(buffer instanceof ArrayBuffer)) {
			return;
		}
		parseBlocks(buffer, canvas, ctx);
	}

	async function handleWebRTCSignal(packet) {
		const code = typeof packet?.code === 'number' ? packet.code : 0;
		if (code !== 0) {
			const warnMsg = packet?.msg || i18n.t('DESKTOP.WEBRTC_SIGNAL_FAILED') || 'WebRTC signalling failed.';
			setWebrtcError(warnMsg);
			message.warning(warnMsg);
			return;
		}
		const data = packet?.data || {};
		if (data?.status === 'unsupported') {
			const unsupportedMsg = i18n.t('DESKTOP.WEBRTC_UNSUPPORTED') || 'Remote device does not support WebRTC yet.';
			setWebrtcError(unsupportedMsg);
			setWebrtcState('unsupported');
			message.info(unsupportedMsg);
			teardownWebRTC();
			return;
		}
		const kind = (data?.kind || packet?.kind || '').toLowerCase();
		const payload = data?.payload || data;
		setWebrtcSignal({
			kind: kind || 'signal',
			status: data?.status || 'ok',
			timestamp: Date.now()
		});
		const pc = pcRef.current;
		if (!pc) {
			return;
		}
		try {
			if (kind === 'answer' && payload?.sdp) {
				const desc = new RTCSessionDescription({
					type: payload.type || 'answer',
					sdp: payload.sdp
				});
				await pc.setRemoteDescription(desc);
				setWebrtcState('answer');
			} else if (kind === 'candidate' && payload?.candidate) {
				const candidate = new RTCIceCandidate({
					candidate: payload.candidate,
					sdpMid: payload.sdpMid,
					sdpMLineIndex: payload.sdpMLineIndex,
				});
				await pc.addIceCandidate(candidate);
			}
		} catch (err) {
			const errMsg = err?.message || 'WebRTC signalling error.';
			setWebrtcError(errMsg);
			message.error(errMsg);
		}
	}

	useEffect(() => {
		const clipboardEnabled = !!caps?.input?.clipboard?.enabled;
		const allowPush = caps?.input?.clipboard?.allowPush !== false;
		const allowPull = caps?.input?.clipboard?.allowPull !== false;
		setClipboardAvailable(clipboardEnabled);
		if (!clipboardEnabled || (!allowPush && !allowPull)) {
			setClipboardSyncEnabled(false);
		}
	}, [caps]);

	async function pushClipboardToRemote() {
		if (!clipboardAvailable || !clipboardSyncEnabled || !conn) return;
		if (!clipboardPushAllowed) {
			message.info(i18n.t('DESKTOP.CLIPBOARD_PUSH_DISABLED') || 'Clipboard send disabled by policy.');
			return;
		}
		if (!navigator.clipboard) {
			message.warn(i18n.t('DESKTOP.CLIPBOARD_BROWSER_UNAVAILABLE') || 'Clipboard access requires HTTPS and user permission.');
			return;
		}
		try {
			setClipboardLoading(true);
			const text = await navigator.clipboard.readText();
			sendData({
				act: 'DESKTOP_CLIPBOARD_PUSH',
				text
			});
		} catch (err) {
			setClipboardLoading(false);
			message.error((err && err.message) || 'Failed to read local clipboard.');
		}
	}

	function requestClipboardFromRemote() {
		if (!clipboardAvailable || !clipboardSyncEnabled || !conn) return;
		if (!clipboardPullAllowed) {
			message.info(i18n.t('DESKTOP.CLIPBOARD_PULL_DISABLED') || 'Clipboard fetch disabled by policy.');
			return;
		}
		setClipboardLoading(true);
		sendData({
			act: 'DESKTOP_CLIPBOARD_PULL'
		});
	}

	function updatePolicyState(payload) {
		setForceInputLoading(false);
		setForceCaptureLoading(false);
		if (!payload) {
			setPolicyState(null);
			return;
		}
		const pointerEnabled = typeof payload.pointerEnabled === 'boolean'
			? payload.pointerEnabled
			: (typeof payload.pointer?.enabled === 'boolean' ? payload.pointer.enabled : null);
		const keyboardEnabled = typeof payload.keyboardEnabled === 'boolean'
			? payload.keyboardEnabled
			: (typeof payload.keyboard?.enabled === 'boolean' ? payload.keyboard.enabled : null);
		const inputEnabled = typeof payload.inputEnabled === 'boolean'
			? payload.inputEnabled
			: Boolean((pointerEnabled ?? false) || (keyboardEnabled ?? false));
		setPolicyState({
			inputEnabled,
			pointerEnabled,
			keyboardEnabled,
			forceInput: !!payload.forceInput,
			forceCapture: !!payload.forceCapture,
			requestedForceInput: !!(payload.requestedForceInput ?? payload.forceInput),
			requestedForceCapture: !!(payload.requestedForceCapture ?? payload.forceCapture),
			connectionId: payload.connectionId || payload.connectionID || payload.connection || null,
			sessionId: payload.sessionId || payload.sessionID || null,
			policyCreated: payload.policyCreated ?? payload.createdAt ?? null,
			policyUpdated: payload.policyUpdated ?? payload.updatedAt ?? null,
			nativePolicyUpdated: payload.nativePolicyUpdated ?? null
		});
	}

	function parseBlocks(ab, canvas, canvasCtx) {
		ab = ab.slice(5);
		let dv = new DataView(ab);
		let op = dv.getUint8(0);
		if (op === 3) {
			handleJSON(ab.slice(1));
			return;
		}
		if (op === 2) {
			let width = dv.getUint16(3, false);
			let height = dv.getUint16(5, false);
			if (width === 0 || height === 0) return;
			canvas.width = width;
			canvas.height = height;
			setResolution(`${width}x${height}`);
			return;
		}
		if (op === 0) frames++;
		bytes += ab.byteLength;
		let offset = 1;
		while (offset < ab.byteLength) {
			let bl = dv.getUint16(offset + 0, false); // body length
			let it = dv.getUint16(offset + 2, false); // image type
			let dx = dv.getUint16(offset + 4, false); // image block x
			let dy = dv.getUint16(offset + 6, false); // image block y
			let bw = dv.getUint16(offset + 8, false); // image block width
			let bh = dv.getUint16(offset + 10, false); // image block height
			let il = bl - 10; // image length
			offset += 12;
			updateImage(ab.slice(offset, offset + il), it, dx, dy, bw, bh, canvasCtx);
			offset += il;
		}
		dv = null;
	}
	function updateImage(ab, it, dx, dy, bw, bh, canvasCtx) {
		switch (it) {
			case 0:
				canvasCtx.putImageData(new ImageData(new Uint8ClampedArray(ab), bw, bh), dx, dy, 0, 0, bw, bh);
				break;
			case 1:
				createImageBitmap(new Blob([ab]), 0, 0, bw, bh, {
					premultiplyAlpha: 'none',
					colorSpaceConversion: 'none'
				}).then((ib) => {
					canvasCtx.drawImage(ib, 0, 0, bw, bh, dx, dy, bw, bh);
				});
				break;
		}
	}
	function handleJSON(ab) {
		let data = decrypt(ab, secret);
		try {
			data = JSON.parse(data);
		} catch (_) {}
		if (data?.act === 'DESKTOP_MONITORS') {
			const payload = data?.data || {};
			setMonitorLoading(false);
			if (Array.isArray(payload.monitors)) {
				setMonitors(payload.monitors);
			}
			if (typeof payload.selected === 'number') {
				setSelectedMonitor(payload.selected);
			}
			return;
		}
		if (data?.act === 'DESKTOP_SET_MONITOR') {
			const payload = data?.data || {};
			setMonitorLoading(false);
			if (data?.code && data.code !== 0) {
				message.error(data?.msg || payload?.error || i18n.t('COMMON.UNKNOWN_ERROR'));
				return;
			}
			if (typeof payload.index === 'number') {
				setSelectedMonitor(payload.index);
			}
			if (Array.isArray(payload.monitors)) {
				setMonitors(payload.monitors);
			}
			return;
		}
		if (data?.act === 'DESKTOP_SET_QUALITY') {
			const payload = data?.data || {};
			if (data?.code && data.code !== 0) {
				setQualityLoading(false);
				message.error(data?.msg || payload?.error || i18n.t('COMMON.UNKNOWN_ERROR'));
				return;
			}
			updateQualityState(payload);
			return;
		}
		if (data?.act === 'DESKTOP_CLIPBOARD_RESULT') {
			setClipboardLoading(false);
			if (data?.code && data.code !== 0) {
				message.error(data?.msg || i18n.t('COMMON.UNKNOWN_ERROR'));
			} else {
				message.success(i18n.t('DESKTOP.CLIPBOARD_PUSHED') || 'Clipboard sent to remote device.');
			}
			return;
		}
		if (data?.act === 'DESKTOP_CLIPBOARD_DATA') {
			setClipboardLoading(false);
			const payload = data?.data || {};
			const text = payload?.text || data?.text;
			if (text && navigator.clipboard?.writeText) {
				navigator.clipboard.writeText(text).then(() => {
					message.success(i18n.t('DESKTOP.CLIPBOARD_PULLED') || 'Remote clipboard copied locally.');
				}).catch((err) => {
					message.warning(err?.message || 'Copied remote clipboard text. Paste manually.');
				});
			} else if (text) {
				message.info((i18n.t('DESKTOP.CLIPBOARD_DATA') || 'Remote clipboard: ') + text);
			}
			return;
		}
		if (data?.act === 'DESKTOP_METRICS') {
			setAgentStats(data?.data || data);
			return;
		}
		if (data?.act === 'DESKTOP_CAPS') {
			const payload = data?.data || data?.capabilities || data;
			if (payload?.quality) {
				updateQualityState(payload.quality);
			}
			if (payload?.policy) {
				updatePolicyState(payload.policy);
			} else {
				updatePolicyState(null);
			}
			setCaps(payload);
			return;
		}
		if (data?.act === 'DESKTOP_POLICY') {
			updatePolicyState(data?.data || data);
			return;
		}
		if (data?.act === 'DESKTOP_POLICY_ALERT') {
			handlePolicyAlert(data);
			return;
		}
		if (data?.act === 'DESKTOP_POLICY_FORCE') {
			handlePolicyForceResponse(data);
			return;
		}
		if (data?.act === 'DESKTOP_WEBRTC_SIGNAL') {
			handleWebRTCSignal(data);
			return;
		}
		if (data?.act === 'DESKTOP_SECURE_HOTKEY') {
			setSecureHotkeyLoading(false);
			if (data?.code && data.code !== 0) {
				message.error(data?.msg || i18n.t('DESKTOP.SECURE_HOTKEY_FAILED') || 'Secure hotkey failed.');
			} else {
				const seqLabel = data?.data?.sequence || data?.sequence || '';
				message.success((i18n.t('DESKTOP.SECURE_HOTKEY_SENT') || 'Secure hotkey sent.') + (seqLabel ? ` (${seqLabel})` : ''));
			}
			return;
		}
		if (data?.act === 'WARN') {
			message.warn(data.msg ? translate(data.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
			return;
		}
		if (data?.act === 'QUIT') {
			message.warn(data.msg ? translate(data.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
			conn = false;
			ws.close();
		}
	}

	function sendData(data) {
		if (conn) {
			let body = encrypt(str2ua(JSON.stringify(data)), secret);
			let buffer = new Uint8Array(body.length + 8);
			buffer.set(new Uint8Array([34, 22, 19, 17, 20, 3]), 0);
			buffer.set(new Uint8Array([body.length >> 8, body.length & 0xFF]), 6);
			buffer.set(body, 8);
			ws.send(buffer);
		}
	}

	const monitorOptions = Array.isArray(monitors) ? monitors.map((monitor) => ({
		label: `Display ${monitor.index + 1}${monitor.width && monitor.height ? ` (${monitor.width}x${monitor.height})` : ''}`,
		value: monitor.index
	})) : [];
	const selectedMonitorMeta = Array.isArray(monitors) ? monitors.find((monitor) => monitor.index === selectedMonitor) : null;
	const monitorLabel = selectedMonitorMeta ? `Monitor: Display ${selectedMonitorMeta.index + 1}${selectedMonitorMeta.width && selectedMonitorMeta.height ? ` (${selectedMonitorMeta.width}x${selectedMonitorMeta.height})` : ''}` : null;
	const qualityOptions = Array.isArray(qualityPresets) ? qualityPresets.map((preset) => ({
		label: preset.label || preset.key,
		value: preset.key
	})) : [];
	const clipboardCaps = caps?.input?.clipboard;
	const clipboardPushAllowed = clipboardCaps?.allowPush !== false;
	const clipboardPullAllowed = clipboardCaps?.allowPull !== false;
	const clipboardSendDisabled = !clipboardSyncEnabled || !clipboardPushAllowed;
	const clipboardFetchDisabled = !clipboardSyncEnabled || !clipboardPullAllowed;
	const secureHotkeyOptions = [
		{
			label: i18n.t('DESKTOP.SECURE_HOTKEY_CTRL_ALT_DEL') || 'Secure: Ctrl + Alt + Del',
			value: 'CTRL_ALT_DEL'
		},
		{
			label: i18n.t('DESKTOP.SECURE_HOTKEY_WIN_L') || 'Secure: Win + L (Lock)',
			value: 'WIN_L'
		},
		{
			label: i18n.t('DESKTOP.SECURE_HOTKEY_CTRL_SHIFT_ESC') || 'Secure: Ctrl + Shift + Esc',
			value: 'CTRL_SHIFT_ESC'
		}
	];
	const policyForceAvailable = !!(policyState && policyState.connectionId);
	const policyForceInputActive = !!(typeof policyState?.requestedForceInput === 'boolean' ? policyState.requestedForceInput : policyState?.forceInput);
	const policyForceCaptureActive = !!(typeof policyState?.requestedForceCapture === 'boolean' ? policyState.requestedForceCapture : policyState?.forceCapture);
	const activePolicyIssues = Object.entries(policyIssueFlags || {}).filter(([, issue]) => issue?.active);
	const transports = Array.isArray(caps?.transports) ? caps.transports : [];
	const rtcSupported = typeof window !== 'undefined' && typeof window.RTCPeerConnection === 'function';
	const webrtcAvailable = rtcSupported && transports.includes('webrtc');
	const selectedQuality = qualityOptions.find((option) => option.value === qualityKey) || qualityOptions[0];
	const qualityLabel = selectedQuality ? `Quality: ${selectedQuality.label}` : null;
	const captureLabel = caps?.capture?.primary ? caps.capture.primary.toUpperCase() : '';
	const sessionItems = caps?.session ? [
		caps.session.user ? `User: ${caps.session.user}` : null,
		caps.session.id ? `Session ID: ${caps.session.id}` : null,
		caps.session.sid ? `SID: ${caps.session.sid}` : null,
	].filter(Boolean) : [];
	const encoderLabel = Array.isArray(caps?.encoders) && caps.encoders.length ? caps.encoders.map((enc) => (enc.name || enc.type || '')).filter(Boolean).join('/') : '';
	const transportLabel = transports.length ? transports.join('/') : '';
	const monitorTitle = selectedMonitorMeta ? `Display ${selectedMonitorMeta.index + 1}` : '';
	const capabilityTitle = [captureLabel, encoderLabel, transportLabel, monitorTitle].filter(Boolean).join(' · ');
	const webrtcStatusLabel = webrtcAvailable ? `WebRTC: ${webrtcOptIn ? webrtcState : 'disabled'}` : null;
	const webrtcErrorLabel = webrtcOptIn && webrtcError ? `WebRTC Error: ${webrtcError}` : null;
	const capItems = caps ? [
		caps?.capture?.primary ? `Capture: ${caps.capture.primary}` : null,
		caps?.encoders?.length ? `Encoder: ${caps.encoders.map((enc) => enc.name || enc.type).filter(Boolean).join(', ')}` : null,
		transports.length ? `Transport: ${transports.join(', ')}` : null,
		monitorLabel,
		qualityLabel,
		webrtcStatusLabel,
		webrtcErrorLabel,
	].filter(Boolean) : [];
	const policyItems = policyState ? [
		policyState.inputEnabled === true ? 'Input Enabled' : (policyState.inputEnabled === false ? 'Input Disabled' : null),
		typeof policyState.pointerEnabled === 'boolean' ? `Pointer Input: ${policyState.pointerEnabled ? 'Ready' : 'Blocked'}` : null,
		typeof policyState.keyboardEnabled === 'boolean' ? `Keyboard Input: ${policyState.keyboardEnabled ? 'Ready' : 'Blocked'}` : null,
		policyState.requestedForceInput ? 'Requested: Force Input' : null,
		policyState.requestedForceCapture ? 'Requested: Force Capture' : null,
		policyState.forceInput ? 'UMH: Force Input Active' : null,
		policyState.forceCapture ? 'UMH: Force Capture Active' : null,
		policyState.connectionId ? `Policy Session: ${policyState.connectionId.substring(0, 8)}...` : null,
		policyState.nativePolicyUpdated ? `UMH Updated: ${new Date(policyState.nativePolicyUpdated).toLocaleTimeString()}` : null,
		policyState.policyUpdated ? `Requested Updated: ${new Date(policyState.policyUpdated).toLocaleTimeString()}` : null,
	].filter(Boolean) : [];
	const agentItems = agentStats ? [
		typeof agentStats.fps === 'number' ? `Agent FPS: ${agentStats.fps.toFixed(1)}` : null,
		typeof agentStats.bandwidthBytesPerSec === 'number' ? `Agent BW: ${formatSize(agentStats.bandwidthBytesPerSec)}/s` : null,
		typeof agentStats.queueHighWater === 'number' ? `Frame Queue: ${agentStats.queueHighWater}` : null,
		agentStats.queueDrops ? `Drops: ${agentStats.queueDrops}` : null,
		agentStats.lastError ? `Last Error: ${agentStats.lastError}` : null,
	].filter(Boolean) : [];
	const bannerItems = [...sessionItems, ...capItems, ...policyItems, ...agentItems];
	const agentTitle = agentStats ? ` | Agent ${typeof agentStats.fps === 'number' ? agentStats.fps.toFixed(1) : '—'}fps ${formatSize(agentStats.bandwidthBytesPerSec || 0)}/s` : '';

	return (
		<DraggableModal
			draggable={true}
			maskClosable={false}
			destroyOnClose={true}
			modalTitle={`${title} ${resolution} UI ${formatSize(bandwidth)}/s ${fps}fps${agentTitle}${capabilityTitle ? ` • ${capabilityTitle}` : ''}`}
			footer={null}
			height={480}
			width={940}
			bodyStyle={{
				padding: 0
			}}
			{...props}
		>
				<div style={{width: '100%', height: '100%', display: 'flex', flexDirection: 'column'}}>
					{(bannerItems.length > 0 || monitorOptions.length > 1) && (
						<div style={{background: 'rgba(0, 0, 0, 0.65)', color: '#fff', fontSize: 12, padding: '6px 12px', display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center'}}>
							{bannerItems.map((item, index) => (
								<span key={index}>{item}</span>
							))}
							{monitorOptions.length > 1 && (
								<Select
									size='small'
									value={typeof selectedMonitor === 'number' ? selectedMonitor : (monitorOptions[0]?.value)}
									onChange={handleMonitorChange}
									options={monitorOptions}
									loading={monitorLoading}
									style={{minWidth: 160, marginLeft: 'auto'}}
									dropdownMatchSelectWidth={false}
								/>
							)}
							{qualityOptions.length > 0 && (
								<Select
									size='small'
									value={selectedQuality ? selectedQuality.value : undefined}
									onChange={handleQualityChange}
									options={qualityOptions}
									loading={qualityLoading}
									style={{minWidth: 180}}
									dropdownMatchSelectWidth={false}
								/>
							)}
							{webrtcAvailable && (
								<div style={{display: 'flex', alignItems: 'center', gap: 6}}>
									<Switch
										size='small'
										checked={webrtcOptIn}
										onChange={toggleWebRTCOptIn}
									/>
									<span>{i18n.t('DESKTOP.WEBRTC_BETA') || 'WebRTC (beta)'}</span>
								</div>
							)}
							<Select
								key={`secure-hotkey-${secureHotkeyDropdownKey}`}
								size='small'
								placeholder={i18n.t('DESKTOP.SECURE_HOTKEY') || 'Secure Hotkey'}
								disabled={!controlEnabled}
								loading={secureHotkeyLoading}
								onSelect={handleSecureHotkeySelect}
								options={secureHotkeyOptions}
								dropdownMatchSelectWidth={false}
								style={{minWidth: 220}}
							/>
							{policyForceAvailable && (
								<div style={{display: 'flex', gap: '8px', flexWrap: 'wrap'}}>
									<Button
										size='small'
										type={policyForceInputActive ? 'primary' : 'default'}
										loading={forceInputLoading}
										onClick={() => requestPolicyForce('input', !policyForceInputActive)}
									>
										{policyForceInputActive ? (i18n.t('DESKTOP.POLICY_FORCE_INPUT_ON') || 'Force Input On') : (i18n.t('DESKTOP.POLICY_FORCE_INPUT_OFF') || 'Force Input Off')}
									</Button>
									<Button
										size='small'
										type={policyForceCaptureActive ? 'primary' : 'default'}
										loading={forceCaptureLoading}
										onClick={() => requestPolicyForce('capture', !policyForceCaptureActive)}
									>
										{policyForceCaptureActive ? (i18n.t('DESKTOP.POLICY_FORCE_CAPTURE_ON') || 'Force Capture On') : (i18n.t('DESKTOP.POLICY_FORCE_CAPTURE_OFF') || 'Force Capture Off')}
									</Button>
								</div>
							)}
						</div>
					)}
					{activePolicyIssues.length > 0 && (
						<div style={{padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: '8px'}}>
							{activePolicyIssues.map(([category, issue]) => {
								const content = getPolicyIssueContent(category);
								return (
									<Alert
										key={`policy-issue-${category}-${issue?.timestamp || 'current'}`}
										type={content.type}
										showIcon
										closable
										message={content.title}
										description={content.description || undefined}
										onClose={() => dismissPolicyIssue(category)}
									/>
								);
							})}
						</div>
					)}
					{policyAlerts.length > 0 && (
						<div style={{padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: '8px'}}>
							{policyAlerts.map((alert) => (
								<Alert
									key={alert.id}
									type={alert.type}
									showIcon
									closable
									message={alert.message}
									description={alert.description || undefined}
									onClose={() => dismissPolicyAlert(alert.id)}
								/>
							))}
						</div>
					)}
					<div style={{position: 'relative', flex: 1}}>
						<video
							ref={webrtcVideoRef}
							autoPlay
							playsInline
							muted
							style={{
								position: 'absolute',
								inset: 0,
								width: '100%',
								height: '100%',
								objectFit: 'contain',
								opacity: webrtcState === 'connected' ? 1 : 0,
								transition: 'opacity 0.2s ease',
								pointerEvents: 'none',
								background: '#000'
							}}
						/>
						<canvas
							id='painter'
							ref={canvasRef}
							style={{width: '100%', height: '100%', display: 'block'}}
						/>
					</div>
				</div>
			<Button
				style={{right:'59px'}}
				className='header-button'
				icon={<FullscreenOutlined />}
				onClick={fullScreen}
			/>
			<Button
				style={{right:'115px'}}
				className='header-button'
				icon={<ReloadOutlined />}
				onClick={refresh}
			/>
			{pointerLockSupported && (
				<Button
					style={{right:'283px'}}
					className={`header-button ${pointerLockActive ? 'active' : ''}`}
					onClick={togglePointerLock}
					disabled={!controlEnabled}
				>
					{pointerLockActive ? (i18n.t('DESKTOP.POINTER_LOCK_ON') || 'Pointer Lock On') : (i18n.t('DESKTOP.POINTER_LOCK_OFF') || 'Pointer Lock Off')}
				</Button>
			)}
			{clipboardAvailable && (
				<>
					<Button
						style={{right:pointerLockSupported ? '395px' : '227px'}}
						className={`header-button ${clipboardSyncEnabled ? 'active' : ''}`}
						onClick={toggleClipboardSync}
					>
						{clipboardSyncEnabled ? (i18n.t('DESKTOP.CLIPBOARD_SYNC_ON') || 'Clipboard Sync On') : (i18n.t('DESKTOP.CLIPBOARD_SYNC_OFF') || 'Clipboard Sync Off')}
					</Button>
					<Button
						style={{right:pointerLockSupported ? '507px' : '339px'}}
						className='header-button'
						loading={clipboardLoading}
						disabled={clipboardSendDisabled}
						onClick={pushClipboardToRemote}
					>
						{i18n.t('DESKTOP.CLIPBOARD_SEND') || 'Send Clipboard'}
					</Button>
					<Button
						style={{right:pointerLockSupported ? '619px' : '451px'}}
						className='header-button'
						loading={clipboardLoading}
						disabled={clipboardFetchDisabled}
						onClick={requestClipboardFromRemote}
					>
						{i18n.t('DESKTOP.CLIPBOARD_FETCH') || 'Fetch Clipboard'}
					</Button>
				</>
			)}
			<Button
				style={{right:'171px'}}
				className={`header-button ${controlEnabled ? 'active' : ''}`}
				onClick={toggleControl}
				disabled={policyState && policyState.inputEnabled === false}
			>
				{controlEnabled ? i18n.t('DESKTOP.CONTROL_ON') || 'Control On' : i18n.t('DESKTOP.CONTROL_OFF') || 'Control Off'}
			</Button>
		</DraggableModal>
	);
}

export default ScreenModal;
