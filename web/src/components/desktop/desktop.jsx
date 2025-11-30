import React, {useCallback, useEffect, useState, useRef} from 'react';
import {encrypt, decrypt, formatSize, genRandHex, getBaseURL, translate, str2ua, hex2ua, ua2hex} from "../../utils/utils";
import i18n from "../../locale/locale";
import DraggableModal from "../modal";
import {Button, message, Tooltip} from "antd";
import {
	FullscreenOutlined,
	FullscreenExitOutlined,
	ReloadOutlined,
	DesktopOutlined,
	DisconnectOutlined,
	CameraOutlined,
	KeyOutlined,
	DragOutlined,
	PauseCircleOutlined,
	PlayCircleOutlined,
	SoundOutlined,
	CopyOutlined
} from "@ant-design/icons";
import './desktop.css';

let ws = null;
let ctx = null;
let conn = false;
let canvas = null;
let secret = null;
let flushTimer = null;
let ticker = 0;
let frames = 0;
let bytes = 0;
let ticks = 0;
let title = i18n.t('DESKTOP.TITLE');
let inputBuffer = [];
let inputErrorShown = false;
let codecWarningShown = false;
let codecFallbackRequested = false;
let videoDecoder = null;
let videoDecoderConfig = null;
const videoFrameHeaderSize = 23; // matches client wire format

function ScreenModal(props) {
	const [resolution, setResolution] = useState('0x0');
	const [resInfo, setResInfo] = useState({width: 0, height: 0});
	const [bandwidth, setBandwidth] = useState(0);
	const [fps, setFps] = useState(0);
	const [drops, setDrops] = useState(0);
	const [monitors, setMonitors] = useState([]);
	const [selectedDisplay, setSelectedDisplay] = useState(0);
	const [quality, setQuality] = useState(70);
	const [fpsTarget, setFpsTarget] = useState(60);
	const [cursorState, setCursorState] = useState({x: 0, y: 0, visible: true, display: 0});
	const [remoteClipboard, setRemoteClipboard] = useState('');
	const [audioEnabled, setAudioEnabled] = useState(false);
	const [audioSupported, setAudioSupported] = useState(true);
	const [health, setHealth] = useState({level: 'ok', msg: ''});
	const [connectionStatus, setConnectionStatus] = useState('disconnected');
	const [isFullscreen, setIsFullscreen] = useState(false);
	const [keyboardEnabled, setKeyboardEnabled] = useState(true);
	const [mouseEnabled, setMouseEnabled] = useState(true);
	const [inputPaused, setInputPaused] = useState(false);
	const [inputSupported, setInputSupported] = useState(true);
	const [showInputHint, setShowInputHint] = useState(true);
	const [cursorInStream, setCursorInStream] = useState(false);
	const [retrying, setRetrying] = useState(false);

	const thresholds = useRef({
		fpsWarn: 50,
		fpsCrit: 30,
		dropWarn: 5,
		dropCrit: 20,
		consecutive: 3
	});
	let degradeRef = useRef({count: 0, level: 'ok'});
	const containerRef = useRef(null);

	const canvasRef = useCallback((e) => {
		if (e && props.open && !conn && !canvas) {
			secret = hex2ua(genRandHex(32));
			canvas = e;
			initCanvas(canvas);
			construct(canvas);
		}
	}, [props]);

	useEffect(() => {
		if (!props.open) {
			canvas = null;
			if (ws && conn) {
				clearInterval(ticker);
				clearInterval(flushTimer);
				ws.close();
				conn = false;
				inputBuffer = [];
			}
			resetVideoPipeline();
			setConnectionStatus('disconnected');
			setHealth({level: 'ok', msg: ''});
			degradeRef.current = {count: 0, level: 'ok'};
			// Reset input state for next session
			inputErrorShown = false;
			setInputSupported(true);
			setKeyboardEnabled(true);
			setMouseEnabled(true);
			setInputPaused(false);
			setShowInputHint(true);
			setCursorInStream(false);
			setRetrying(false);
			setMonitors([]);
			setSelectedDisplay(0);
			setQuality(70);
			setFpsTarget(60);
			setResInfo({width: 0, height: 0});
			setCursorState({x: 0, y: 0, visible: false, display: 0});
			setRemoteClipboard('');
			setAudioEnabled(false);
			setAudioSupported(true);
		}
	}, [props.open]);

	// Fullscreen change listener
	useEffect(() => {
		const handleFullscreenChange = () => {
			setIsFullscreen(!!document.fullscreenElement);
		};
		document.addEventListener('fullscreenchange', handleFullscreenChange);
		return () => {
			document.removeEventListener('fullscreenchange', handleFullscreenChange);
		};
	}, []);

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
			setConnectionStatus('connecting');
			ws = new WebSocket(getBaseURL(true, `api/device/desktop?device=${props.device.id}&secret=${ua2hex(secret)}`));
			ws.binaryType = 'arraybuffer';
			ws.onopen = () => {
				conn = true;
				setConnectionStatus('connected');
				setRetrying(false);
				canvas?.focus();
				startInputFlush();
			}
			ws.onmessage = (e) => {
				parseBlocks(e.data, canvas, ctx);
			};
			ws.onclose = () => {
				if (conn) {
					conn = false;
					setConnectionStatus('disconnected');
					message.warn(i18n.t('COMMON.DISCONNECTED'));
				}
				resetVideoPipeline();
				setCursorInStream(false);
				stopInputFlush();
				setRetrying(false);
			};
			ws.onerror = (e) => {
				console.error(e);
				if (conn) {
					conn = false;
					setConnectionStatus('disconnected');
					message.warn(i18n.t('COMMON.DISCONNECTED'));
				} else {
					setConnectionStatus('disconnected');
					message.warn(i18n.t('COMMON.CONNECTION_FAILED'));
				}
				resetVideoPipeline();
				setCursorInStream(false);
				stopInputFlush();
				setRetrying(false);
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

	function resetVideoPipeline(options = {}) {
		const {preserveFallbackRequest = false, preserveWarning = false} = options;
		try {
			if (videoDecoder && videoDecoder.state !== 'closed') {
				if (typeof videoDecoder.flush === 'function') {
					videoDecoder.flush().catch(() => {});
				}
				videoDecoder.close();
			}
		} catch (err) {
			console.warn('reset video decoder failed', err);
		}
		videoDecoder = null;
		videoDecoderConfig = null;
		if (!preserveWarning) {
			codecWarningShown = false;
		}
		if (!preserveFallbackRequest) {
			codecFallbackRequested = false;
		}
		setCursorInStream(false);
	}

	function supportsWebCodecs() {
		return typeof window !== 'undefined'
			&& typeof window.VideoDecoder !== 'undefined'
			&& typeof window.EncodedVideoChunk !== 'undefined';
	}

	function ensureVideoDecoder(width, height) {
		if (!supportsWebCodecs()) return false;
		if (videoDecoder && videoDecoder.state !== 'closed') {
			if (videoDecoderConfig && videoDecoderConfig.width === width && videoDecoderConfig.height === height) {
				return true;
			}
			resetVideoPipeline();
		}
		try {
			videoDecoder = new VideoDecoder({
				output: (frame) => {
					if (!canvas || !ctx) {
						frame.close();
						return;
					}
					try {
						const targetWidth = width || canvas.width || frame.displayWidth;
						const targetHeight = height || canvas.height || frame.displayHeight;
						if (targetWidth && targetHeight) {
							if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
								canvas.width = targetWidth;
								canvas.height = targetHeight;
								setResolution(`${targetWidth}x${targetHeight}`);
							}
							ctx.drawImage(frame, 0, 0, targetWidth, targetHeight);
						}
					} finally {
						frame.close();
					}
				},
				error: (err) => console.error('WebCodecs decoder error', err)
			});
			videoDecoder.configure({
				codec: 'avc1.42E01E',
				optimizeForLatency: true,
				hardwareAcceleration: 'prefer-hardware',
				codedWidth: width || undefined,
				codedHeight: height || undefined
			});
			videoDecoderConfig = {width, height};
			return true;
		} catch (err) {
			console.warn('WebCodecs not available, keeping JPEG path', err);
			resetVideoPipeline({preserveFallbackRequest: true, preserveWarning: true});
			return false;
		}
	}

	function requestCodecFallback() {
		if (codecFallbackRequested || !conn) return;
		codecFallbackRequested = true;
		sendData({
			act: 'DESKTOP_CODEC',
			data: {h264: false}
		});
	}

	function parseVideoPacket(ab) {
		if (!ab || ab.byteLength < 1) return false;
		const view = new DataView(ab);
		const op = view.getUint8(0);
		if (op !== 0x20 && op !== 0x21) return false;
		if (ab.byteLength < videoFrameHeaderSize) return true;
		if (!canvas) return true;

		let timestamp = 0;
		if (typeof view.getBigUint64 === 'function') {
			timestamp = Number(view.getBigUint64(5, false));
		} else {
			const hi = view.getUint32(5, false);
			const lo = view.getUint32(9, false);
			timestamp = hi * 0x100000000 + lo;
		}
		const flags = view.getUint16(13, false);
		const width = view.getUint16(15, false);
		const height = view.getUint16(17, false);
		const payloadLen = view.getUint32(19, false);

		if (ab.byteLength < videoFrameHeaderSize + payloadLen) {
			return true;
		}
		const payload = new Uint8Array(ab, videoFrameHeaderSize, payloadLen);
		const keyframe = op === 0x20 || (flags & 0x1);
		const hasCursor = (flags & 0x2) !== 0;
		const hasResolution = (flags & 0x4) !== 0;

		if (hasCursor) {
			setCursorInStream(true);
		}
		if (hasResolution && width > 0 && height > 0) {
			if (canvas.width !== width || canvas.height !== height) {
				canvas.width = width;
				canvas.height = height;
			}
			setResolution(`${width}x${height}`);
		}
		frames++;
		bytes += ab.byteLength;

		if (!ensureVideoDecoder(width, height)) {
			if (!codecWarningShown) {
				codecWarningShown = true;
				message.warning(i18n.t('DESKTOP.WEBCODECS_UNAVAILABLE') || 'Browser cannot play H.264 stream, fallback to JPEG', 4);
			}
			requestCodecFallback();
			return true;
		}
		try {
			const chunk = new EncodedVideoChunk({
				type: keyframe ? 'key' : 'delta',
				timestamp: (timestamp || Date.now()) * 1000,
				data: payload
			});
			videoDecoder.decode(chunk);
		} catch (err) {
			console.warn('decode failed, falling back to JPEG path', err);
			requestCodecFallback();
			resetVideoPipeline({preserveFallbackRequest: true, preserveWarning: true});
			return true;
		}
		return true;
	}

	function toggleFullScreen() {
		if (!document.fullscreenElement) {
			containerRef.current?.requestFullscreen().catch(console.error);
		} else {
			document.exitFullscreen().catch(console.error);
		}
	}

	function reconnect() {
		if (!props.open) return;
		setRetrying(true);
		stopInputFlush();
		if (ws) {
			try {
				ws.onclose = null;
				ws.close();
			} catch (_) {}
		}
		conn = false;
		setConnectionStatus('connecting');
		setTimeout(() => {
			if (canvas) {
				construct(canvas);
			}
		}, 50);
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

	function takeScreenshot() {
		if (!canvas || !conn) return;
		try {
			const link = document.createElement('a');
			link.download = `screenshot_${props.device.hostname || 'device'}_${Date.now()}.png`;
			link.href = canvas.toDataURL('image/png');
			link.click();
			message.success(i18n.t('DESKTOP.SCREENSHOT_SAVED') || 'Screenshot saved');
		} catch (err) {
			console.error('Screenshot error:', err);
			message.error(i18n.t('DESKTOP.SCREENSHOT_FAILED') || 'Screenshot failed');
		}
	}

	function toggleKeyboard() {
		setKeyboardEnabled(prev => !prev);
	}

	function toggleMouse() {
		setMouseEnabled(prev => !prev);
	}

	function toggleAllInput() {
		setInputPaused(prev => {
			const newPaused = !prev;
			if (newPaused) {
				setKeyboardEnabled(false);
				setMouseEnabled(false);
			} else {
				setKeyboardEnabled(true);
				setMouseEnabled(true);
			}
			return newPaused;
		});
	}

	function parseBlocks(ab, canvas, canvasCtx) {
		ab = ab.slice(5);
		if (parseVideoPacket(ab)) {
			return;
		}
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
			setResInfo({width, height});
			return;
		}
		if (op === 0) frames++;
		bytes += ab.byteLength;
		let offset = 1;
		while (offset < ab.byteLength) {
			let bl = dv.getUint16(offset + 0, false);
			let it = dv.getUint16(offset + 2, false);
			let dx = dv.getUint16(offset + 4, false);
			let dy = dv.getUint16(offset + 6, false);
			let bw = dv.getUint16(offset + 8, false);
			let bh = dv.getUint16(offset + 10, false);
			let il = bl - 10;
			offset += 12;
			updateImage(ab.slice(offset, offset + il), it, dx, dy, bw, bh, canvasCtx);
			offset += il;
		}
		dv = null;
	}

	function updateImage(ab, it, dx, dy, bw, bh, canvasCtx) {
		switch (it) {
			case 0:
				// Raw RGBA image data - buffer must be exactly width * height * 4 bytes
				const expectedSize = bw * bh * 4;
				if (ab.byteLength !== expectedSize) {
					console.warn(`Image block size mismatch: expected ${expectedSize} bytes, got ${ab.byteLength} bytes for ${bw}x${bh} block at (${dx},${dy})`);
					// Try to handle gracefully by creating correctly sized buffer
					const correctBuffer = new Uint8ClampedArray(expectedSize);
					const sourceArray = new Uint8Array(ab);
					const copySize = Math.min(ab.byteLength, expectedSize);
					correctBuffer.set(sourceArray.subarray(0, copySize), 0);
					canvasCtx.putImageData(new ImageData(correctBuffer, bw, bh), dx, dy, 0, 0, bw, bh);
				} else {
					canvasCtx.putImageData(new ImageData(new Uint8ClampedArray(ab), bw, bh), dx, dy, 0, 0, bw, bh);
				}
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
		const body = (data && data.data) ? data.data : data;
		if (data?.act === 'DESKTOP_STATS') {
			if (typeof body.fps === 'number') {
				setFps(body.fps);
			}
			if (typeof body.dropped === 'number') {
				setDrops(body.dropped);
			}
			if (typeof body.bandwidth === 'number') {
				setBandwidth(body.bandwidth);
			}
			updateHealth(body.fps, body.dropped);
			return;
		}
		if (data?.act === 'DESKTOP_INFO') {
			if (Array.isArray(body.displays)) {
				setMonitors(body.displays);
			}
			if (body.config) {
				if (typeof body.config.display === 'number') {
					setSelectedDisplay(body.config.display);
				}
				if (typeof body.config.quality === 'number') {
					setQuality(Math.round(body.config.quality));
				}
				if (typeof body.config.fps === 'number') {
					setFpsTarget(Math.round(body.config.fps));
				}
			}
			return;
		}
		if (data?.act === 'DESKTOP_CURSOR') {
			setCursorState(prev => ({
				...prev,
				...body,
				visible: typeof body.visible === 'boolean' ? body.visible : true
			}));
			setCursorInStream(true);
			return;
		}
		if (data?.act === 'DESKTOP_CLIPBOARD') {
			if (data.code !== 0) {
				message.warning(data.msg ? translate(data.msg) : (i18n.t('COMMON.UNKNOWN_ERROR') || 'Clipboard failed'));
				return;
			}
			if (typeof body.text === 'string') {
				setRemoteClipboard(body.text);
				if (navigator?.clipboard?.writeText) {
					navigator.clipboard.writeText(body.text).catch(() => {});
				}
				message.success(i18n.t('DESKTOP.CLIPBOARD_SYNCED') || 'Clipboard synced');
			}
			return;
		}
		if (data?.act === 'DESKTOP_AUDIO') {
			const supported = data?.data?.supported !== false;
			setAudioSupported(supported);
			if (!supported) {
				setAudioEnabled(false);
				const msg = data.msg || i18n.t('DESKTOP.AUDIO_NOT_SUPPORTED') || 'Audio not available on this device';
				message.warning(msg);
				return;
			}
			if (data.code !== 0) {
				setAudioEnabled(false);
				message.warning(data.msg ? translate(data.msg) : (i18n.t('DESKTOP.AUDIO_NOT_SUPPORTED') || 'Audio not available'));
				return;
			}
			setAudioEnabled(!!data.data?.enabled);
			message.info(i18n.t('DESKTOP.AUDIO_USE_MODAL') || 'Audio is available via the Audio panel');
			return;
		}
		if (data?.act === 'DESKTOP_INPUT') {
			// Handle input error response (e.g., input not supported on Linux/macOS)
			if (data.code !== 0 && data.msg) {
				// Show error only once per session to avoid spam
				if (!inputErrorShown) {
					inputErrorShown = true;
					const errorMsg = data.msg.includes('unsupported')
						? i18n.t('DESKTOP.INPUT_NOT_SUPPORTED') || 'Input not supported on this platform'
						: translate(data.msg);
					message.warning(errorMsg, 5);
					// Disable input controls when not supported
					setKeyboardEnabled(false);
					setMouseEnabled(false);
					setInputSupported(false);
				}
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
			setConnectionStatus('disconnected');
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

	function updateHealth(fpsVal, dropVal) {
		const limits = thresholds.current;
		const lowFps = typeof fpsVal === 'number' && fpsVal < limits.fpsWarn;
		const criticalFps = typeof fpsVal === 'number' && fpsVal < limits.fpsCrit;
		const dropping = typeof dropVal === 'number' && dropVal > limits.dropWarn;
		const criticalDrops = typeof dropVal === 'number' && dropVal > limits.dropCrit;

		let level = 'ok';
		let msg = '';
		if (criticalFps || criticalDrops) {
			level = 'crit';
			msg = criticalDrops ? i18n.t('DESKTOP.DROPPING_FRAMES') : i18n.t('DESKTOP.LOW_FPS');
		} else if (lowFps || dropping) {
			level = 'warn';
			msg = dropping ? i18n.t('DESKTOP.DROPPING_FRAMES') : i18n.t('DESKTOP.LOW_FPS');
		}

		if (level === 'ok') {
			degradeRef.current = {count: 0, level: 'ok'};
			setHealth({level: 'ok', msg: ''});
			return;
		}
		const sameLevel = degradeRef.current.level === level;
		const nextCount = sameLevel ? degradeRef.current.count + 1 : 1;
		degradeRef.current = {count: nextCount, level};
		if (nextCount >= limits.consecutive) {
			setHealth({level, msg});
		}
	}

	function sendConfig(next = {}) {
		const payload = {
			display: next.display !== undefined ? next.display : selectedDisplay,
			fps: next.fps !== undefined ? next.fps : fpsTarget,
			quality: next.quality !== undefined ? next.quality : quality
		};
		sendData({
			act: 'DESKTOP_CONFIG',
			data: payload
		});
	}

	function handleDisplayChange(value) {
		const idx = Number(value) || 0;
		setSelectedDisplay(idx);
		sendConfig({display: idx});
	}

	function handleQualityChange(value) {
		const val = Math.max(30, Math.min(95, Number(value) || quality));
		setQuality(val);
		sendConfig({quality: val});
	}

	function handleFpsChange(value) {
		const val = Math.max(10, Math.min(120, Number(value) || fpsTarget));
		setFpsTarget(val);
		sendConfig({fps: val});
	}

	async function pushClipboard() {
		try {
			if (!navigator?.clipboard?.readText) {
				message.warning(i18n.t('DESKTOP.CLIPBOARD_BROWSER_BLOCK') || 'Clipboard access is blocked');
				return;
			}
			const text = await navigator.clipboard.readText();
			sendData({
				act: 'DESKTOP_CLIPBOARD',
				data: {direction: 'push', text}
			});
		} catch (err) {
			console.error(err);
			message.error(i18n.t('DESKTOP.CLIPBOARD_BROWSER_BLOCK') || 'Clipboard access denied');
		}
	}

	function pullClipboard() {
		sendData({
			act: 'DESKTOP_CLIPBOARD',
			data: {direction: 'pull'}
		});
	}

	function toggleAudio() {
		if (!audioSupported) {
			message.warning(i18n.t('DESKTOP.AUDIO_NOT_SUPPORTED') || 'Audio not available on this device');
			return;
		}
		const next = !audioEnabled;
		setAudioEnabled(next);
		sendData({
			act: 'DESKTOP_AUDIO',
			data: {enable: next}
		});
	}

	// Input capture and batching
	function startInputFlush() {
		stopInputFlush();
		flushTimer = setInterval(() => {
			if (!conn || inputBuffer.length === 0) return;
			sendData({
				act: 'DESKTOP_INPUT',
				data: {events: inputBuffer}
			});
			inputBuffer = [];
		}, 16);
	}

	function stopInputFlush() {
		if (flushTimer) {
			clearInterval(flushTimer);
			flushTimer = null;
		}
		inputBuffer = [];
	}

	useEffect(() => {
		if (!props.open) return;
		if (!canvas) return;
		canvas.tabIndex = 0;

		const onClick = async () => {
			if (!mouseEnabled) return;
			try {
				if (document.pointerLockElement !== canvas) {
					await canvas.requestPointerLock();
				}
				canvas.focus();
				setShowInputHint(false);
			} catch (err) {
				console.error('pointer lock', err);
			}
		};

		const onContextMenu = (e) => {
			if (!conn || !mouseEnabled) return;
			e.preventDefault();
		};

		const onMouseMove = (e) => {
			if (!conn || !mouseEnabled) return;
			const rect = canvas.getBoundingClientRect();
			if (document.pointerLockElement === canvas) {
				inputBuffer.push({
					type: 'move',
					deltaX: e.movementX | 0,
					deltaY: e.movementY | 0
				});
			} else {
				inputBuffer.push({
					type: 'move',
					x: Math.round(((e.clientX - rect.left) / rect.width) * canvas.width),
					y: Math.round(((e.clientY - rect.top) / rect.height) * canvas.height)
				});
			}
		};

		const onMouseDown = (e) => {
			if (!conn || !mouseEnabled) return;
			const buttons = ['left', 'middle', 'right'];
			inputBuffer.push({
				type: 'button',
				button: buttons[e.button] || 'left',
				down: true
			});
		};

		const onMouseUp = (e) => {
			if (!conn || !mouseEnabled) return;
			const buttons = ['left', 'middle', 'right'];
			inputBuffer.push({
				type: 'button',
				button: buttons[e.button] || 'left',
				down: false
			});
		};

		const onWheel = (e) => {
			if (!conn || !mouseEnabled) return;
			e.preventDefault();
			inputBuffer.push({
				type: 'scroll',
				deltaX: e.deltaX | 0,
				deltaY: e.deltaY | 0
			});
		};

		const onKeyDown = (e) => {
			if (!conn || !keyboardEnabled) return;
			e.preventDefault();
			inputBuffer.push({
				type: 'key',
				key: e.key,
				keyCode: e.keyCode,
				down: true
			});
		};

		const onKeyUp = (e) => {
			if (!conn || !keyboardEnabled) return;
			e.preventDefault();
			inputBuffer.push({
				type: 'key',
				key: e.key,
				keyCode: e.keyCode,
				down: false
			});
		};

		canvas.addEventListener('click', onClick);
		canvas.addEventListener('contextmenu', onContextMenu);
		canvas.addEventListener('mousemove', onMouseMove);
		canvas.addEventListener('mousedown', onMouseDown);
		canvas.addEventListener('mouseup', onMouseUp);
		canvas.addEventListener('wheel', onWheel, {passive: false});
		window.addEventListener('keydown', onKeyDown);
		window.addEventListener('keyup', onKeyUp);

		return () => {
			canvas.removeEventListener('click', onClick);
			canvas.removeEventListener('contextmenu', onContextMenu);
			canvas.removeEventListener('mousemove', onMouseMove);
			canvas.removeEventListener('mousedown', onMouseDown);
			canvas.removeEventListener('mouseup', onMouseUp);
			canvas.removeEventListener('wheel', onWheel);
			window.removeEventListener('keydown', onKeyDown);
			window.removeEventListener('keyup', onKeyUp);
		};
	}, [props.open, keyboardEnabled, mouseEnabled]);

	const getConnectionStatusClass = () => {
		switch (connectionStatus) {
			case 'connected': return 'connected';
			case 'connecting': return 'connecting';
			default: return 'disconnected';
		}
	};

	const getConnectionStatusText = () => {
		switch (connectionStatus) {
			case 'connected': return i18n.t('DESKTOP.CONNECTED') || 'Connected';
			case 'connecting': return i18n.t('DESKTOP.CONNECTING') || 'Connecting...';
			default: return i18n.t('DESKTOP.DISCONNECTED') || 'Disconnected';
		}
	};

	return (
		<DraggableModal
			draggable={true}
			maskClosable={false}
			destroyOnClose={true}
			modalTitle={title}
			footer={null}
			height={560}
			width={1000}
			bodyStyle={{
				padding: 0
			}}
			{...props}
		>
			<div className={`desktop-container ${isFullscreen ? 'fullscreen' : ''}`} ref={containerRef}>
				{/* Toolbar */}
				<div className="desktop-toolbar">
					<div className="toolbar-group">
						{/* Connection Status */}
						<div className={`connection-status ${getConnectionStatusClass()}`}>
							{connectionStatus === 'connected' ? (
								<DesktopOutlined />
							) : connectionStatus === 'connecting' ? (
								<div className="loading-spinner" style={{width: 14, height: 14, borderWidth: 2}} />
							) : (
								<DisconnectOutlined />
							)}
							<span>{getConnectionStatusText()}</span>
						</div>
						<Button
							size='small'
							type='primary'
							ghost
							loading={retrying}
							disabled={connectionStatus === 'connecting'}
							onClick={reconnect}
						>
							{connectionStatus === 'connected' ? (i18n.t('DESKTOP.REFRESH') || 'Refresh') : (i18n.t('COMMON.RETRY') || 'Reconnect')}
						</Button>

						<div className="toolbar-divider" />

						{/* Stats */}
						<div className="status-indicator">
							<span className="label">RES</span>
							<span className="value">{resolution}</span>
						</div>
						<div className="status-indicator">
							<span className="label">FPS</span>
							<span className="value">{fps}</span>
						</div>
						<div className="status-indicator">
							<span className="label">BW</span>
							<span className="value">{formatSize(bandwidth)}/s</span>
						</div>
						{drops > 0 && (
							<div className="status-indicator" style={{color: '#ff4d4f'}}>
								<span className="label">DROP</span>
								<span className="value" style={{color: '#ff4d4f'}}>{drops}</span>
							</div>
						)}
						{monitors.length > 0 && (
							<div className="toolbar-select">
								<span className="label">{i18n.t('DESKTOP.DISPLAY') || 'Display'}</span>
								<select value={selectedDisplay} onChange={(e) => handleDisplayChange(e.target.value)}>
									{monitors.map((m) => (
										<option value={m.index} key={m.index}>{`#${m.index} (${m.width}x${m.height})`}</option>
									))}
								</select>
							</div>
						)}
						<div className="toolbar-slider">
							<span className="label">Q</span>
							<input
								type="range"
								min={30}
								max={95}
								step={5}
								value={quality}
								onChange={(e) => handleQualityChange(e.target.value)}
							/>
							<span className="value">{quality}</span>
						</div>
						<div className="toolbar-slider">
							<span className="label">FPS</span>
							<input
								type="number"
								min={10}
								max={120}
								value={fpsTarget}
								onChange={(e) => handleFpsChange(e.target.value)}
							/>
						</div>
					</div>

					<div className="toolbar-group">
						{/* Input Controls */}
						<Tooltip title={!inputSupported ? (i18n.t('DESKTOP.INPUT_NOT_SUPPORTED') || 'Input not supported on this platform') : (keyboardEnabled ? (i18n.t('DESKTOP.DISABLE_KEYBOARD') || 'Disable Keyboard') : (i18n.t('DESKTOP.ENABLE_KEYBOARD') || 'Enable Keyboard'))}>
							<button
								className={`toolbar-btn ${keyboardEnabled && inputSupported ? 'active' : ''} ${!inputSupported ? 'disabled' : ''}`}
								onClick={toggleKeyboard}
								disabled={!inputSupported}
							>
								<KeyOutlined />
								<span>{i18n.t('DESKTOP.KEYBOARD') || 'Keyboard'}</span>
							</button>
						</Tooltip>

						<Tooltip title={!inputSupported ? (i18n.t('DESKTOP.INPUT_NOT_SUPPORTED') || 'Input not supported on this platform') : (mouseEnabled ? (i18n.t('DESKTOP.DISABLE_MOUSE') || 'Disable Mouse') : (i18n.t('DESKTOP.ENABLE_MOUSE') || 'Enable Mouse'))}>
							<button
								className={`toolbar-btn ${mouseEnabled && inputSupported ? 'active' : ''} ${!inputSupported ? 'disabled' : ''}`}
								onClick={toggleMouse}
								disabled={!inputSupported}
							>
								<DragOutlined />
								<span>{i18n.t('DESKTOP.MOUSE') || 'Mouse'}</span>
							</button>
						</Tooltip>

						<Tooltip title={!inputSupported ? (i18n.t('DESKTOP.INPUT_NOT_SUPPORTED') || 'Input not supported on this platform') : (inputPaused ? (i18n.t('DESKTOP.ENABLE_INPUT') || 'Enable All Input') : (i18n.t('DESKTOP.DISABLE_INPUT') || 'Disable All Input'))}>
							<button
								className={`toolbar-btn ${inputPaused ? 'danger' : ''} ${!inputSupported ? 'disabled' : ''}`}
								onClick={toggleAllInput}
								disabled={!inputSupported}
							>
								{inputPaused ? <PlayCircleOutlined /> : <PauseCircleOutlined />}
								<span>{inputPaused ? (i18n.t('DESKTOP.RESUME') || 'Resume') : (i18n.t('DESKTOP.PAUSE') || 'Pause')}</span>
							</button>
						</Tooltip>
						<Tooltip title={audioSupported ? (audioEnabled ? (i18n.t('DESKTOP.AUDIO_DISABLE') || 'Disable Audio') : (i18n.t('DESKTOP.AUDIO_ENABLE') || 'Enable Audio')) : (i18n.t('DESKTOP.AUDIO_NOT_SUPPORTED') || 'Audio not available on this device')}>
							<button
								className={`toolbar-btn ${audioEnabled ? 'active' : ''} ${!audioSupported ? 'disabled' : ''}`}
								onClick={toggleAudio}
								disabled={!audioSupported}
							>
								<SoundOutlined />
								<span>{i18n.t('DESKTOP.AUDIO') || 'Audio'}</span>
							</button>
						</Tooltip>

						<div className="toolbar-divider" />

						{/* Actions */}
						<Tooltip title={i18n.t('DESKTOP.CLIPBOARD_PULL') || 'Pull remote clipboard'}>
							<button className="toolbar-btn" style={{minWidth: 44}} onClick={pullClipboard}>
								<CopyOutlined />
								<span className="toolbar-btn-text">{i18n.t('DESKTOP.CLIPBOARD_PULL') || 'Pull'}</span>
							</button>
						</Tooltip>
						<Tooltip title={i18n.t('DESKTOP.CLIPBOARD_PUSH') || 'Send local clipboard'}>
							<button className="toolbar-btn" style={{minWidth: 44}} onClick={pushClipboard}>
								<CopyOutlined />
								<span className="toolbar-btn-text">{i18n.t('DESKTOP.CLIPBOARD_PUSH') || 'Push'}</span>
							</button>
						</Tooltip>
						<Tooltip title={i18n.t('DESKTOP.SCREENSHOT') || 'Screenshot'}>
							<button className="toolbar-btn" style={{minWidth: 44}} onClick={takeScreenshot}>
								<CameraOutlined />
								<span className="toolbar-btn-text">{i18n.t('DESKTOP.SCREENSHOT') || 'Screenshot'}</span>
							</button>
						</Tooltip>

						<Tooltip title={i18n.t('DESKTOP.REFRESH') || 'Refresh'}>
							<button className="toolbar-btn" style={{minWidth: 44}} onClick={refresh}>
								<ReloadOutlined />
								<span className="toolbar-btn-text">{i18n.t('DESKTOP.REFRESH') || 'Refresh'}</span>
							</button>
						</Tooltip>

						<Tooltip title={isFullscreen ? (i18n.t('DESKTOP.EXIT_FULLSCREEN') || 'Exit Fullscreen') : (i18n.t('DESKTOP.FULLSCREEN') || 'Fullscreen')}>
							<button className="toolbar-btn" style={{minWidth: 44}} onClick={toggleFullScreen}>
								{isFullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
								<span className="toolbar-btn-text">{isFullscreen ? (i18n.t('DESKTOP.EXIT_FULLSCREEN') || 'Exit Fullscreen') : (i18n.t('DESKTOP.FULLSCREEN') || 'Fullscreen')}</span>
							</button>
						</Tooltip>
					</div>
				</div>

				{showInputHint && (
					<div className="desktop-hint">
						<span>{i18n.t('DESKTOP.POINTER_TIP') || 'Click the canvas to lock pointer and enable keyboard control.'}</span>
						<Button type='link' size='small' onClick={() => setShowInputHint(false)}>
							{i18n.t('COMMON.GOT_IT') || 'Got it'}
						</Button>
					</div>
				)}

				{/* Health Warning */}
				{health.level !== 'ok' && (
					<div style={{
						background: health.level === 'crit' ? '#b3261e' : '#8c6d1f',
						color: '#fff',
						padding: '8px 16px',
						fontSize: 12,
						fontWeight: 600,
						display: 'flex',
						justifyContent: 'space-between',
						alignItems: 'center',
						gap: 12
					}}>
						<span>{health.msg || i18n.t('DESKTOP.LOW_FPS')}</span>
						<span style={{opacity: 0.9}}>{`FPS: ${fps} | Dropped: ${drops}`}</span>
					</div>
				)}

				{/* Canvas Container */}
				<div className="canvas-container">
					{connectionStatus === 'connecting' && (
						<div className="desktop-loading">
							<div className="loading-spinner" />
							<span>{i18n.t('DESKTOP.CONNECTING') || 'Connecting...'}</span>
						</div>
					)}
					{connectionStatus === 'disconnected' && (
						<div className="desktop-disconnected">
							<DisconnectOutlined />
							<div style={{fontWeight: 600}}>{i18n.t('COMMON.DISCONNECTED') || 'Connection lost'}</div>
							<div style={{opacity: 0.8, fontSize: 12}}>{i18n.t('DESKTOP.RETRY_HINT') || 'Reconnect to resume control'}</div>
							<Button size='small' type='primary' onClick={reconnect} loading={retrying}>
								{i18n.t('COMMON.RETRY') || 'Reconnect'}
							</Button>
						</div>
					)}
					<canvas
						id='painter'
						ref={canvasRef}
						className={`desktop-canvas ${(!keyboardEnabled && !mouseEnabled) ? 'input-disabled' : ''}`}
						style={{
							display: connectionStatus === 'connecting' ? 'none' : 'block',
							cursor: cursorInStream ? 'none' : 'crosshair'
						}}
					/>
					{cursorState.visible && resInfo.width > 0 && resInfo.height > 0 && connectionStatus === 'connected' && (
						<div
							className="remote-cursor"
							style={{
								left: `${Math.min(100, Math.max(0, (cursorState.x / resInfo.width) * 100))}%`,
								top: `${Math.min(100, Math.max(0, (cursorState.y / resInfo.height) * 100))}%`
							}}
						>
							<div className="remote-cursor-dot" />
						</div>
					)}
					{(!keyboardEnabled || !mouseEnabled) && connectionStatus === 'connected' && (
						<div className="input-disabled-overlay">
							{!keyboardEnabled && !mouseEnabled ? (
								<><PauseCircleOutlined /> {i18n.t('DESKTOP.INPUT_DISABLED') || 'Input Disabled'}</>
							) : !keyboardEnabled ? (
								<><KeyOutlined /> {i18n.t('DESKTOP.KEYBOARD_DISABLED') || 'Keyboard Disabled'}</>
							) : (
								<><DragOutlined /> {i18n.t('DESKTOP.MOUSE_DISABLED') || 'Mouse Disabled'}</>
							)}
						</div>
					)}
				</div>

				{/* Status Bar */}
				<div className="desktop-statusbar">
					<div className="statusbar-group">
						<div className="statusbar-item">
							<span className="icon"><DesktopOutlined /></span>
							<span className="value">{props.device?.hostname || 'Unknown'}</span>
						</div>
						<div className="statusbar-item">
							<span className="value">{resolution}</span>
						</div>
						<div className="statusbar-item">
							<span>{i18n.t('DESKTOP.DISPLAY') || 'Display'}:</span>
							<span className="value">#{selectedDisplay}</span>
						</div>
						<div className="statusbar-item">
							<span>{i18n.t('DESKTOP.QUALITY') || 'Quality'}:</span>
							<span className="value">{quality}</span>
						</div>
					</div>
					<div className="statusbar-group">
						<div className="statusbar-item">
							<span>{i18n.t('DESKTOP.KEYBOARD') || 'Keyboard'}:</span>
							<span className="value" style={{color: keyboardEnabled ? '#52c41a' : '#ff4d4f'}}>
								{keyboardEnabled ? 'ON' : 'OFF'}
							</span>
						</div>
						<div className="statusbar-item">
							<span>{i18n.t('DESKTOP.MOUSE') || 'Mouse'}:</span>
							<span className="value" style={{color: mouseEnabled ? '#52c41a' : '#ff4d4f'}}>
								{mouseEnabled ? 'ON' : 'OFF'}
							</span>
						</div>
						<div className="statusbar-item">
							<span>{i18n.t('DESKTOP.CURSOR') || 'Cursor'}:</span>
							<span className="value" style={{color: cursorInStream ? '#52c41a' : '#faad14'}}>
								{cursorInStream ? (i18n.t('COMMON.ACTIVE') || 'STREAM') : (i18n.t('COMMON.WAITING') || 'PENDING')}
							</span>
						</div>
						<div className="statusbar-item">
							<span>{i18n.t('DESKTOP.AUDIO') || 'Audio'}:</span>
							<span className="value" style={{color: audioSupported && audioEnabled ? '#52c41a' : '#faad14'}}>
								{audioSupported ? (audioEnabled ? (i18n.t('COMMON.ACTIVE') || 'ON') : (i18n.t('COMMON.WAITING') || 'OFF')) : (i18n.t('DESKTOP.AUDIO_NOT_SUPPORTED') || 'N/A')}
							</span>
						</div>
						<div className="statusbar-item">
							<div className={`status-dot ${connectionStatus !== 'connected' ? 'disconnected' : ''}`} />
						</div>
					</div>
				</div>
			</div>
		</DraggableModal>
	);
}

export default ScreenModal;
