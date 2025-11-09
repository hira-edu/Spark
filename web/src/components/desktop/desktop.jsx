import React, {useCallback, useEffect, useRef, useState} from 'react';
import {encrypt, decrypt, formatSize, genRandHex, getBaseURL, translate, str2ua, hex2ua, ua2hex} from "../../utils/utils";
import i18n from "../../locale/locale";
import DraggableModal from "../modal";
import {Button, message, Select} from "antd";
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
	const [agentStats, setAgentStats] = useState(null);
	const [monitors, setMonitors] = useState([]);
	const [selectedMonitor, setSelectedMonitor] = useState(null);
	const [monitorLoading, setMonitorLoading] = useState(false);
	const [qualityPresets, setQualityPresets] = useState([]);
	const [qualityKey, setQualityKey] = useState(null);
	const [qualityLoading, setQualityLoading] = useState(false);
	const [controlEnabled, setControlEnabled] = useState(false);
	const [clipboardLoading, setClipboardLoading] = useState(false);
	const [clipboardAvailable, setClipboardAvailable] = useState(false);
	const lastMoveRef = useRef(null);
	const moveFrame = useRef(null);
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
			setCaps(null);
			setMonitors([]);
			setSelectedMonitor(null);
			setMonitorLoading(false);
			setQualityPresets([]);
			setQualityKey(null);
			setQualityLoading(false);
			setAgentStats(null);
			canvas = null;
			if (ws && conn) {
				clearInterval(ticker);
				ws.close();
				conn = false;
			}
	}
}, [props.open]);

useEffect(() => {
	if (!canvas || !controlEnabled) return;
		const handleMouseDown = (evt) => {
			evt.preventDefault();
			const coords = normalizeCoords(evt);
			if (!coords) return;
			sendInputEvent({
				type: 'mouse',
				action: 'down',
				button: evt.button,
				x: coords.x,
				y: coords.y,
				timestamp: Date.now()
			});
		};
		const handleMouseUp = (evt) => {
			evt.preventDefault();
			const coords = normalizeCoords(evt);
			if (!coords) return;
			sendInputEvent({
				type: 'mouse',
				action: 'up',
				button: evt.button,
				x: coords.x,
				y: coords.y,
				timestamp: Date.now()
			});
		};
		const handleMouseMove = (evt) => {
			if (!controlEnabled) return;
			const coords = normalizeCoords(evt);
			if (!coords) return;
			lastMoveRef.current = {
				type: 'mouse',
				action: 'move',
				x: coords.x,
				y: coords.y,
				timestamp: Date.now()
			};
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
			const coords = normalizeCoords(evt);
			if (!coords) return;
			sendInputEvent({
				type: 'mouse',
				action: 'wheel',
				deltaY: evt.deltaY,
				x: coords.x,
				y: coords.y,
				timestamp: Date.now()
			});
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
		const next = !controlEnabled;
		setControlEnabled(next);
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

	function normalizeCoords(evt) {
		if (!canvas) return null;
		const rect = canvas.getBoundingClientRect();
		const scaleX = canvas.width / rect.width;
		const scaleY = canvas.height / rect.height;
		const x = Math.max(0, Math.min(canvas.width, (evt.clientX - rect.left) * scaleX));
		const y = Math.max(0, Math.min(canvas.height, (evt.clientY - rect.top) * scaleY));
		return {x: Math.round(x), y: Math.round(y)};
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

	useEffect(() => {
		const clipboardEnabled = !!caps?.input?.clipboard?.enabled;
		setClipboardAvailable(clipboardEnabled);
	}, [caps]);

	async function pushClipboardToRemote() {
		if (!clipboardAvailable || !conn) return;
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
		if (!clipboardAvailable || !conn) return;
		setClipboardLoading(true);
		sendData({
			act: 'DESKTOP_CLIPBOARD_PULL'
		});
	}

	function updatePolicyState(payload) {
		if (!payload) {
			setPolicyState(null);
			return;
		}
		setPolicyState({
			inputEnabled: !!payload.inputEnabled,
			forceInput: !!payload.forceInput,
			forceCapture: !!payload.forceCapture,
			connectionId: payload.connectionId || payload.connectionID || payload.connection || null,
			policyCreated: payload.policyCreated || payload.createdAt || null,
			policyUpdated: payload.policyUpdated || payload.updatedAt || null,
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
	const selectedQuality = qualityOptions.find((option) => option.value === qualityKey) || qualityOptions[0];
	const qualityLabel = selectedQuality ? `Quality: ${selectedQuality.label}` : null;
	const captureLabel = caps?.capture?.primary ? caps.capture.primary.toUpperCase() : '';
	const sessionItems = caps?.session ? [
		caps.session.user ? `User: ${caps.session.user}` : null,
		caps.session.id ? `Session ID: ${caps.session.id}` : null,
		caps.session.sid ? `SID: ${caps.session.sid}` : null,
	].filter(Boolean) : [];
	const encoderLabel = Array.isArray(caps?.encoders) && caps.encoders.length ? caps.encoders.map((enc) => (enc.name || enc.type || '')).filter(Boolean).join('/') : '';
	const transportLabel = Array.isArray(caps?.transports) && caps.transports.length ? caps.transports.join('/') : '';
	const monitorTitle = selectedMonitorMeta ? `Display ${selectedMonitorMeta.index + 1}` : '';
	const capabilityTitle = [captureLabel, encoderLabel, transportLabel, monitorTitle].filter(Boolean).join(' · ');
	const capItems = caps ? [
		caps?.capture?.primary ? `Capture: ${caps.capture.primary}` : null,
		caps?.encoders?.length ? `Encoder: ${caps.encoders.map((enc) => enc.name || enc.type).filter(Boolean).join(', ')}` : null,
		caps?.transports?.length ? `Transport: ${caps.transports.join(', ')}` : null,
		monitorLabel,
		qualityLabel,
	].filter(Boolean) : [];
	const policyItems = policyState ? [
		policyState.inputEnabled ? 'Input Enabled' : null,
		policyState.forceInput ? 'Force Input Active' : null,
		policyState.forceCapture ? 'Force Capture Active' : null,
		policyState.connectionId ? `Policy Session: ${policyState.connectionId.substring(0, 8)}...` : null,
		policyState.policyUpdated ? `Policy Updated: ${new Date(policyState.policyUpdated).toLocaleTimeString()}` : null,
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
						</div>
					)}
				<canvas
					id='painter'
					ref={canvasRef}
					style={{width: '100%', height: '100%'}}
				/>
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
			{clipboardAvailable && (
				<>
					<Button
						style={{right:'227px'}}
						className='header-button'
						loading={clipboardLoading}
						onClick={pushClipboardToRemote}
					>
						{i18n.t('DESKTOP.CLIPBOARD_SEND') || 'Send Clipboard'}
					</Button>
					<Button
						style={{right:'339px'}}
						className='header-button'
						loading={clipboardLoading}
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
			>
				{controlEnabled ? i18n.t('DESKTOP.CONTROL_ON') || 'Control On' : i18n.t('DESKTOP.CONTROL_OFF') || 'Control Off'}
			</Button>
		</DraggableModal>
	);
}

export default ScreenModal;
