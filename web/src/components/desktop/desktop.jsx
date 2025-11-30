import React, {useCallback, useEffect, useState} from 'react';
import {encrypt, decrypt, formatSize, genRandHex, getBaseURL, translate, str2ua, hex2ua, ua2hex} from "../../utils/utils";
import i18n from "../../locale/locale";
import DraggableModal from "../modal";
import {Button, message} from "antd";
import {FullscreenOutlined, ReloadOutlined, LockOutlined, PoweroffOutlined} from "@ant-design/icons";

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
const inputFlushMs = 16;
const inputBufferLimit = 32;
let inputBuffer = [];
let inputTimer = null;
let inputAttached = false;
let inputActive = false;
let inputFocused = false;
let setPointerLockState = () => {};
let inputAllowed = true;

function clamp(val, min, max) {
	if (val < min) return min;
	if (val > max) return max;
	return val;
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

function queueInput(event) {
	if (!conn || !inputActive) return;
	if (inputBuffer.length >= inputBufferLimit) {
		inputBuffer.shift();
	}
	inputBuffer.push(event);
}

function flushInputBuffer() {
	if (!conn || !inputActive || inputBuffer.length === 0) {
		return;
	}
	sendData({
		act: 'DESKTOP_INPUT',
		data: {events: inputBuffer}
	});
	inputBuffer = [];
}

function startInputPipeline() {
	if (!canvas || !inputAllowed) return;
	inputActive = true;
	attachInputHandlers();
	if (!inputTimer) {
		inputTimer = setInterval(flushInputBuffer, inputFlushMs);
	}
}

function stopInputPipeline() {
	inputActive = false;
	inputFocused = false;
	inputBuffer = [];
	detachInputHandlers();
	if (inputTimer) {
		clearInterval(inputTimer);
		inputTimer = null;
	}
	if (document.pointerLockElement === canvas && document.exitPointerLock) {
		document.exitPointerLock().catch(() => {});
	}
	setPointerLockState(false);
}

function attachInputHandlers() {
	if (!canvas || inputAttached) {
		return;
	}
	canvas.addEventListener('mousemove', handleMouseMove);
	canvas.addEventListener('mousedown', handleMouseDown);
	canvas.addEventListener('mouseup', handleMouseUp);
	canvas.addEventListener('mouseleave', handleMouseLeave);
	canvas.addEventListener('wheel', handleWheel, {passive: false});
	window.addEventListener('keydown', handleKeyDown);
	window.addEventListener('keyup', handleKeyUp);
	document.addEventListener('pointerlockchange', handlePointerLockChange);
	document.addEventListener('pointerlockerror', handlePointerLockError);
	inputAttached = true;
}

function detachInputHandlers() {
	if (!canvas || !inputAttached) {
		return;
	}
	canvas.removeEventListener('mousemove', handleMouseMove);
	canvas.removeEventListener('mousedown', handleMouseDown);
	canvas.removeEventListener('mouseup', handleMouseUp);
	canvas.removeEventListener('mouseleave', handleMouseLeave);
	canvas.removeEventListener('wheel', handleWheel);
	window.removeEventListener('keydown', handleKeyDown);
	window.removeEventListener('keyup', handleKeyUp);
	document.removeEventListener('pointerlockchange', handlePointerLockChange);
	document.removeEventListener('pointerlockerror', handlePointerLockError);
	inputAttached = false;
}

function handleMouseMove(e) {
	if (!conn || !inputActive || !canvas) return;
	const locked = document.pointerLockElement === canvas;
	if (locked) {
		const dx = Math.trunc(e.movementX);
		const dy = Math.trunc(e.movementY);
		if (dx !== 0 || dy !== 0) {
			queueInput({
				type: 'move',
				deltaX: dx,
				deltaY: dy
			});
		}
		return;
	}
	const rect = canvas.getBoundingClientRect();
	if (!rect.width || !rect.height) return;
	const x = clamp(Math.round(((e.clientX - rect.left) / rect.width) * canvas.width), 0, canvas.width - 1);
	const y = clamp(Math.round(((e.clientY - rect.top) / rect.height) * canvas.height), 0, canvas.height - 1);
	queueInput({
		type: 'move',
		x,
		y
	});
}

function handleMouseDown(e) {
	if (!conn || !inputActive) return;
	inputFocused = true;
	const buttons = ['left', 'middle', 'right'];
	queueInput({
		type: 'button',
		button: buttons[e.button] || 'left',
		down: true
	});
}

function handleMouseUp(e) {
	if (!conn || !inputActive) return;
	const buttons = ['left', 'middle', 'right'];
	queueInput({
		type: 'button',
		button: buttons[e.button] || 'left',
		down: false
	});
}

function handleMouseLeave() {
	if (document.pointerLockElement !== canvas) {
		inputFocused = false;
	}
}

function handleWheel(e) {
	if (!conn || !inputActive) return;
	e.preventDefault();
	queueInput({
		type: 'scroll',
		deltaX: Math.trunc(e.deltaX),
		deltaY: Math.trunc(e.deltaY)
	});
}

function handleKeyDown(e) {
	if (!conn || !inputActive) return;
	if (!inputFocused && document.pointerLockElement !== canvas) return;
	e.preventDefault();
	queueInput({
		type: 'key',
		key: e.key,
		keyCode: e.keyCode || e.which || 0,
		down: true
	});
}

function handleKeyUp(e) {
	if (!conn || !inputActive) return;
	if (!inputFocused && document.pointerLockElement !== canvas) return;
	e.preventDefault();
	queueInput({
		type: 'key',
		key: e.key,
		keyCode: e.keyCode || e.which || 0,
		down: false
	});
}

function handlePointerLockChange() {
	const locked = document.pointerLockElement === canvas;
	inputFocused = locked;
	setPointerLockState(locked);
}

function handlePointerLockError() {
	setPointerLockState(false);
	message.warn(i18n.t('COMMON.UNKNOWN_ERROR'));
}
function ScreenModal(props) {
	const [resolution, setResolution] = useState('0x0');
	const [bandwidth, setBandwidth] = useState(0);
	const [fps, setFps] = useState(0);
	const [pointerLocked, setPointerLocked] = useState(false);
	const [controlEnabled, setControlEnabled] = useState(true);
	useEffect(() => {
		setPointerLockState = setPointerLocked;
		return () => {
			setPointerLockState = () => {};
		};
	}, []);
	useEffect(() => {
		inputAllowed = controlEnabled;
		if (!controlEnabled) {
			stopInputPipeline();
		} else if (conn) {
			startInputPipeline();
		}
	}, [controlEnabled]);
	const canvasRef = useCallback((e) => {
		if (e && props.open && !conn && !canvas) {
			secret = hex2ua(genRandHex(32));
			canvas = e;
			inputAttached = false;
			initCanvas(canvas);
			construct(canvas);
		}
	}, [props]);
	const toggleControl = () => {
		setControlEnabled((prev) => {
			if (prev) {
				stopInputPipeline();
			} else if (conn) {
				startInputPipeline();
			}
			return !prev;
		});
	};
	const togglePointerLock = () => {
		if (!canvas) return;
		if (document.pointerLockElement === canvas) {
			document.exitPointerLock?.().catch(() => {});
			return;
		}
		if (!conn || !controlEnabled) return;
		canvas.requestPointerLock?.();
	};
	useEffect(() => {
		if (!props.open) {
			stopInputPipeline();
			setPointerLocked(false);
			inputAttached = false;
			canvas = null;
			if (ws && conn) {
				clearInterval(ticker);
				ws.close();
				conn = false;
			}
		}
	}, [props.open]);

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
				startInputPipeline();
			}
			ws.onmessage = (e) => {
				parseBlocks(e.data, canvas, ctx);
			};
			ws.onclose = () => {
				stopInputPipeline();
				setPointerLocked(false);
				clearInterval(ticker);
				if (conn) {
					conn = false;
					message.warn(i18n.t('COMMON.DISCONNECTED'));
				}
			};
			ws.onerror = (e) => {
				console.error(e);
				stopInputPipeline();
				setPointerLocked(false);
				clearInterval(ticker);
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
	function togglePointerLock() {
		if (!canvas) return;
		if (document.pointerLockElement === canvas) {
			if (document.exitPointerLock) {
				document.exitPointerLock().catch(() => {});
			}
		} else if (canvas.requestPointerLock) {
			canvas.requestPointerLock();
		}
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
		if (data?.act === 'DESKTOP_INPUT' && data.code && data.code !== 0) {
			message.warn(data.msg ? translate(data.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
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

	return (
		<DraggableModal
			draggable={true}
			maskClosable={false}
			destroyOnClose={true}
			modalTitle={`${title} ${resolution} ${formatSize(bandwidth)}/s FPS: ${fps}`}
			footer={null}
			height={480}
			width={940}
			bodyStyle={{
				padding: 0
			}}
			{...props}
		>
			<canvas
				id='painter'
				ref={canvasRef}
				style={{width: '100%', height: '100%'}}
			/>
			<Button
				style={{right:'59px'}}
				className='header-button'
				icon={<ReloadOutlined />}
				onClick={refresh}
			/>
			<Button
				style={{right:'115px'}}
				className='header-button'
				type={pointerLocked ? 'primary' : 'default'}
				icon={<LockOutlined />}
				onClick={togglePointerLock}
			/>
			<Button
				style={{right:'171px'}}
				className='header-button'
				icon={<FullscreenOutlined />}
				onClick={fullScreen}
			/>
		</DraggableModal>
	);
}

export default ScreenModal;
