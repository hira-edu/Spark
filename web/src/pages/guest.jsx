import React, {useEffect, useRef, useState} from 'react';
import {Alert, Button, Card, message, Spin, Tag} from 'antd';
import {decrypt, genRandHex, getBaseURL, hex2ua, ua2hex} from "../utils/utils";
import i18n from "../locale/locale";

let ws = null;
let secret = null;

function Guest() {
	const canvasRef = useRef(null);
	const [share, setShare] = useState(null);
	const [status, setStatus] = useState('idle');
	const [error, setError] = useState('');

	const token = new URLSearchParams(window.location.search).get('token') || '';

	useEffect(() => {
		if (!token) {
			setError('Missing token');
			return;
		}
		setStatus('validating');
		fetch(`/api/share/validate?token=${encodeURIComponent(token)}`)
			.then(async (res) => {
				const data = await res.json();
				if (data.code !== 0) {
					throw new Error(data.msg || 'Invalid token');
				}
				setShare(data.data.share);
				setStatus('connecting');
			})
			.catch((e) => {
				console.error(e);
				setError(e.message || 'Unable to validate token');
				setStatus('error');
			});
		return () => {
			if (ws) {
				ws.close();
				ws = null;
			}
		};
	}, [token]);

	useEffect(() => {
		if (status === 'connecting' && share) {
			startStream();
		}
	}, [status, share]);

	const startStream = () => {
		const canvas = canvasRef.current;
		if (!canvas || !share) return;
		secret = hex2ua(genRandHex(32));
		const ctx = canvas.getContext('2d', {alpha: false});
		ctx.imageSmoothingEnabled = false;
		if (ws) {
			ws.close();
		}
		ws = new WebSocket(getBaseURL(true, `api/share/desktop?token=${encodeURIComponent(token)}&secret=${ua2hex(secret)}`));
		ws.binaryType = 'arraybuffer';
		ws.onopen = () => setStatus('streaming');
		ws.onmessage = (e) => parseBlocks(e.data, canvas, ctx);
		ws.onclose = () => {
			setStatus('disconnected');
		};
		ws.onerror = (e) => {
			console.error(e);
			setStatus('error');
		};
	};

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
			return;
		}
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
		} catch (_) {
		}
		if (data?.act === 'WARN') {
			message.warn(data.msg ? data.msg : i18n.t('COMMON.UNKNOWN_ERROR'));
			return;
		}
		if (data?.act === 'QUIT') {
			message.warn(data.msg ? data.msg : i18n.t('COMMON.UNKNOWN_ERROR'));
			setStatus('disconnected');
			if (ws) {
				ws.close();
			}
		}
	}

	if (!token) {
		return <Alert type="error" message="Token missing"/>;
	}

	return (
		<div style={{maxWidth: 1200, margin: '20px auto', padding: '0 12px'}}>
			<Card title="Guest Desktop" extra={share && <Tag color="blue">{share.device}</Tag>}>
				{error && <Alert type="error" message={error} style={{marginBottom: 12}}/>}
				{!error && status === 'validating' && <Spin tip="Validating token..."/>}
				<canvas
					ref={canvasRef}
					style={{width: '100%', minHeight: '400px', background: '#0f131a'}}
				/>
				<div style={{marginTop: 12}}>
					<Tag color={status === 'streaming' ? 'green' : status === 'error' ? 'red' : 'orange'}>
						{status}
					</Tag>
					<Button onClick={startStream} style={{marginLeft: 8}} disabled={!share}>
						{i18n.t('COMMON.REFRESH')}
					</Button>
				</div>
			</Card>
		</div>
	);
}

export default Guest;
