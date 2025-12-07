import React, {useEffect, useMemo, useState} from 'react';
import {Alert, Button, Card, Result, Spin, Typography} from 'antd';
import axios from 'axios';
import {translate} from '../utils/utils';
import i18n from '../locale/locale';
import Desktop from '../components/desktop/desktop';

const {Paragraph, Text} = Typography;

function SharePage() {
	const [token, setToken] = useState('');
	const [status, setStatus] = useState('validating');
	const [share, setShare] = useState(null);
	const [error, setError] = useState('');

	const t = (key, fallback) => {
		const value = i18n.t(key);
		if (value && value !== key) {
			return value;
		}
		if (fallback !== undefined) {
			return fallback;
		}
		const parts = key.split('.');
		return parts[parts.length - 1] || key;
	};

	useEffect(() => {
		const params = new URLSearchParams(location.search);
		const t = params.get('token') || '';
		setToken(t);
		if (!t) {
			setStatus('missing');
			return;
		}
		validateToken(t);
	}, []);

	const guestUrl = useMemo(() => {
		if (!token) return '';
		return `${location.origin}/share?token=${encodeURIComponent(token)}`;
	}, [token]);

	function validateToken(tk) {
		setStatus('validating');
		setError('');
		axios.get('/api/share/validate', {params: {token: tk}})
			.then(res => {
				if (res.data.code === 0) {
					setShare(res.data.data?.share ?? null);
					setStatus('ok');
				} else {
					setError(res.data.msg ? translate(res.data.msg) : '');
					setStatus('invalid');
				}
			}).catch((err) => {
				setError(err?.response?.data?.msg ? translate(err.response.data.msg) : '');
				setStatus('invalid');
			});
	}

	if (status === 'missing') {
		return (
			<Result
				status='warning'
				title={t('SHARE.NO_TOKEN', 'No share token provided')}
				extra={<Button type='primary' onClick={() => validateToken(token)}>{t('COMMON.RETRY', 'Retry')}</Button>}
			/>
		);
	}

	if (status === 'invalid') {
		return (
			<Result
				status='error'
				title={error || t('SHARE.INVALID_OR_EXPIRED', 'Invalid or expired share link')}
				extra={<Button type='primary' onClick={() => validateToken(token)}>{t('COMMON.RETRY', 'Retry')}</Button>}
			/>
		);
	}

	if (status === 'validating') {
		return <Spin style={{marginTop: 120}} tip={t('SHARE.VALIDATING', 'Validating share link...')} />;
	}

	return (
		<div style={{padding: 24}}>
			<Card title={`${t('COMMON.SHARE', 'Share')} / ${(share?.id || '')}`} style={{marginBottom: 16}}>
				<Paragraph>
					<Text strong>{t('COMMON.DEVICE', 'Device')}:</Text> {share?.device}
				</Paragraph>
				<Paragraph>
					<Text strong>Desktop:</Text> {share?.desktop || '-'}
				</Paragraph>
				<Paragraph>
					<Text strong>{t('COMMON.EXPIRES_AT', 'Expires At')}:</Text> {(() => {
						const exp = share?.expiresAt ? new Date(share.expiresAt) : null;
						if (!exp || Number.isNaN(exp.getTime()) || exp.getFullYear() <= 1) {
							return t('SHARE.NEVER', 'Never');
						}
						return exp.toLocaleString();
					})()}
				</Paragraph>
				<Paragraph>
					<Text strong>URL:</Text> {guestUrl}
				</Paragraph>
				<Alert
					showIcon
					type={share?.viewOnly === false ? 'success' : 'info'}
					message={share?.viewOnly === false ? t('COMMON.CONTROL', 'Control enabled') : t('COMMON.READ_ONLY', 'Read-only view')}
					description={share?.viewOnly === false ? t('SHARE.ACCESS_GRANTED', 'You can control this desktop.') : t('SHARE.VALIDATION_FAILED', 'Input is disabled for guests.')}
				/>
			</Card>
			<Desktop
				open={true}
				device={{id: share?.device, hostname: share?.device}}
				onCancel={() => {}}
				allowControl={share?.viewOnly === false}
				shareToken={token}
				shareSecret={share?.secret}
			/>
		</div>
	);
}

export default SharePage;
