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
		return `${location.origin}${location.pathname}#/share?token=${encodeURIComponent(token)}`;
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
				title={i18n.t('SHARE.NO_TOKEN')}
				extra={<Button type='primary' onClick={() => validateToken(token)}>{i18n.t('COMMON.RETRY')}</Button>}
			/>
		);
	}

	if (status === 'invalid') {
		return (
			<Result
				status='error'
				title={error || i18n.t('SHARE.INVALID_OR_EXPIRED')}
				extra={<Button type='primary' onClick={() => validateToken(token)}>{i18n.t('COMMON.RETRY')}</Button>}
			/>
		);
	}

	if (status === 'validating') {
		return <Spin style={{marginTop: 120}} tip={i18n.t('SHARE.VALIDATING')} />;
	}

	return (
		<div style={{padding: 24}}>
			<Card title={i18n.t('COMMON.SHARE') + ' / ' + (share?.id || '')} style={{marginBottom: 16}}>
				<Paragraph>
					<Text strong>{i18n.t('COMMON.DEVICE')}:</Text> {share?.device}
				</Paragraph>
				<Paragraph>
					<Text strong>Desktop:</Text> {share?.desktop || '-'}
				</Paragraph>
				<Paragraph>
					<Text strong>{i18n.t('COMMON.EXPIRES_AT')}:</Text> {(() => {
						const exp = share?.expiresAt ? new Date(share.expiresAt) : null;
						if (!exp || Number.isNaN(exp.getTime()) || exp.getFullYear() <= 1) {
							return i18n.t('SHARE.NEVER') || 'Never';
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
					message={share?.viewOnly === false ? (i18n.t('COMMON.CONTROL') || 'Control enabled') : (i18n.t('COMMON.READ_ONLY') || 'Read-only view')}
					description={share?.viewOnly === false ? i18n.t('SHARE.ACCESS_GRANTED') || 'You can control this desktop.' : i18n.t('SHARE.VALIDATION_FAILED') || 'Input is disabled for guests.'}
				/>
			</Card>
			<Desktop
				open={true}
				device={{id: share?.device, hostname: share?.device}}
				onCancel={() => {}}
				allowControl={share?.viewOnly === false}
				shareToken={token}
			/>
		</div>
	);
}

export default SharePage;
