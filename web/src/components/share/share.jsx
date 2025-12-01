import React, {useEffect, useMemo, useState} from 'react';
import {Button, Form, Input, InputNumber, Switch, message, Modal, Space, Table, Tag, Tooltip} from 'antd';
import {CopyOutlined, PlusOutlined, ReloadOutlined, StopOutlined} from '@ant-design/icons';
import axios from 'axios';
import i18n from '../../locale/locale';
import {translate} from '../../utils/utils';

function Share(props) {
	const {open, onCancel, device} = props;
	const [form] = Form.useForm();
	const [loading, setLoading] = useState(false);
	const [creating, setCreating] = useState(false);
	const [shares, setShares] = useState([]);

	const guestBase = useMemo(() => `${location.origin}/share?token=`, []);

	useEffect(() => {
		if (open) {
			form.setFieldsValue({
				device: device?.id ?? '',
				desktop: device?.desktop ?? '',
				ttlSeconds: 3600,
				viewOnly: true,
				singleUse: false,
				turnOnly: false,
			});
			loadShares();
		}
	}, [open, device]);

	const columns = [
		{title: 'ID', dataIndex: 'id', key: 'id', ellipsis: true},
		{title: i18n.t('COMMON.DEVICE'), dataIndex: 'device', key: 'device', ellipsis: true},
		{title: 'Desktop', dataIndex: 'desktop', key: 'desktop', ellipsis: true},
		{
			title: 'Access',
			key: 'access',
			render: (_, row) => (
				<Space size={4} wrap>
					<Tag color={row.viewOnly ? 'gold' : 'green'}>
						{row.viewOnly ? (i18n.t('COMMON.READ_ONLY') || 'View-only') : (i18n.t('COMMON.CONTROL') || 'Control')}
					</Tag>
					{row.singleUse && (
						<Tag color={row.used ? 'red' : 'blue'}>
							{row.used ? (i18n.t('SHARE.TOKEN_ALREADY_USED') || 'Used') : (i18n.t('COMMON.SINGLE_USE') || 'Single-use')}
						</Tag>
					)}
					{row.turnOnly && (
						<Tag color='purple'>TURN only</Tag>
					)}
				</Space>
			)
		},
		{
			title: i18n.t('COMMON.EXPIRES_AT'),
			dataIndex: 'expiresAt',
			key: 'expiresAt',
			render: (v) => {
				const date = v ? new Date(v) : null;
				if (!date || Number.isNaN(date.getTime()) || date.getFullYear() <= 1) {
					return i18n.t('SHARE.NEVER') || 'Never';
				}
				return date.toLocaleString();
			}
		},
		{
			title: 'Token',
			dataIndex: 'token',
			key: 'token',
			render: (token) => (
					<Space>
						<Tag color='blue'>{token.slice(0, 8)}…</Tag>
						<Tooltip title={i18n.t('COMMON.COPY')}>
							<Button size='small' icon={<CopyOutlined />} onClick={() => copyText(token)} />
						</Tooltip>
						<Tooltip title={i18n.t('COMMON.COPY') + ' URL'}>
							<Button size='small' icon={<CopyOutlined />} onClick={() => copyText(guestBase + encodeURIComponent(token))} />
						</Tooltip>
					</Space>
				)
			},
		{
			title: i18n.t('COMMON.OPERATIONS'),
			key: 'ops',
			render: (_, row) => (
				<Space>
					<Button size='small' icon={<StopOutlined />} danger onClick={() => revoke(row.id)}>
						{i18n.t('COMMON.REVOKE') ?? 'Revoke'}
					</Button>
				</Space>
			)
		}
	];

	function copyText(text) {
		navigator.clipboard?.writeText(text).then(() => {
			message.success(i18n.t('COMMON.COPIED') || 'Copied');
		}).catch(() => {
			message.warn(i18n.t('COMMON.REQUEST_FAILED'));
		});
	}

	function loadShares() {
		setLoading(true);
		axios.get('/api/share/list').then(res => {
			if (res.data.code === 0) {
				setShares(res.data.data?.shares ?? []);
			}
		}).finally(() => setLoading(false));
	}

	function revoke(id) {
		axios.post('/api/share/revoke', {id}).then(res => {
			if (res.data.code === 0) {
				message.success(i18n.t('COMMON.OPERATION_SUCCESS'));
				loadShares();
			}
		});
	}

	function createShare(values) {
		setCreating(true);
		axios.post('/api/share/create', {
			device: values.device,
			desktop: values.desktop,
			ttlSeconds: values.ttlSeconds,
			viewOnly: !!values.viewOnly,
			singleUse: !!values.singleUse,
			turnOnly: !!values.turnOnly,
		}).then(res => {
			if (res.data.code === 0) {
				message.success(i18n.t('COMMON.OPERATION_SUCCESS'));
				loadShares();
			}
		}).catch(err => {
			const msg = err?.response?.data?.msg;
			if (msg) {
				message.warn(translate(msg));
			}
		}).finally(() => setCreating(false));
	}

	return (
		<Modal
			title={i18n.t('COMMON.SHARE') || 'Share'}
			open={!!open}
			width={900}
			onCancel={() => onCancel?.(false)}
			footer={null}
			destroyOnClose
		>
			<Form
				layout='inline'
				form={form}
				onFinish={createShare}
				style={{marginBottom: 12}}
			>
				<Form.Item
					label={i18n.t('COMMON.DEVICE')}
					name='device'
					rules={[{required: true, message: i18n.t('COMMON.INVALID_PARAMETER')}]}
				>
					<Input placeholder='device id' style={{width: 180}} />
				</Form.Item>
			<Form.Item label='Desktop' name='desktop'>
				<Input placeholder='desktop id (optional)' style={{width: 160}} />
			</Form.Item>
			<Form.Item
				label={i18n.t('COMMON.READ_ONLY') || 'View-only'}
				name='viewOnly'
				valuePropName='checked'
			>
				<Switch />
			</Form.Item>
			<Form.Item
				label={i18n.t('COMMON.SINGLE_USE') || 'Single-use'}
				name='singleUse'
				valuePropName='checked'
			>
				<Switch />
			</Form.Item>
			<Form.Item
				label='TURN only'
				name='turnOnly'
				valuePropName='checked'
				tooltip='Force TURN-only ICE for restricted networks'
			>
				<Switch />
			</Form.Item>
				<Form.Item
					label={i18n.t('SHARE.DURATION_TIP') ?? 'TTL (s)'}
					name='ttlSeconds'
					rules={[{required: true}]}
				>
					<InputNumber min={0} max={86400} step={60} />
				</Form.Item>
				<Form.Item>
					<Space>
						<Button type='primary' htmlType='submit' icon={<PlusOutlined />} loading={creating}>
							{i18n.t('COMMON.CREATE') || 'Create'}
						</Button>
						<Button icon={<ReloadOutlined />} onClick={loadShares}>
							{i18n.t('COMMON.REFRESH') || 'Refresh'}
						</Button>
					</Space>
				</Form.Item>
			</Form>
			<Table
				size='small'
				rowKey='id'
				loading={loading}
				dataSource={shares}
				columns={columns}
				pagination={false}
			/>
			<div style={{marginTop: 8, color: '#888'}}>
				{i18n.t('SHARE.DURATION_TIP') ?? 'Specify TTL in seconds; 0 means no expiry.'}
			</div>
		</Modal>
	);
}

export default Share;
