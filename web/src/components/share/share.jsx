import React, {useEffect, useMemo, useRef, useState} from 'react';
import {
	Button, Form, Input, InputNumber, Radio, Segmented, Switch,
	message, Modal, Space, Table, Tag, Tooltip, Typography, Divider, Row, Col, Card
} from 'antd';
import {
	CopyOutlined, PlusOutlined, ReloadOutlined, StopOutlined,
	LinkOutlined, DesktopOutlined, ClockCircleOutlined, SafetyOutlined
} from '@ant-design/icons';
import axios from 'axios';
import i18n from '../../locale/locale';
import {translate} from '../../utils/utils';

const {Text, Paragraph} = Typography;

const DEFAULT_DURATION_HOURS = 4;
const MAX_DURATION_HOURS = 24;
const DURATION_PRESETS = [1, 4, 8, 24];
const ACCESS_MODE_CONTROL = 'control';
const ACCESS_MODE_VIEW = 'view';

function Share(props) {
	const {open, onCancel, device} = props;
	const [form] = Form.useForm();
	const [loading, setLoading] = useState(false);
	const [creating, setCreating] = useState(false);
	const [shares, setShares] = useState([]);
	const [durationPreset, setDurationPreset] = useState(DEFAULT_DURATION_HOURS);
	const [showCustomDuration, setShowCustomDuration] = useState(false);
	const durationInputRef = useRef(null);

	const guestBase = useMemo(() => `${location.origin}/share?token=`, []);

	// Get device display name
	const deviceName = device?.hostname || device?.name || 'Unknown Device';
	const deviceId = device?.id || device?.conn || '';

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
		if (open) {
			setTimeout(() => {
				form.setFieldsValue({
					device: deviceId,
					durationHours: DEFAULT_DURATION_HOURS,
					accessMode: ACCESS_MODE_CONTROL,
					singleUse: false,
					turnOnly: false,
				});
				setDurationPreset(DEFAULT_DURATION_HOURS);
				setShowCustomDuration(false);
			}, 0);
			loadShares();
		}
	}, [open, device, form, deviceId]);

	const handleDurationPresetChange = (value) => {
		if (value === 'custom') {
			setDurationPreset('custom');
			setShowCustomDuration(true);
			setTimeout(() => {
				durationInputRef.current?.focus?.();
			}, 0);
			return;
		}
		setDurationPreset(value);
		setShowCustomDuration(false);
		form.setFieldsValue({durationHours: value});
	};

	const handleCustomDurationChange = (value) => {
		if (typeof value === 'number' && !Number.isNaN(value)) {
			form.setFieldsValue({durationHours: value});
		}
	};

	// Simplified table columns for better readability
	const columns = [
		{
			title: 'Access Link',
			key: 'token',
			width: 200,
			render: (_, row) => (
				<Space direction="vertical" size={2}>
					<Space size={4}>
						<Tag color={row.viewOnly ? 'gold' : 'green'} style={{margin: 0}}>
							{row.viewOnly ? 'View' : 'Control'}
						</Tag>
						{row.singleUse && (
							<Tag color={row.used ? 'default' : 'blue'} style={{margin: 0}}>
								{row.used ? 'Used' : '1-time'}
							</Tag>
						)}
						{row.turnOnly && <Tag color='purple' style={{margin: 0}}>TURN</Tag>}
					</Space>
					<Space size={4}>
						<Text code style={{fontSize: 11}}>{row.token?.slice(0, 12)}…</Text>
						<Tooltip title="Copy token">
							<Button
								type="text"
								size='small'
								icon={<CopyOutlined />}
								onClick={() => copyText(row.token)}
								style={{padding: '0 4px'}}
							/>
						</Tooltip>
						<Tooltip title="Copy share URL">
							<Button
								type="text"
								size='small'
								icon={<LinkOutlined />}
								onClick={() => copyText(guestBase + encodeURIComponent(row.token))}
								style={{padding: '0 4px'}}
							/>
						</Tooltip>
					</Space>
				</Space>
			)
		},
		{
			title: 'Expires',
			dataIndex: 'expiresAt',
			key: 'expiresAt',
			width: 140,
			render: (v) => {
				const date = v ? new Date(v) : null;
				if (!date || Number.isNaN(date.getTime()) || date.getFullYear() <= 1) {
					return <Text type="secondary">Never</Text>;
				}
				const now = new Date();
				const isExpired = date < now;
				const hoursLeft = Math.round((date - now) / (1000 * 60 * 60));
				return (
					<Space direction="vertical" size={0}>
						<Text type={isExpired ? 'danger' : undefined} style={{fontSize: 12}}>
							{date.toLocaleDateString()}
						</Text>
						<Text type="secondary" style={{fontSize: 11}}>
							{isExpired ? 'Expired' : `${hoursLeft}h left`}
						</Text>
					</Space>
				);
			}
		},
		{
			title: '',
			key: 'ops',
			width: 80,
			render: (_, row) => (
				<Button
					size='small'
					type="text"
					danger
					icon={<StopOutlined />}
					onClick={() => revoke(row.id)}
				>
					Revoke
				</Button>
			)
		}
	];

	function copyText(text) {
		navigator.clipboard?.writeText(text).then(() => {
			message.success(t('COMMON.COPIED', 'Copied to clipboard'));
		}).catch(() => {
			message.warning(t('COMMON.REQUEST_FAILED', 'Failed to copy'));
		});
	}

	function loadShares() {
		setLoading(true);
		axios.get('/api/share/list').then(res => {
			if (res.data.code === 0) {
				// Filter shares for current device
				const allShares = res.data.data?.shares ?? [];
				const deviceShares = deviceId
					? allShares.filter(s => s.device === deviceId)
					: allShares;
				setShares(deviceShares);
			}
		}).finally(() => setLoading(false));
	}

	function revoke(id) {
		axios.post('/api/share/revoke', {id}).then(res => {
			if (res.data.code === 0) {
				message.success(t('COMMON.OPERATION_SUCCESS', 'Link revoked'));
				loadShares();
			}
		});
	}

	function createShare(values) {
		setCreating(true);
		const durationHours = typeof values.durationHours === 'number' ? values.durationHours : DEFAULT_DURATION_HOURS;
		const ttlSeconds = durationHours > 0 ? Math.round(durationHours * 3600) : 0;
		const accessMode = values.accessMode || ACCESS_MODE_CONTROL;
		const viewOnly = accessMode === ACCESS_MODE_VIEW;
		axios.post('/api/share/create', {
			device: values.device,
			ttlSeconds,
			viewOnly,
			singleUse: !!values.singleUse,
			turnOnly: !!values.turnOnly,
		}).then(res => {
			if (res.data.code === 0) {
				message.success(t('COMMON.OPERATION_SUCCESS', 'Share link created'));
				loadShares();
			}
		}).catch(err => {
			const msg = err?.response?.data?.msg;
			if (msg) {
				message.warning(translate(msg));
			}
		}).finally(() => setCreating(false));
	}

	return (
		<Modal
			title={
				<Space>
					<LinkOutlined />
					<span>Share Desktop Access</span>
				</Space>
			}
			open={!!open}
			width={560}
			onCancel={() => onCancel?.(false)}
			footer={null}
			destroyOnClose
		>
			{/* Device Info Banner */}
			<div style={{
				background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
				borderRadius: 8,
				padding: '12px 16px',
				marginBottom: 20,
				color: '#fff'
			}}>
				<Space>
					<DesktopOutlined style={{fontSize: 20}} />
					<div>
						<div style={{fontWeight: 600, fontSize: 14}}>{deviceName}</div>
						<Text style={{fontSize: 11, opacity: 0.8, color: '#fff'}}>
							{deviceId?.slice(0, 16)}…
						</Text>
					</div>
				</Space>
			</div>

			<Form
				layout='vertical'
				form={form}
				onFinish={createShare}
				requiredMark={false}
			>
				{/* Hidden device field */}
				<Form.Item name='device' hidden>
					<Input />
				</Form.Item>

				{/* Access Mode Section */}
				<Form.Item
					label={
						<Space>
							<SafetyOutlined />
							<span>Access Level</span>
						</Space>
					}
					name='accessMode'
					rules={[{required: true}]}
					style={{marginBottom: 16}}
				>
					<Radio.Group
						optionType='button'
						buttonStyle='solid'
						style={{width: '100%'}}
					>
						<Radio.Button value={ACCESS_MODE_CONTROL} style={{width: '50%', textAlign: 'center'}}>
							Full Control
						</Radio.Button>
						<Radio.Button value={ACCESS_MODE_VIEW} style={{width: '50%', textAlign: 'center'}}>
							View Only
						</Radio.Button>
					</Radio.Group>
				</Form.Item>

				{/* Duration Section */}
				<Form.Item
					label={
						<Space>
							<ClockCircleOutlined />
							<span>Link Duration</span>
						</Space>
					}
					style={{marginBottom: 16}}
				>
					<Segmented
						block
						value={durationPreset}
						onChange={handleDurationPresetChange}
						options={[
							{label: '1 hour', value: 1},
							{label: '4 hours', value: 4},
							{label: '8 hours', value: 8},
							{label: '24 hours', value: 24},
							{label: 'Custom', value: 'custom'},
						]}
					/>
					{showCustomDuration && (
						<div style={{marginTop: 8}}>
							<InputNumber
								ref={durationInputRef}
								min={1}
								max={MAX_DURATION_HOURS}
								step={1}
								addonAfter="hours"
								style={{width: 140}}
								onChange={handleCustomDurationChange}
								placeholder="1-24"
							/>
						</div>
					)}
				</Form.Item>
				<Form.Item name='durationHours' hidden>
					<InputNumber />
				</Form.Item>

				{/* Options Row */}
				<Row gutter={16} style={{marginBottom: 20}}>
					<Col span={12}>
						<Card size="small" style={{height: '100%'}}>
							<Form.Item
								name='singleUse'
								valuePropName='checked'
								style={{marginBottom: 0}}
							>
								<Space>
									<Switch size="small" />
									<div>
										<div style={{fontWeight: 500, fontSize: 13}}>Single-use</div>
										<Text type="secondary" style={{fontSize: 11}}>
											Link expires after first use
										</Text>
									</div>
								</Space>
							</Form.Item>
						</Card>
					</Col>
					<Col span={12}>
						<Card size="small" style={{height: '100%'}}>
							<Form.Item
								name='turnOnly'
								valuePropName='checked'
								style={{marginBottom: 0}}
							>
								<Space>
									<Switch size="small" />
									<div>
										<div style={{fontWeight: 500, fontSize: 13}}>TURN Only</div>
										<Text type="secondary" style={{fontSize: 11}}>
											Force relay for strict firewalls
										</Text>
									</div>
								</Space>
							</Form.Item>
						</Card>
					</Col>
				</Row>

				{/* Action Buttons */}
				<Form.Item style={{marginBottom: 0}}>
					<Button
						type='primary'
						htmlType='submit'
						icon={<PlusOutlined />}
						loading={creating}
						block
						size="large"
					>
						Create Share Link
					</Button>
				</Form.Item>
			</Form>

			{/* Active Links Section */}
			{shares.length > 0 && (
				<>
					<Divider style={{margin: '20px 0 12px'}}>
						<Space>
							<Text type="secondary" style={{fontSize: 12}}>
								Active Links ({shares.length})
							</Text>
							<Button
								type="text"
								size="small"
								icon={<ReloadOutlined />}
								onClick={loadShares}
								style={{padding: '0 4px'}}
							/>
						</Space>
					</Divider>
					<Table
						size='small'
						rowKey='id'
						loading={loading}
						dataSource={shares}
						columns={columns}
						pagination={false}
						showHeader={false}
						style={{
							background: '#fafafa',
							borderRadius: 8,
						}}
					/>
				</>
			)}

			{shares.length === 0 && !loading && (
				<div style={{
					textAlign: 'center',
					padding: '20px 0',
					color: '#999'
				}}>
					<LinkOutlined style={{fontSize: 24, marginBottom: 8, display: 'block'}} />
					<Text type="secondary">No active share links for this device</Text>
				</div>
			)}
		</Modal>
	);
}

export default Share;
