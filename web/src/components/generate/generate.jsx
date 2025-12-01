import React, {useMemo, useState} from 'react';
import {ModalForm, ProFormCascader, ProFormDigit, ProFormGroup, ProFormText} from '@ant-design/pro-form';
import {post, request} from "../../utils/utils";
import prebuilt from '../../config/prebuilt.json';
import i18n from "../../locale/locale";
import {Alert, Divider, Space, Typography} from "antd";

function Generate(props) {
	const initValues = getInitValues();
	const [notice, setNotice] = useState('');
	const [preview, setPreview] = useState(() => buildPreview(initValues));
	const title = useMemo(() => i18n.t('GENERATOR.TITLE') || 'Generate Client', []);

	async function onFinish(form) {
		if (form?.ArchOS?.length === 2) {
			form.os = form.ArchOS[0];
			form.arch = form.ArchOS[1];
			delete form.ArchOS;
		}
		form.secure = location.protocol === 'https:' ? 'true' : 'false';
		let basePath = location.origin + location.pathname + 'api/client/';
		request(basePath + 'check', form).then(res => {
			if (res.data.code === 0) {
				post(basePath += 'generate', form);
				setNotice(i18n.t('GENERATOR.NEXT_STEPS') || 'Download starts in your browser. Run the binary on the target and keep this host/port reachable.');
			}
		}).catch(() => {
			setNotice('');
		});
	}

	function getInitValues() {
		let pathname = location.pathname || `/`;
		if (!pathname.startsWith(`/`)) {
			pathname = `/` + pathname;
		}
		let initValues = {
			host: location.hostname,
			port: location.port,
			path: pathname,
			ArchOS: ['windows', 'amd64']
		};
		if (String(location.port).length === 0) {
			initValues.port = location.protocol === 'https:' ? 443 : 80;
		}
		return initValues;
	}

	function buildPreview(values) {
		if (!values) return '';
		const host = values.host || location.hostname;
		const port = values.port || (location.protocol === 'https:' ? 443 : 80);
		let path = values.path || '/';
		if (!path.startsWith('/')) path = '/' + path;
		return `${location.protocol}//${host}:${port}${path}`;
	}

	return (
		<ModalForm
			title={title}
			modalProps={{
				destroyOnClose: true,
				maskClosable: false,
				centered: true,
				width: 760,
			}}
			initialValues={initValues}
			onFinish={onFinish}
			onValuesChange={(_, values) => setPreview(buildPreview(values))}
			submitter={{
				searchConfig: {
					submitText: i18n.t('COMMON.OK') || 'Generate'
				},
				render: (_, elems) => elems.pop()
			}}
			{...props}
		>
			{
				notice &&
				<Alert
					type='info'
					showIcon
					message={notice}
					description={i18n.t('GENERATOR.NEXT_STEPS_DESC') || 'If download is blocked, copy the generated link and fetch it from a host behind your firewall. Keep the port open so the client can call home.'}
					style={{marginBottom: 12}}
				/>
			}
			<Alert
				type="warning"
				showIcon
				message={i18n.t('GENERATOR.NOTE') || 'The binary will call home using the connection details below.'}
				style={{marginBottom: 12}}
			/>

			<Space direction="vertical" style={{width: '100%'}} size="large">
				<div>
					<Typography.Text strong>
						{i18n.t('GENERATOR.CONNECTION') || 'Connection'}
					</Typography.Text>
					<ProFormGroup>
						<ProFormText
							width="md"
							name="host"
							label={i18n.t('GENERATOR.HOST')}
							tooltip={i18n.t('GENERATOR.HOST_HELP') || 'Hostname or IP the client will connect to.'}
							rules={[{required: true, message: i18n.t('GENERATOR.HOST_REQUIRED') || 'Host is required'}]}
						/>
						<ProFormDigit
							width="md"
							name="port"
							label={i18n.t('GENERATOR.PORT')}
							tooltip={i18n.t('GENERATOR.PORT_HELP') || 'Listening port of this server.'}
							min={1}
							max={65535}
							rules={[{required: true, message: i18n.t('GENERATOR.PORT_REQUIRED') || 'Port is required'}]}
						/>
					</ProFormGroup>
					<ProFormGroup>
						<ProFormText
							width="md"
							name="path"
							label={i18n.t('GENERATOR.PATH')}
							tooltip={i18n.t('GENERATOR.PATH_HELP') || 'Base path where the client reaches /ws and /api.'}
							rules={[{required: true, message: i18n.t('GENERATOR.PATH_REQUIRED') || 'Path is required'}]}
						/>
						<ProFormCascader
							width="md"
							name="ArchOS"
							label={i18n.t('GENERATOR.OS_ARCH')}
							request={() => prebuilt}
							tooltip={i18n.t('GENERATOR.OS_ARCH_HELP') || 'Select the target OS and architecture.'}
							rules={[{required: true, message: i18n.t('GENERATOR.OS_ARCH_REQUIRED') || 'OS/Arch is required'}]}
						/>
					</ProFormGroup>
					<Typography.Text type="secondary">
						{i18n.t('GENERATOR.PREVIEW') || 'Connection preview'}: {preview}
					</Typography.Text>
				</div>

				<Divider style={{margin: '8px 0'}} />
				<Typography.Paragraph type="secondary" style={{marginBottom: 0}}>
					{i18n.t('GENERATOR.NEXT_STEPS_DESC') || 'After generation, the download starts. If blocked, copy the link and fetch from a host behind your firewall. Keep the port reachable.'}
				</Typography.Paragraph>
			</Space>
		</ModalForm>
	)
}

export default Generate;
