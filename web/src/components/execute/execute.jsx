import React from 'react';
import {ModalForm, ProFormText} from '@ant-design/pro-form';
import {request} from "../../utils/utils";
import i18n from "../../locale/locale";
import {message} from "antd";

function Execute(props) {
	const { device, onCancel, open, visible, ...restProps } = props;
	const isOpen = open ?? visible;

	async function onFinish(form) {
		const basePath = location.origin + location.pathname + 'api/device/';
		const payload = {
			...form,
			device: device?.id
		};
		try {
			const res = await request(basePath + 'exec', payload);
			if (res.data.code === 0) {
				message.success(i18n.t('EXECUTE.EXECUTION_SUCCESS'));
				return true;
			}
		} catch (err) {
			return false;
		}
		return false;
	}

	return (
		<ModalForm
			open={isOpen}
			modalProps={{
				destroyOnClose: true,
				maskClosable: false,
			}}
			title={i18n.t('EXECUTE.TITLE')}
			width={380}
			onFinish={onFinish}
			onOpenChange={(nextOpen) => {
				if (!nextOpen && onCancel) onCancel();
			}}
			submitter={{
				render: (_, elems) => elems.pop()
			}}
			{...restProps}
		>
			<ProFormText
				width="md"
				name="cmd"
				label={i18n.t('EXECUTE.CMD_PLACEHOLDER')}
				rules={[{
					required: true
				}]}
			/>
			<ProFormText
				width="md"
				name="args"
				label={i18n.t('EXECUTE.ARGS_PLACEHOLDER')}
			/>
		</ModalForm>
	)
}

export default Execute;
