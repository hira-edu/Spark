import React from 'react';
import ProLayout, {PageContainer} from '@ant-design/pro-layout';
import zhCN from 'antd/lib/locale/zh_CN';
import en from 'antd/lib/locale/en_US';
import {getLang, getLocale} from "../locale/locale";
import {Button, ConfigProvider, notification, Dropdown, Avatar, Space} from "antd";
import {LogoutOutlined, UserOutlined} from '@ant-design/icons';
import {useNavigate} from 'react-router-dom';
import {useAuth} from '../context/AuthContext';
import version from "../config/version.json";
import ReactMarkdown from "react-markdown";
import i18n from "i18next";
import axios from "axios";
import './wrapper.css';

const enableUpdateCheck = window.location.hostname === '1248.ink';
if (enableUpdateCheck) {
	promptUpdate();
}
function wrapper(props) {
	const navigate = useNavigate();
	const { user, logout } = useAuth();

	const handleLogout = async () => {
		await logout();
		navigate('/login');
	};

	const userMenuItems = [
		{
			key: 'user-info',
			label: (
				<div style={{ padding: '4px 0' }}>
					<div style={{ fontWeight: 600, color: '#ffffff' }}>{user?.username}</div>
					{user?.email && (
						<div style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.65)' }}>{user.email}</div>
					)}
				</div>
			),
			disabled: true
		},
		{
			type: 'divider'
		},
		{
			key: 'logout',
			icon: <LogoutOutlined />,
			label: 'Logout',
			onClick: handleLogout,
			danger: true
		}
	];

	const UserMenu = () => (
		<Dropdown menu={{ items: userMenuItems }} placement="bottomRight">
			<Space style={{ cursor: 'pointer', padding: '0 16px' }}>
				<Avatar
					size="small"
					icon={<UserOutlined />}
					style={{
						background: 'linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%)',
					}}
				/>
				<span style={{ color: '#ffffff' }}>{user?.username}</span>
			</Space>
		</Dropdown>
	);

	return (
		<ProLayout
			loading={false}
			title='Rocket'
			logo={null}
			layout='top'
			navTheme='dark'
			collapsed={true}
			fixedHeader={true}
			contentWidth='fluid'
			collapsedButtonRender={Title}
			headerTheme='dark'
			rightContentRender={() => <UserMenu />}
			style={{
				background: '#1a1a1a',
			}}
			contentStyle={{
				background: '#1a1a1a',
				padding: 0,
			}}
		>
			<PageContainer
				header={{
					style: { display: 'none' }
				}}
				style={{
					background: '#1a1a1a',
				}}
			>
				<ConfigProvider locale={getLang()==='zh-CN'?zhCN:en}>
					{props.children}
				</ConfigProvider>
			</PageContainer>
		</ProLayout>
	);
}

function Title() {
	return (
		<div
			style={{
				userSelect: 'none',
				fontWeight: 500
			}}
		>
			Rocket
		</div>
	)
}
function promptUpdate() {
	let latest = '';
	axios('https://1248.ink/rocket/update', {
		method: 'POST',
		data: version
	}).then(res => {
		const data = res.data;
		const locale = getLocale();
		latest = data?.latest;

		// if is the latest version, don't show update notification
		if (!checkVersion(version.version, latest)) return;

		let localCache = getLocalCache();
		if (!shouldPrompt(localCache, latest)) return;
		if (!data.versions[latest] || !data.versions[latest].message) return;

		let message = data.versions[latest].message[locale];
		if (!message.content) return;

		notification.open({
			key: 'update',
			message: message.title ? <b>{message.title}</b> : undefined,
			description: <UpdateNotice url={message.url} content={message.content}/>,
			onClose: dismissUpdate,
			duration: 0
		});
	}).catch(e => {
		console.error(e);
	});

	function getLocalCache() {
		let localCache = {};
		let localRawCache = localStorage.getItem('updateCache');
		if (localRawCache) {
			try {
				localCache = JSON.parse(localRawCache);
			} catch (e) {
				localCache = {};
			}
		}
		localCache = Object.assign({
			lastCheck: 0,
			latestVersion: '0.0.0',
			hasDismissed: false
		}, localCache);
		return localCache;
	}
	function checkVersion(current, latest) {
		let latestVersion = parseInt(String(latest).replaceAll('.', ''));
		let currentVersion = parseInt(String(current).replaceAll('.', ''));
		return currentVersion < latestVersion;
	}
	function shouldPrompt(cache, latest) {
		let should = true;
		let now = Math.floor(Date.now() / 1000);
		if (!checkVersion(cache.latestVersion, latest)) {
			if (now - cache?.lastCheck < 7 * 86400) {
				should = !cache.hasDismissed;
			}
		}
		return should;
	}
	function dismissUpdate() {
		notification.close('update');
		let now = Math.floor(Date.now() / 1000);
		localStorage.setItem('updateCache', JSON.stringify({
			lastCheck: now,
			latestVersion: latest,
			dismissUpdate: true
		}));
	}
	function UpdateNotice(props) {
		return (
			<>
				<ReactMarkdown>
					{props.content}
				</ReactMarkdown>
				<div style={{marginTop: '10px'}}>
					<Button
						type='primary'
						onClick={() => {
							window.open(props.url, '_blank');
							notification.close('update');
						}}
					>
						{i18n.t('COMMON.UPDATE_DETAILS')}
					</Button>
					<Button
						style={{marginLeft: '10px'}}
						onClick={dismissUpdate}
					>
						{i18n.t('COMMON.UPDATE_DISMISS')}
					</Button>
				</div>
			</>
		);
	}
}


export default wrapper;
