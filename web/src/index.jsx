import React from 'react';
import ReactDOM from 'react-dom';
import {HashRouter as Router, Route, Routes} from 'react-router-dom';
import Wrapper from './components/wrapper';
import AuthGuard from './components/AuthGuard';
import { AuthProvider } from './context/AuthContext';
import Err from './pages/404';
import axios from 'axios';
import {message} from 'antd';
import i18n from "./locale/locale";

import './global.css';
import 'antd/dist/antd.css';
import Overview from "./pages/overview";
import SharePage from "./pages/share";
import LoginPage from "./pages/login";
import SetupPage from "./pages/setup";
import {translate} from "./utils/utils";

axios.defaults.baseURL = '.';
axios.interceptors.response.use(async res => {
	let data = res.data;
	if (data.hasOwnProperty('code')) {
		if (data.code !== 0){
			// Don't show auth errors on initial load or login/setup pages
			const isAuthError = data.msg && (data.msg.includes('AUTH.') || data.msg.includes('SESSION'));
			const isAuthPage = window.location.hash === '#/login' || window.location.hash === '#/setup' || window.location.hash === '';
			if (!isAuthError || !isAuthPage) {
				message.warn(translate(data.msg));
			}
		} else {
			// The first request will ask user to provide user/pass.
			// If set timeout at the beginning, then timeout warning
			// might be triggered before authentication finished.
			axios.defaults.timeout = 5000;
		}
	}
	return Promise.resolve(res);
}, err => {
	// console.error(err);
	if (err.code === 'ECONNABORTED') {
		message.error(i18n.t('COMMON.REQUEST_TIMEOUT'));
		return Promise.reject(err);
	}
	let res = err.response;
	let data = res?.data ?? {};
	if (data.hasOwnProperty('code') && data.hasOwnProperty('msg')) {
		if (data.code !== 0){
			// Don't show auth errors on initial load or login/setup pages
			const isAuthError = data.msg && (data.msg.includes('AUTH.') || data.msg.includes('SESSION'));
			const isAuthPage = window.location.hash === '#/login' || window.location.hash === '#/setup' || window.location.hash === '';
			if (!isAuthError || !isAuthPage) {
				message.warn(translate(data.msg));
			}
			return Promise.resolve(res);
		}
	}
	// Handle 401 Unauthorized - redirect to login
	if (res?.status === 401 && window.location.hash !== '#/login' && window.location.hash !== '#/setup') {
		window.location.hash = '#/login';
	}
	return Promise.reject(err);
});

ReactDOM.render(
	<Router>
		<AuthProvider>
			<Routes>
				{/* Public routes */}
				<Route path="/login" element={<LoginPage/>}/>
				<Route path="/setup" element={<SetupPage/>}/>
				<Route path="/share" element={<SharePage/>}/>

				{/* Protected routes */}
				<Route path="/" element={
					<AuthGuard>
						<Wrapper>
							<Overview/>
						</Wrapper>
					</AuthGuard>
				}/>

				{/* 404 page */}
				<Route path="*" element={<Err/>}/>
			</Routes>
		</AuthProvider>
	</Router>,
	document.getElementById('root')
);
