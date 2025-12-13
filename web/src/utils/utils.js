import axios from "axios";
import Qs from "qs";
import i18n, {getLang} from "../locale/locale";
import en from "../locale/en";
import {message} from "antd";

let orderCompare;
try {
	let collator = new Intl.Collator(getLang(), {numeric: true, sensitivity: 'base'});
	orderCompare = collator.compare.bind(collator);
} catch (e) {
	orderCompare = (a, b) => a - b;
}

function request(url, data, headers, ext, noTrans) {
	let _headers = headers ?? {};
	_headers = Object.assign({'Content-Type': 'application/x-www-form-urlencoded'}, _headers);
	return axios(Object.assign({
		url: url,
		data: data,
		method: 'post',
		headers: _headers,
		transformRequest: noTrans ? [] : [Qs.stringify],
	}, ext??{}));
}

function waitTime(time) {
	time = (time ?? 100);
	return new Promise((resolve) => {
		setTimeout(() => {
			resolve(true);
		}, time);
	});
}

function formatSize(size) {
	size = isNaN(size) ? 0 : (size??0);
	size = Math.max(size, 0);
	let k = 1024,
		i = size === 0 ? 0 : Math.floor(Math.log(size) / Math.log(k)),
		units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'],
		result = size / Math.pow(k, i);
	return (Math.round(result * 100) / 100) + ' ' + units[i];
}

function tsToTime(ts) {
	if (isNaN(ts)) return 'Unknown';
	let hours = Math.floor(ts / 3600);
	ts %= 3600;
	let minutes = Math.floor(ts / 60);
	// Always return English units; no runtime translation lookup
	return `${String(hours)} h ${String(minutes)} m`;
}

function getBaseURL(ws, suffix) {
	const isHttps = location.protocol === 'https:';
	const scheme = ws ? (isHttps ? 'wss' : 'ws') : (isHttps ? 'https' : 'http');
	let path = suffix || '';
	// Always build from the site root; avoid inheriting the current route prefix
	if (path && !path.startsWith('/')) {
		path = '/' + path;
	}
	return `${scheme}://${location.host}${path}`;
}

function genRandHex(len) {
	return [...Array(len)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}

function post(url, data, ext) {
	let form = document.createElement('form');
	form.action = url;
	form.method = 'POST';
	form.target = '_self';

	for (const key in ext) {
		form[key] = ext[key];
	}
	for (const key in data) {
		if (Array.isArray(data[key])) {
			for (let i = 0; i < data[key].length; i++) {
				let input = document.createElement('input');
				input.name = key;
				input.value = data[key][i];
				form.appendChild(input);
			}
			continue;
		}
		let input = document.createElement('input');
		input.name = key;
		input.value = data[key];
		form.appendChild(input);
	}

	document.body.appendChild(form).submit();
	form.remove();
}

// Resolve a translation key from the static English bundle to avoid runtime lookups
function resolveEnKey(path) {
	if (typeof path !== 'string') return path;
	// Locale dictionaries are stored as flat "DOT.PATH" keys (not nested objects).
	// Fast-path those lookups first, then fall back to legacy nested traversal.
	if (Object.prototype.hasOwnProperty.call(en, path)) {
		const val = en[path];
		return typeof val === 'string' ? val : path;
	}
	const parts = path.split('.');
	let cur = en;
	for (let i = 0; i < parts.length; i += 1) {
		if (cur && Object.prototype.hasOwnProperty.call(cur, parts[i])) {
			cur = cur[parts[i]];
		} else {
			return path;
		}
	}
	return typeof cur === 'string' ? cur : path;
}

function translate(text) {
	if (typeof text !== 'string') return text;
	return text.replace(/\$\{i18n\|([a-zA-Z0-9_.]+)\}/g, (match, key) => resolveEnKey(key));
}

function preventClose(e) {
	e.preventDefault();
	e.returnValue = '';
	return '';
}

function catchBlobReq(err) {
	let res = err.response;
	if ((res?.data?.type ?? '').startsWith('application/json')) {
		let data = res?.data ?? {};
		data.text().then((str) => {
			let data = {};
			try {
				data = JSON.parse(str);
			} catch (e) { }
			message.warning(data.msg ? translate(data.msg) : i18n.t('COMMON.REQUEST_FAILED'));
		});
	}
}

function hex2ua(hex) {
	if (typeof hex !== 'string') {
		return new Uint8Array([]);
	}
	let list = hex.match(/.{1,2}/g);
	if (list === null) {
		return new Uint8Array([]);
	}
	return new Uint8Array(list.map(byte => parseInt(byte, 16)));
}

function ua2hex(buf) {
	let hexArr = Array.prototype.map.call(buf, bit => {
		return ('00' + bit.toString(16)).slice(-2);
	});
	return hexArr.join('');
}

function str2ua(str) {
	return new TextEncoder().encode(str);
}

function ua2str(buf) {
	return new TextDecoder().decode(buf);
}

function hex2str(hex) {
	return new TextDecoder().decode(hex2ua(hex));
}

function str2hex(str) {
	return ua2hex(new TextEncoder().encode(str));
}

// Encryption/decryption disabled: return pass-through copies for clarity.
async function encrypt(data, secret) {
	return new Uint8Array(data);
}

async function decrypt(data, secret) {
	const buf = new Uint8Array(data);
	return ua2str(buf);
}

function encryptSync(data, secret) {
	return new Uint8Array(data);
}

function decryptSync(data, secret) {
	return ua2str(new Uint8Array(data));
}

export {post, request, waitTime, formatSize, tsToTime, getBaseURL, genRandHex, translate, preventClose, catchBlobReq, hex2ua, ua2hex, str2ua, ua2str, hex2str, str2hex, encrypt, decrypt, encryptSync, decryptSync, orderCompare};
