import i18n from 'i18next';
import en from './en';

const resources = {
	en: {
		translation: en
	}
};

const lang = 'en';
const locale = 'en';

i18n.init({
	lng: lang,
	fallbackLng: 'en',
	initImmediate: true,
	resources
});

function getLang() {
	return lang;
}
function getLocale() {
	return locale;
}

export { getLang, getLocale };
export default i18n;
