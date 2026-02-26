import { createI18n } from "vue-i18n";

import en from "./en/main";
import zh from "./zh/main";

const messages = {
  en,
  "en-US": en,
  zh,
  "zh-CN": zh,
};

const browserLanguage = navigator.language;
const defaultLocale = Object.keys(messages).includes(browserLanguage)
  ? browserLanguage
  : browserLanguage.startsWith("en")
    ? "en"
    : browserLanguage.startsWith("zh")
      ? "zh"
      : "zh";

const i18n = createI18n({
  legacy: false,
  locale: defaultLocale,
  fallbackLocale: "zh",
  messages,
});

export default i18n;
