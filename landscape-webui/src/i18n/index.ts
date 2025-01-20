import { createI18n } from "vue-i18n";

import en from "./en/main";
import zh from "./zh/main";

const messages = {
  en,
  zh,
};

// const browserLanguage = navigator.language.split("-")[0];

// const defaultLocale = Object.keys(messages).includes(browserLanguage)
//   ? browserLanguage
//   : "en";

const i18n = createI18n({
  legacy: false,
  locale: "zh",
  fallbackLocale: "zh",
  messages,
});

export default i18n;
