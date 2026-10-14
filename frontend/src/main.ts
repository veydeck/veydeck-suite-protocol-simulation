import { createApp } from "vue";
import { createI18n } from "vue-i18n";
import "@veydeck/tokens/index.css";
import "@veydeck/vue/style.css";
import App from "./App.vue";
import zh from "./locales/zh";
import en from "./locales/en";
import { suiteBridge } from "./suite-bridge";
import "./styles.css";

const initialLocale = document.documentElement.lang?.startsWith("en")
  ? "en"
  : "zh";
const i18n = createI18n({
  legacy: false,
  locale: initialLocale,
  fallbackLocale: "zh",
  messages: { zh, en },
});

suiteBridge.subscribeLocale(({ locale }) => {
  document.documentElement.lang = locale;
  i18n.global.locale.value = locale.startsWith("en") ? "en" : "zh";
  window.dispatchEvent(
    new CustomEvent("veydeck-suite-locale", { detail: { locale } }),
  );
});

suiteBridge.ready();

createApp(App).use(i18n).mount("#app");
