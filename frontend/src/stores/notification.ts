import { useI18n } from "vue-i18n";
import { notifyHost } from "@/suite-bridge";

type NotifyType = "success" | "error" | "warning" | "info";

const NOTIFICATION_DURATION: Record<NotifyType, number> = {
  success: 6_000,
  info: 6_000,
  warning: 10_000,
  error: 10_000,
};

/** 向 Veydeck 主控发送统一通知，并在独立运行时降级为本地事件。 */
function emit(
  type: NotifyType,
  title: string,
  message: string,
  duration: number,
) {
  const delivered = notifyHost({ type, title, message, duration });
  if (!delivered) {
    window.dispatchEvent(
      new CustomEvent("veydeck-suite-notification", {
        detail: { type, title, message, duration },
      }),
    );
  }
  const method =
    type === "error" ? "error" : type === "warning" ? "warn" : "log";
  console[method](`[${type}] ${message}`);
}

/** 提供协议仿真套件统一的本地化通知入口。 */
export function useNotificationStore() {
  const { t } = useI18n();
  const notify = (type: NotifyType, message: string, duration?: number) =>
    emit(
      type,
      t(`notification.title.${type}`),
      message,
      duration ?? NOTIFICATION_DURATION[type],
    );

  return {
    success: (message: string, duration?: number) =>
      notify("success", message, duration),
    error: (message: string, duration?: number) =>
      notify("error", message, duration),
    warning: (message: string, duration?: number) =>
      notify("warning", message, duration),
    info: (message: string, duration?: number) =>
      notify("info", message, duration),
  };
}
