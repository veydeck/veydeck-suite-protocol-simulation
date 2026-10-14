type ConfirmationOptions = {
  message: string;
  title?: string;
  confirmText?: string;
  cancelText?: string;
};

let handler: ((options: ConfirmationOptions) => Promise<boolean>) | null = null;

export function registerConfirmationHandler(
  nextHandler: ((options: ConfirmationOptions) => Promise<boolean>) | null,
) {
  handler = nextHandler;
}

export function useConfirmationModalStore() {
  return {
    async showConfirmation(
      message: string,
      title?: string,
      confirmText?: string,
      cancelText?: string,
    ) {
      if (!handler) return false;
      return handler({ message, title, confirmText, cancelText });
    },
  };
}
