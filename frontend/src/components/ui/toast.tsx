import { Toaster as SonnerToaster, toast } from "sonner";

/**
 * Non-blocking feedback. Sonner is mounted once in main.tsx (not in tests);
 * messages use role="status" via Sonner, never role="alert".
 */
export function Toaster() {
  return (
    <SonnerToaster
      closeButton
      position="bottom-right"
      theme="light"
      toastOptions={{
        classNames: {
          toast:
            "rounded-lg border border-border bg-card text-foreground shadow-lg text-sm",
          title: "font-medium",
          description: "text-muted-foreground",
          actionButton: "rounded-md bg-primary text-primary-foreground text-xs",
          cancelButton: "rounded-md bg-muted text-foreground text-xs",
          closeButton: "border-border bg-card text-muted-foreground",
        },
      }}
    />
  );
}

export const notify = {
  success: (message: string) => toast.success(message),
  info: (message: string) => toast(message),
  error: (message: string) => toast.error(message),
  promise: toast.promise,
  dismiss: toast.dismiss,
};
